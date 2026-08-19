//! Properties of the source tree itself, enforced on every `cargo test`.
//!
//! Neither check below is about runtime behaviour. Both close gaps where a real defect can ship
//! while every other gate — `cargo check`, `cargo clippy`, the integration suite, the e2e suite —
//! passes green, because none of those gates looks at the artifact in question.

use std::path::{Path, PathBuf};

use oxc_allocator::Allocator;
use oxc_parser::Parser;
use oxc_span::SourceType;

/// Resolves a path relative to the crate root, so these tests are independent of the working
/// directory `cargo test` happens to be invoked from.
fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

// ═════════════════════════════════════════════════════════════
// The dashboard's JavaScript must parse
// ═════════════════════════════════════════════════════════════
//
// `static/` is served straight off disk by `ServeDir` and is never compiled, linted, or executed by
// anything else in this repository. A syntax error in `app.js` is therefore invisible to every
// existing gate: they all exercise the HTTP API and never parse the file they are serving. The
// dashboard would be completely dead in the browser and the first thing to notice would be a human
// opening it.

/// Parses one file and returns its syntax errors, each rendered as `path:line:col message`.
fn syntax_errors(relative: &str) -> Vec<String> {
    let path = repo_path(relative);
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{relative} must be readable: {e}"));

    let allocator = Allocator::default();
    // `cjs` rather than `mjs`: `app.js` is loaded with a plain `<script>` tag, so it is a classic
    // script. The distinction is not cosmetic — module source would silently accept `import` and
    // `export` that the browser would reject in this context.
    let parsed = Parser::new(&allocator, &source, SourceType::cjs()).parse();

    // Named rather than destructured so a future `oxc` rename fails to compile instead of silently
    // reporting "no syntax errors" against a list this test never looked at.
    parsed
        .diagnostics
        .iter()
        .map(|err| {
            // A diagnostic without a label falls back to offset 0 rather than being dropped: an
            // error with an unknown position is still an error. Widened to `usize` once here so the
            // slicing below cannot truncate on a large file.
            let offset =
                (err.labels.first().map_or(0, |span| span.offset()) as usize).min(source.len());
            let line = source[..offset].matches('\n').count() + 1;
            let column = offset - source[..offset].rfind('\n').map_or(0, |i| i + 1) + 1;
            format!("{relative}:{line}:{column}  {}", err.message)
        })
        .collect()
}

/// `static/app.js` must parse as valid ECMAScript.
#[test]
fn app_js_has_no_syntax_errors() {
    let errors = syntax_errors("static/app.js");
    assert!(
        errors.is_empty(),
        "static/app.js has {} syntax error(s) and will not load in a browser:\n  {}",
        errors.len(),
        errors.join("\n  ")
    );
}

/// The check is only worth having if it actually rejects broken input.
///
/// Without this, a future refactor could neuter [`app_js_has_no_syntax_errors`] — wrong path,
/// swallowed errors, an `is_empty()` on a list that is always empty — and it would keep passing
/// silently. A guard that has never been shown to fail is not evidence of anything.
#[test]
fn the_syntax_check_rejects_the_defect_it_exists_to_catch() {
    let allocator = Allocator::default();
    // A backtick inside a template literal: it ends the template early and leaves the following
    // word as a bare identifier. This is the classic way `app.js` breaks, because the file is full
    // of HTML-building template literals and HTML comments are a natural place to write one.
    let broken = r#"
        function render(rows) {
            return rows.map(r => `
                <td>
                    <!-- `title` carries the full value -->
                    <span title="${r.name}">${r.name}</span>
                </td>
            `).join('');
        }
    "#;

    let parsed = Parser::new(&allocator, broken, SourceType::cjs()).parse();
    assert!(
        !parsed.diagnostics.is_empty(),
        "a backtick inside a template literal must be reported as a syntax error — if this passes, \
         the parser is not actually checking anything"
    );
}

/// Cheap insurance against the check being pointed at a path that no longer exists.
#[test]
fn the_checked_frontend_files_are_where_the_tests_think_they_are() {
    for relative in ["static/app.js", "static/index.html"] {
        assert!(
            repo_path(relative).is_file(),
            "{relative} not found — a frontend check is pointed at a path that does not exist"
        );
    }
}

// ═════════════════════════════════════════════════════════════
// No raw SQL on any query path
// ═════════════════════════════════════════════════════════════

/// Every construct that puts a hand-written SQL string in front of the database.
///
/// `Expr::cust` and `.cust(` are included even though they sit inside the query builder: they splice
/// an uninterpreted fragment into a statement, so they carry exactly the injection risk the builder
/// otherwise removes.
const RAW_SQL_MARKERS: [&str; 8] = [
    "execute_unprepared",
    "Statement::from_string",
    "Statement::from_sql_and_values",
    "from_raw_sql",
    "query_one_raw",
    "query_all_raw",
    "execute_raw",
    "Expr::cust",
];

/// The only two files permitted to contain them, each for a reason the query builder cannot address.
///
/// Both are audited in `AGENT_NOTES.MD`, and **neither is reachable from a request**: one issues
/// connection pragmas at startup, the other emits DDL during a migration. Neither interpolates any
/// runtime value — the sole substitution across both is a compile-time `const`.
///
/// A third entry existed briefly, for a literal `SELECT 1` in `src/api/health.rs`. It was removed
/// when the readiness probe moved to SeaORM's typed builder: that exemption sat in a handler that is
/// both request-reachable and *unauthenticated*, which is the worst place in the service to hold one,
/// and it bought only a saved round-trip. A future third entry should be held to the same test —
/// unreachable from a request, or not granted.
const ALLOWED: [(&str, &str); 2] = [
    (
        "src/db.rs",
        "SQLite `PRAGMA` statements. A pragma is not a query — it configures how the engine \
         behaves, not what it is asked — and SeaORM's builders cannot express one. Backend-gated to \
         SQLite and issued once at startup.",
    ),
    (
        "src/migration/m20230106_090000_master_key_uniqueness.rs",
        "`ALTER TABLE ... ADD COLUMN ... GENERATED ALWAYS AS (...)`. SeaORM's `ColumnDef` has no \
         generated-column support at all, and RBAC_MODEL.md §5 requires the master marker to be \
         engine-derived rather than application-maintained. DDL, run once, with no user input.",
    ),
];

/// Walks `src/`, returning every `.rs` file's repo-relative path and contents.
fn source_files() -> Vec<(String, String)> {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, String)>) {
        let entries = std::fs::read_dir(dir).expect("src/ is readable");
        for entry in entries {
            let path = entry.expect("directory entry is readable").path();
            if path.is_dir() {
                walk(&path, root, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let relative = path
                    .strip_prefix(root)
                    .expect("every walked path is under the repo root")
                    .to_string_lossy()
                    .replace('\\', "/");
                let contents = std::fs::read_to_string(&path).expect("a source file is readable");
                out.push((relative, contents));
            }
        }
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    walk(&root.join("src"), root, &mut out);
    assert!(!out.is_empty(), "the walk found no source files — the path is wrong");
    out
}

/// **No unparameterised SQL reaches the database from any query path.**
///
/// Every query in `src/api.rs`, `src/retention.rs`, `src/middleware.rs` and `src/executor.rs` — that
/// is, every statement built from anything a caller sent — goes through SeaORM's typed entities and
/// expression builders. This test asserts that mechanically rather than by inspection, because the
/// property is only worth anything if it holds for code written after the audit as well.
///
/// Both allowlisted files are genuine exceptions rather than unfinished work, and **neither is
/// reachable from a request**: one issues connection pragmas at startup, the other emits DDL the
/// schema builder cannot express. Adding a third entry should require an argument of the same kind —
/// and specifically should not be granted to a handler, as the readiness probe's short-lived
/// exemption was before it moved to the typed builder.
#[test]
fn no_raw_sql_outside_the_documented_exceptions() {
    let mut violations = Vec::new();

    for (relative, contents) in source_files() {
        if ALLOWED.iter().any(|(allowed, _)| *allowed == relative) {
            continue;
        }
        for (number, line) in contents.lines().enumerate() {
            // Doc comments describe these constructs in several places (including this file's own
            // prose in `AGENT_NOTES.MD`), and naming one is not using one.
            let code = line.trim_start();
            if code.starts_with("//") || code.starts_with("*") {
                continue;
            }
            for marker in RAW_SQL_MARKERS {
                if code.contains(marker) {
                    violations.push(format!("{relative}:{}  uses {marker}", number + 1));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "raw SQL found outside the documented exceptions:\n  {}\n\nUse SeaORM entities or \
         expression builders. If this is genuinely unavoidable — DDL the schema builder cannot \
         express, or a connection pragma — add the file to ALLOWED with the reason, and record it \
         in AGENT_NOTES.MD.",
        violations.join("\n  ")
    );
}

/// The allowlist must not outlive its justification.
///
/// An entry naming a file that no longer exists, or that no longer contains raw SQL, is an
/// exemption nobody is checking — and the next file to land at that path inherits it silently.
#[test]
fn every_allowlisted_exception_still_exists_and_is_still_needed() {
    for (relative, reason) in ALLOWED {
        let path = repo_path(relative);
        assert!(path.is_file(), "allowlisted file {relative} no longer exists — drop the entry");

        let contents = std::fs::read_to_string(&path).expect("allowlisted file is readable");
        assert!(
            RAW_SQL_MARKERS.iter().any(|m| contents.contains(m)),
            "{relative} is allowlisted for raw SQL but no longer contains any — drop the entry \
             rather than leaving a standing exemption. Recorded reason: {reason}"
        );
    }
}

/// The scanner has to be able to see a violation, or the two tests above prove nothing.
#[test]
fn the_raw_sql_scanner_detects_what_it_is_looking_for() {
    // Exercised against a string rather than by writing a file: the point is that the marker set and
    // the comment-skipping logic agree with each other.
    let offending = r#"    db.execute_unprepared("DROP TABLE api_keys").await?;"#;
    let commented = r#"    // execute_unprepared is documented here, not called"#;

    let hits = |line: &str| {
        let code = line.trim_start();
        if code.starts_with("//") || code.starts_with("*") {
            return false;
        }
        RAW_SQL_MARKERS.iter().any(|m| code.contains(m))
    };

    assert!(hits(offending), "the scanner missed a real call");
    assert!(!hits(commented), "the scanner flagged prose describing a call");
}

// ═════════════════════════════════════════════════════════════
// The dashboard's element references must resolve
// ═════════════════════════════════════════════════════════════

/// Collects every `id` that exists in a document, whether written in the HTML or produced by a
/// template literal in the script.
fn declared_ids(sources: &[&str]) -> std::collections::HashSet<String> {
    let mut ids = std::collections::HashSet::new();
    for source in sources {
        // `id="..."` and `id='...'`. Deliberately naive: the point is to gather candidates, and a
        // false positive here can only make the assertion below more forgiving, never less correct.
        for (pattern, quote) in [("id=\"", '"'), ("id='", '\'')] {
            let mut rest = *source;
            while let Some(start) = rest.find(pattern) {
                rest = &rest[start + pattern.len()..];
                if let Some(end) = rest.find(quote) {
                    let value = &rest[..end];
                    // Template interpolation (`id="row-${h.id}"`) names no fixed element.
                    if !value.is_empty() && !value.contains("${") {
                        ids.insert(value.to_owned());
                    }
                    rest = &rest[end..];
                }
            }
        }
    }
    ids
}

/// Every `document.getElementById('x')` in `app.js` must name an element that exists.
///
/// # Why this is worth a test
///
/// `getElementById` on a missing id returns `null` and throws only when something is done with the
/// result — often inside an event handler, so the page loads fine and one button silently does
/// nothing. Nothing else in this repository would notice: the syntax check parses the file happily,
/// and the e2e suite drives the HTTP API without ever rendering the page.
///
/// It also catches the inverse drift, which is what actually happened here: `index.html` carried an
/// `apikey-is-master` checkbox whose value `createApiKey` sent as `is_master`, a field the payload
/// type does not have. With `deny_unknown_fields` on that type, **every key creation from the
/// dashboard returned 422** — a control that existed in the markup, was read by the script, and
/// broke the request by being there at all.
#[test]
fn every_element_the_script_reaches_for_exists_in_the_markup() {
    let js = std::fs::read_to_string(repo_path("static/app.js")).expect("app.js is readable");
    let html =
        std::fs::read_to_string(repo_path("static/index.html")).expect("index.html is readable");

    // Ids may be declared in the markup *or* injected by the script's own templates.
    let declared = declared_ids(&[&html, &js]);

    let mut missing = Vec::new();
    for (pattern, quote) in [("getElementById(\"", '"'), ("getElementById('", '\'')] {
        let mut rest = js.as_str();
        while let Some(start) = rest.find(pattern) {
            rest = &rest[start + pattern.len()..];
            let Some(end) = rest.find(quote) else { continue };
            let id = &rest[..end];
            if !id.contains("${") && !declared.contains(id) {
                missing.push(id.to_owned());
            }
            rest = &rest[end..];
        }
    }
    missing.sort();
    missing.dedup();

    assert!(
        missing.is_empty(),
        "static/app.js calls getElementById for {} id(s) that exist nowhere in index.html or in \
         the script's own templates:\n  {}\n\nEach one returns null at runtime and fails silently \
         inside whatever handler touches it.",
        missing.len(),
        missing.join("\n  ")
    );
}

/// The dashboard must not send fields the API refuses.
///
/// Narrow and specific by design: `is_master` is the one field `RBAC_MODEL.md` §5 forbids on every
/// key payload, and the payload types are `deny_unknown_fields`, so sending it does not merely get
/// ignored — it fails the whole request at the deserializer. This is a regression guard on the exact
/// defect that made the create-key form unusable.
#[test]
fn the_dashboard_never_sends_is_master_in_a_key_payload() {
    let js = std::fs::read_to_string(repo_path("static/app.js")).expect("app.js is readable");

    let offending: Vec<String> = js
        .lines()
        .enumerate()
        .filter(|(_, line)| {
            let code = line.trim_start();
            !code.starts_with("//") && !code.starts_with("*") && code.contains("is_master:")
        })
        .map(|(n, line)| format!("static/app.js:{}  {}", n + 1, line.trim()))
        .collect();

    assert!(
        offending.is_empty(),
        "static/app.js builds a payload carrying `is_master`, which no key payload accepts \
         (RBAC_MODEL.md §5). The payload types use deny_unknown_fields, so the request fails with \
         422 rather than the field being ignored:\n  {}",
        offending.join("\n  ")
    );
}

/// `sea-orm-migration`'s Cargo.toml features must include every backend `sea-orm` itself declares.
///
/// The two crates carry *independent* feature lists. `sea-orm-migration`'s `SchemaManager::has_index`
/// (and `has_table`/`has_column`) compile a match arm per enabled backend feature and fall through to
/// `DbErr::BackendNotSupported` for anything not compiled in — so if this crate's feature list ever
/// drifts to list fewer backends than `sea-orm`'s, the drift is invisible to `cargo check` (everything
/// still compiles; only the runtime match arms differ) and surfaces only when `src/master.rs`'s boot
/// check for RBAC_MODEL.md §5's uniqueness index runs against the backend nobody remembered to enable.
/// A string check on `Cargo.toml` catches the drift where a passing build cannot.
#[test]
fn sea_orm_migration_declares_every_backend_sea_orm_does() {
    let cargo_toml = std::fs::read_to_string(repo_path("Cargo.toml"))
        .expect("Cargo.toml is readable");

    let sea_orm_line = cargo_toml
        .lines()
        .find(|line| line.starts_with("sea-orm ="))
        .expect("a sea-orm dependency line exists");
    let migration_line = cargo_toml
        .lines()
        .find(|line| line.starts_with("sea-orm-migration ="))
        .expect("a sea-orm-migration dependency line exists");

    for backend in ["sqlx-postgres", "sqlx-mysql", "sqlx-sqlite"] {
        assert!(
            sea_orm_line.contains(backend),
            "test fixture assumption broken: the `sea-orm` line no longer declares {backend:?}, so \
             this test can no longer tell drift from an intentional narrowing:\n  {sea_orm_line}"
        );
        assert!(
            migration_line.contains(backend),
            "sea-orm-migration is missing the {backend:?} feature that sea-orm itself declares. \
             SchemaManager::has_index/has_table/has_column silently compile out that backend's match \
             arm and fail at runtime with DbErr::BackendNotSupported instead of at build time:\n  \
             {migration_line}"
        );
    }
}
