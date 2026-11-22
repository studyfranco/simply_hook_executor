//! Repository policy checks for the Cargo manifest, Rust sources, and dashboard.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use oxc_allocator::Allocator;
use oxc_parser::{Parser, config::TokensParserConfig};
use oxc_span::SourceType;
use regex::Regex;

fn regex(pattern: &str) -> Regex {
    Regex::new(pattern).expect("valid policy regex")
}

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|e| panic!("{relative} must be readable: {e}"))
}

fn files_under(directory: &str, recursive: bool) -> Vec<PathBuf> {
    fn visit(directory: &Path, recursive: bool, files: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(directory).expect("read policy directory") {
            let entry = entry.expect("read directory entry");
            let kind = entry.file_type().expect("read directory entry type");
            if kind.is_dir() && recursive {
                visit(&entry.path(), true, files);
            } else if kind.is_file() {
                files.push(entry.path());
            }
        }
    }

    let root = repo_path("");
    let mut files = Vec::new();
    visit(&root.join(directory), recursive, &mut files);
    for file in &mut files {
        *file = file
            .strip_prefix(&root)
            .expect("repository file")
            .to_owned();
    }
    files.sort();
    files
}

fn rust_files(directory: &str) -> impl Iterator<Item = PathBuf> {
    files_under(directory, true)
        .into_iter()
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
}

// Cargo validates the document before running this test. Read the policy keys
// from TOML tokens so comments, quoted keys, and multiline arrays are handled.
fn manifest_tokens(source: &str) -> Vec<&str> {
    static TOKEN: LazyLock<Regex> = LazyLock::new(|| {
        regex(concat!(
            r#"(?s)"""(?:\\.|.)*?""""{0,2}|'''.*?'''\x27{0,2}"#,
            r#"|"(?:\\.|[^"\\])*"|'[^']*'|\#[^\n]*|\n|[^\s\[\]{}.,="'#]+|[\[\]{}.,=]"#
        ))
    });
    TOKEN
        .find_iter(source)
        .map(|token| token.as_str())
        .filter(|token| !token.starts_with('#'))
        .collect()
}

fn toml_text(token: &str) -> String {
    if token.starts_with('"') {
        serde_json::from_str(token).unwrap_or_else(|_| token.to_owned())
    } else {
        token.trim_matches('\'').to_owned()
    }
}

fn value_end(tokens: &[&str], separators: &[&str]) -> usize {
    let mut depth = 0;
    for (index, token) in tokens.iter().enumerate() {
        if depth == 0 && separators.contains(token) {
            return index;
        }
        match *token {
            "[" | "{" | "(" => depth += 1,
            "]" | "}" | ")" => depth -= 1,
            token if token.starts_with('`') && token.ends_with("${") => depth += 1,
            token if token.starts_with('}') && token.ends_with('`') => depth -= 1,
            _ => (),
        }
    }
    tokens.len()
}

fn toml_path(tokens: &[&str]) -> impl Iterator<Item = String> {
    tokens
        .iter()
        .filter(|token| **token != ".")
        .map(|token| toml_text(token))
}

fn manifest_values<'a>(tokens: &'a [&'a str]) -> BTreeMap<Vec<String>, &'a [&'a str]> {
    fn insert_values<'a>(
        mut tokens: &'a [&'a str],
        prefix: &[String],
        separators: &[&str],
        values: &mut BTreeMap<Vec<String>, &'a [&'a str]>,
    ) {
        let mut prefix = prefix.to_vec();
        while let Some((first, rest)) = tokens.split_first() {
            if separators.contains(first) || *first == "\n" {
                tokens = rest;
            } else if *first == "[" {
                let end = rest
                    .iter()
                    .position(|token| *token == "\n")
                    .unwrap_or(rest.len());
                let header = &rest[..end];
                prefix = if header.first() == Some(&"[") {
                    // An array of tables cannot declare a manifest policy key.
                    vec!["[[".to_owned()]
                } else {
                    toml_path(&header[..header.len() - 1]).collect()
                };
                tokens = &rest[end..];
            } else {
                let equals = tokens
                    .iter()
                    .position(|token| *token == "=")
                    .expect("TOML assignment");
                let key: Vec<_> = prefix
                    .iter()
                    .cloned()
                    .chain(toml_path(&tokens[..equals]))
                    .collect();
                let tail = &tokens[equals + 1..];
                let end = value_end(tail, separators);
                let value = &tail[..end];
                values.insert(key.clone(), value);
                if let ["{", fields @ .., "}"] = value {
                    insert_values(fields, &key, &[","], values);
                }
                tokens = &tail[end..];
            }
        }
    }

    let mut values = BTreeMap::new();
    insert_values(tokens, &[], &["\n"], &mut values);
    values
}

fn forbidden_dependencies(values: &BTreeMap<Vec<String>, &[&str]>) -> BTreeSet<String> {
    let mut forbidden = BTreeSet::new();
    for key in values.keys() {
        for (index, segment) in key.iter().enumerate() {
            if matches!(
                segment.as_str(),
                "dependencies" | "dev-dependencies" | "build-dependencies"
            ) && let Some(dependency) = key.get(index + 1)
            {
                let mut package_key = key[..=index + 1].to_vec();
                package_key.push("package".to_owned());
                let package = match values.get(&package_key).copied() {
                    Some([name]) => toml_text(name),
                    _ => dependency.clone(),
                };
                if matches!(package.as_str(), "chrono" | "sea-orm-migration") {
                    forbidden.insert(package);
                }
            }
        }
    }
    forbidden
}

fn manifest_policy(source: &str) -> Vec<String> {
    let tokens = manifest_tokens(source);
    let values = manifest_values(&tokens);
    let get = |path: &[&str]| {
        values
            .get(&path.iter().map(ToString::to_string).collect::<Vec<_>>())
            .copied()
    };
    let level = |value: Option<&[&str]>| match value {
        Some([token]) => toml_text(token),
        _ => String::new(),
    };
    let lint_level = |lint| {
        level(get(&["lints", "clippy", lint, "level"]).or_else(|| get(&["lints", "clippy", lint])))
    };
    let mut violations = Vec::new();
    if level(get(&["package", "edition"])) != "2024" {
        violations.push("package.edition must be 2024".to_owned());
    }
    if get(&["package", "rust-version"]).is_some() {
        violations.push("package.rust-version must be absent".to_owned());
    }
    if level(
        get(&["lints", "rust", "unsafe_code", "level"])
            .or_else(|| get(&["lints", "rust", "unsafe_code"])),
    ) != "forbid"
    {
        violations.push("lints.rust.unsafe_code must be forbid".to_owned());
    }
    for (lint, priority) in [("all", "-2"), ("pedantic", "-1")] {
        if level(get(&["lints", "clippy", lint, "priority"])) != priority {
            violations.push(format!("lints.clippy.{lint} must have priority {priority}"));
        }
        if lint_level(lint) != "warn" {
            violations.push(format!("lints.clippy.{lint} must be warn"));
        }
    }
    for key in values.keys() {
        if let [lints, clippy, lint] | [lints, clippy, lint, _] = key.as_slice()
            && lints == "lints"
            && clippy == "clippy"
            && (key.len() == 3 || get(&["lints", "clippy", lint]).is_none())
            && lint_level(lint) == "allow"
        {
            violations.push(format!("lints.clippy.{lint} must not be allow"));
        }
    }
    violations.extend(
        forbidden_dependencies(&values)
            .into_iter()
            .map(|package| format!("Forbidden dependency: {package}")),
    );
    let features = |dependency| -> BTreeSet<_> {
        get(&["dependencies", dependency, "features"])
            .into_iter()
            .flatten()
            .map(|token| toml_text(token))
            .collect()
    };
    let orm_features = features("sea-orm");
    let schema_features = features("sea-schema");
    for (dependency, declared, required) in [
        ("sea-orm", &orm_features, &["with-time", "schema-sync"][..]),
        (
            "sea-schema",
            &schema_features,
            &["discovery", "probe", "runtime-tokio-rustls"][..],
        ),
    ] {
        if get(&["dependencies", dependency, "default-features"]) != Some(&["false"][..]) {
            violations.push(format!("{dependency} must disable default features"));
        }
        for &feature in required
            .iter()
            .chain(&["sqlx-mysql", "sqlx-postgres", "sqlx-sqlite"])
        {
            if !declared.contains(feature) {
                violations.push(format!("{dependency} is missing {feature}"));
            }
        }
    }
    if orm_features.contains("with-chrono") || orm_features.contains("chrono") {
        violations.push("sea-orm must not enable chrono".to_owned());
    }
    for backend in orm_features.symmetric_difference(&schema_features) {
        if backend.starts_with("sqlx-") {
            violations.push(format!("SeaORM backend features differ for {backend}"));
        }
    }
    violations
}

#[test]
fn cargo_manifest_enforces_ecosystem_policy() {
    let violations = manifest_policy(&read("Cargo.toml"));
    assert_eq!(violations, [] as [String; 0], "{}", violations.join("\n"));
}

#[test]
fn manifest_policy_rejects_drift() {
    let manifest = r#"
        [package]
        edition = '2024' # A comment is not a key.
        [lints.rust]
        unsafe_code = "forbid"
        [lints.clippy]
        all = { priority = -2, level = 'warn' }
        pedantic = { level = "warn", priority = -1 }
        [dependencies.sea-orm]
        default-features = false
        features = ["sqlx-sqlite", # Keep database support in sync.
            "sqlx-postgres", "sqlx-mysql", "with-time", "schema-sync"]
        [dependencies]
        sea-schema = { default-features = false, features = ['sqlx-postgres', 'sqlx-sqlite', 'sqlx-mysql', 'discovery', 'probe', 'runtime-tokio-rustls'] }
    "#;
    assert_eq!(manifest_policy(manifest), [] as [String; 0]);
    for (before, after, diagnostic) in [
        ("priority = -2", "priority = -1", "clippy.all"),
        ("'2024'", "'2021'", "package.edition"),
        (
            "'2024'",
            "'2024'\nrust-version = '1.95'",
            "package.rust-version",
        ),
        ("forbid", "warn", "unsafe_code"),
        ("level = 'warn'", "level = 'allow'", "clippy.all"),
        ("level = \"warn\"", "level = \"deny\"", "clippy.pedantic"),
        (
            "priority = -1 }",
            "priority = -1 }\nneedless_pass_by_value.level = 'allow'",
            "clippy.needless_pass_by_value",
        ),
        ("'sqlx-sqlite'", "'with-uuid'", "missing sqlx-sqlite"),
        (
            "default-features = false",
            "default-features = true",
            "default features",
        ),
        ("schema-sync", "with-json", "sea-orm is missing schema-sync"),
        ("with-time", "with-chrono", "sea-orm is missing with-time"),
        ("'discovery'", "'writer'", "sea-schema is missing discovery"),
        ("'probe'", "'writer'", "sea-schema is missing probe"),
        (
            "'runtime-tokio-rustls'",
            "'runtime-tokio'",
            "sea-schema is missing runtime-tokio-rustls",
        ),
        (
            "'sqlx-mysql'",
            "'sqlx-other'",
            "SeaORM backend features differ",
        ),
        (
            "[dependencies]",
            "[dependencies]\nchrono = '0.4'",
            "Forbidden dependency: chrono",
        ),
        (
            "[dependencies]",
            "[dependencies]\nold = { package = 'sea-orm-migration', version = '2' }",
            "Forbidden dependency: sea-orm-migration",
        ),
    ] {
        let violations = manifest_policy(&manifest.replace(before, after));
        assert!(
            violations.iter().any(|error| error.contains(diagnostic)),
            "{violations:?}"
        );
    }
}

struct RustSource<'a> {
    code: String,
    strings: Vec<(Range<usize>, &'a str)>,
}

fn quoted_end(bytes: &[u8], quote: u8) -> usize {
    let mut index = 1;
    while index < bytes.len() {
        match bytes[index] {
            byte if byte == quote => return index + 1,
            b'\\' => index += 2,
            _ => index += 1,
        }
    }
    bytes.len()
}

fn block_comment_end(bytes: &[u8]) -> usize {
    let mut depth = 1;
    let mut index = 2;
    while depth > 0 && index + 1 < bytes.len() {
        match &bytes[index..index + 2] {
            b"/*" => {
                depth += 1;
                index += 2;
            }
            b"*/" => {
                depth -= 1;
                index += 2;
            }
            _ => index += 1,
        }
    }
    if depth == 0 { index } else { bytes.len() }
}

fn rust_source(source: &str) -> RustSource<'_> {
    static RAW_OPENING: LazyLock<Regex> = LazyLock::new(|| regex(r#"^(?:br|cr|r)(#*)""#));
    static CHARACTER: LazyLock<Regex> =
        LazyLock::new(|| regex(r"^'(?:[^'\\\r\n]|\\(?:u\{[\da-fA-F_]+\}|x[\da-fA-F]{2}|.))'"));
    let bytes = source.as_bytes();
    let mut code = bytes.to_vec();
    let mut strings = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let tail = &bytes[index..];
        let mut content = None;
        let length = match tail {
            [b'/', b'/', ..] => tail
                .iter()
                .position(|byte| *byte == b'\n')
                .unwrap_or(tail.len()),
            [b'/', b'*', ..] => block_comment_end(tail),
            [b'"', ..] => {
                let end = quoted_end(tail, b'"');
                content = Some(1..end.saturating_sub(1).max(1));
                end
            }
            [b'\'', ..] => CHARACTER.find(&source[index..]).map_or(0, |m| m.end()),
            [b'r' | b'b' | b'c', ..]
                if index == 0
                    || !matches!(bytes[index - 1], b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | 128..=255) =>
            {
                RAW_OPENING.captures(&source[index..]).map_or(0, |opening| {
                    let start = opening.get(0).expect("raw opening").end();
                    let delimiter = format!("\"{}", &opening[1]);
                    let end = source[index + start..]
                        .find(&delimiter)
                        .map_or(tail.len(), |offset| start + offset);
                    content = Some(start..end);
                    (end + delimiter.len()).min(tail.len())
                })
            }
            _ => 0,
        };
        if length == 0 {
            index += 1;
            continue;
        }
        let span = index..index + length;
        if let Some(content) = content {
            strings.push((
                span.clone(),
                &source[index + content.start..index + content.end],
            ));
        }
        for byte in &mut code[span] {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
        if tail[0] == b'\'' {
            // Keep a placeholder for a character token while hiding its contents.
            code[index] = b'_';
        }
        index += length;
    }
    RustSource {
        code: String::from_utf8(code).expect("source masking preserves UTF-8"),
        strings,
    }
}

fn closing_delimiter(code: &str, open: usize, opening: u8, closing: u8) -> Option<usize> {
    let mut depth = 0;
    for (index, byte) in code.bytes().enumerate().skip(open) {
        if byte == opening {
            depth += 1;
        }
        if byte == closing {
            depth -= 1;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

fn test_module_offset(rust: &RustSource<'_>) -> Result<Option<usize>, &'static str> {
    static CFG_TEST: LazyLock<Regex> =
        LazyLock::new(|| regex(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]"));
    static MODULE: LazyLock<Regex> = LazyLock::new(|| regex(r"^\s*mod\s+tests\s*\{"));
    let code = &rust.code;
    let mut depth = 0;
    let mut previous = 0;
    for cfg in CFG_TEST.find_iter(code) {
        for byte in code[previous..cfg.start()].bytes() {
            match byte {
                b'{' => depth += 1,
                b'}' => depth -= 1,
                _ => (),
            }
        }
        previous = cfg.end();
        if depth != 0 {
            continue;
        }
        let module = MODULE
            .find(&code[cfg.end()..])
            .ok_or("top-level cfg(test) must precede mod tests")?;
        let close = closing_delimiter(code, cfg.end() + module.end() - 1, b'{', b'}')
            .ok_or("mod tests has no closing brace")?;
        if !code[close + 1..].trim().is_empty()
            || rust.strings.iter().any(|(span, _)| span.start > close)
        {
            return Err("only comments and whitespace may follow mod tests");
        }
        return Ok(Some(cfg.start()));
    }
    Ok(None)
}

#[test]
fn every_source_file_places_its_test_module_last() {
    for path in rust_files("src") {
        let source = read(path.to_str().expect("UTF-8 path"));
        if let Err(error) = test_module_offset(&rust_source(&source)) {
            panic!("{}: {error}", path.display());
        }
    }
}

#[test]
fn test_module_check_rejects_misplaced_tests() {
    for source in [
        "#[cfg(test)] fn test_helper() {}",
        "#[cfg(test)] mod tests { fn f() {} } fn production() {}",
        "#[cfg(test)] mod tests { fn missing_closing_brace() {}",
        "#[cfg(test)] mod tests {} \"trailing literal\"",
        "#[cfg(test)] mod tests {} 'x'",
    ] {
        assert!(
            test_module_offset(&rust_source(source)).is_err(),
            "{source}"
        );
    }
    let source = r##"fn production() {} #[cfg(test)] mod tests { const TEXT: &str = r#"}"#; /* { /* } */ { */ } // }"##;
    assert_eq!(
        test_module_offset(&rust_source(source)),
        Ok(source.find("#[cfg(test)]"))
    );
}

fn entity_model_with_bool_fields(code: &str, attributes: &str) -> bool {
    static DERIVE: LazyLock<Regex> =
        LazyLock::new(|| regex(r"#\s*\[\s*derive\s*\([^)]*\bDeriveEntityModel\s*[,)]"));
    static MODEL: LazyLock<Regex> = LazyLock::new(|| regex(r"^\s*pub\s+struct\s+Model\s*\{"));
    static BOOL_FIELD: LazyLock<Regex> = LazyLock::new(|| regex(r"\b\w+\s*:\s*bool\s*(?:,|$)"));
    if !DERIVE.is_match(attributes) {
        return false;
    }
    let Some(model) = MODEL.find(code) else {
        return false;
    };
    let Some(end) = closing_delimiter(code, model.end() - 1, b'{', b'}') else {
        return false;
    };
    BOOL_FIELD.find_iter(&code[model.end()..end]).count() >= 4
}

fn lint_attribute_violations(entity_file: bool, rust: &RustSource<'_>) -> Vec<usize> {
    static ATTRIBUTE: LazyLock<Regex> = LazyLock::new(|| regex(r"#\s*(!\s*)?\["));
    static LINT: LazyLock<Regex> = LazyLock::new(|| {
        regex(concat!(
            r"\b(",
            "allow",
            "|",
            "expect",
            "|warn|deny|forbid",
            r")\s*\(([^)]*)\)"
        ))
    });
    static EXPECTED: LazyLock<Regex> = LazyLock::new(|| {
        regex(concat!(
            r"^\s*clippy",
            r"\s*::\s*struct_excessive_bools\s*,\s*reason\s*(=)\s*,?\s*$"
        ))
    });
    let code = &rust.code;
    let attributes: Vec<_> = ATTRIBUTE
        .captures_iter(code)
        .filter_map(|capture| {
            let header = capture.get(0)?;
            let end = closing_delimiter(code, header.end() - 1, b'[', b']')?;
            Some((
                header.start()..end + 1,
                header.end()..end,
                capture.get(1).is_some(),
            ))
        })
        .collect();
    let mut violations = Vec::new();
    for (index, (span, body, inner)) in attributes.iter().enumerate() {
        let contents = &code[body.clone()];
        let Some(lint) = LINT.captures(contents) else {
            continue;
        };
        let direct = contents.trim() == &lint[0];
        if !direct && !contents.trim_start().starts_with("cfg_attr") {
            continue;
        }
        let mut start = span.start;
        let mut end = span.end;
        for (previous, _, _) in attributes[..index].iter().rev() {
            if previous.end > start || !code[previous.end..start].trim().is_empty() {
                break;
            }
            start = previous.start;
        }
        for (following, _, _) in &attributes[index + 1..] {
            if following.start < end || !code[end..following.start].trim().is_empty() {
                break;
            }
            end = following.end;
        }
        let arguments = lint.get(2).expect("lint arguments");
        let valid_reason = EXPECTED
            .captures(arguments.as_str())
            .is_some_and(|expected| {
                let equals = expected.get(1).expect("reason assignment").end();
                let reason_start = body.start + arguments.start() + equals;
                let reason_end = body.start + arguments.end();
                let mut reasons = rust
                    .strings
                    .iter()
                    .filter(|(span, _)| span.start >= reason_start && span.end <= reason_end);
                reasons
                    .next()
                    .is_some_and(|(_, text)| text.trim_matches('"') == "SeaORM DeriveEntityModel requires flat 1:1 fields for SQL BOOLEAN columns")
                    && reasons.next().is_none()
            });
        if !entity_file
            || *inner
            || !direct
            || &lint[1] != "expect"
            || !valid_reason
            || !entity_model_with_bool_fields(&code[end..], &code[start..end])
        {
            violations.push(span.start);
        }
    }
    violations
}

#[test]
fn rust_sources_do_not_ignore_tests() {
    let ignored_test = regex(r"#\s*\[\s*ignore\b");
    for path in rust_files("src").chain(rust_files("tests")) {
        let source = read(path.to_str().expect("UTF-8 path"));
        let rust = rust_source(&source);
        let violations: Vec<_> = ignored_test
            .find_iter(&rust.code)
            .map(|m| m.start())
            .collect();
        assert_eq!(
            violations,
            [] as [usize; 0],
            "{}: ignored test attributes at byte offsets {violations:?}",
            path.display()
        );
    }
}

#[test]
fn rust_sources_do_not_suppress_clippy_lints() {
    for path in rust_files("src").chain(rust_files("tests")) {
        let source = read(path.to_str().expect("UTF-8 path"));
        let violations = lint_attribute_violations(
            path.parent() == Some(Path::new("src/entities")),
            &rust_source(&source),
        );
        assert_eq!(
            violations,
            [] as [usize; 0],
            "{}: forbidden Clippy attributes at byte offsets {violations:?}",
            path.display()
        );
    }
}

#[test]
fn clippy_policy_rejects_suppressions_outside_the_entity_exception() {
    let permitted = concat!(
        "#[derive(Debug, DeriveEntityModel)]\n",
        "#[",
        "expect(clippy::",
        "struct_excessive_bools, reason = \"SeaORM DeriveEntityModel requires flat 1:1 fields for SQL BOOLEAN columns\")]\n",
        "pub struct Model { a: bool, b: bool, c: bool, d: bool }",
    );
    assert_eq!(
        lint_attribute_violations(true, &rust_source(permitted)),
        [] as [usize; 0]
    );
    assert_ne!(
        lint_attribute_violations(false, &rust_source(permitted)),
        [] as [usize; 0]
    );
    for source in [
        "#[allow(dead_code)] fn f() {}".to_owned(),
        concat!("#[", "allow(clippy::", "all)] fn f() {}").to_owned(),
        concat!("#![", "allow(clippy::", "all)]").to_owned(),
        concat!("#![", "expect(clippy::", "all)]").to_owned(),
        concat!("#[cfg_attr(test, ", "allow(clippy::", "all))] fn f() {}").to_owned(),
        concat!("#[", "expect(clippy::", "all, reason = \"no\")] fn f() {}").to_owned(),
        permitted.replace("struct Model", "struct Other"),
        permitted.replace("pub struct Model", "struct Model"),
        permitted.replace("SQL BOOLEAN columns", "SQL columns"),
        permitted.replace("DeriveEntityModel", "Clone"),
        permitted.replace("d: bool", "d: u8"),
        permitted.replace(", reason = \"SeaORM DeriveEntityModel requires flat 1:1 fields for SQL BOOLEAN columns\"", ""),
    ] {
        assert_ne!(
            lint_attribute_violations(true, &rust_source(&source)),
            [] as [usize; 0],
            "{source}"
        );
    }
}

fn production_code_violations(code: &str) -> Vec<&str> {
    static FORBIDDEN: LazyLock<Regex> = LazyLock::new(|| {
        regex(concat!(
            r"(?:\.|::)\s*(?:unwrap|expect)\s*\(",
            r"|\b(?:panic|todo|unimplemented|dbg)\s*!\s*[(\[{]",
            r"|\bunsafe",
            r"\s*(?:\{|\b(?:fn|impl)\b)",
        ))
    });
    FORBIDDEN.find_iter(code).map(|m| m.as_str()).collect()
}

#[test]
fn rust_production_code_is_panic_free_and_safe() {
    for path in rust_files("src") {
        let source = read(path.to_str().expect("UTF-8 path"));
        let rust = rust_source(&source);
        let end = test_module_offset(&rust)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
            .unwrap_or(rust.code.len());
        let violations = production_code_violations(&rust.code[..end]);
        assert_eq!(
            violations,
            [] as [&str; 0],
            "{}: forbidden Rust constructs {violations:?}",
            path.display()
        );
    }
}

#[test]
fn production_check_rejects_panics_and_unsafe_code() {
    for source in [
        concat!("value.", "unwrap /* comment */ ()"),
        concat!("value.", "expect(\"message\")"),
        concat!("panic", "!(\"message\")"),
        concat!("todo", "!()"),
        concat!("unimplemented", "!()"),
        concat!("dbg", "!(value)"),
        concat!("unsafe", " { operation(); }"),
        concat!("unsafe", " fn f() {}"),
        concat!("unsafe", " impl Trait for Type {}"),
    ] {
        assert_eq!(
            production_code_violations(&rust_source(source).code).len(),
            1,
            "{source}"
        );
    }
    let ignored = concat!(
        "// value.",
        "unwrap()\n",
        "/* outer /* ",
        "panic!() */ ",
        "todo!() */\n",
        "let cooked = \"\\\"value.",
        "expect()\";\n",
        "let raw = r##\"unsafe",
        " { } \"#\"##;\n",
        "let character = '\"'; let label = 'x';",
    );
    assert_eq!(
        production_code_violations(&rust_source(ignored).code),
        [] as [&str; 0]
    );
}

const RAW_SQL_MARKERS: &str = concat!(
    r"\bStatement",
    r"\s*::\s*from_\w+\b",
    r"|\b(?:execute_raw|query_(?:\w+_)?raw|execute_unprepared|from_raw_sql|sqlx\s*::\s*query(?:_as|_scalar)?)\s*\(",
    r"|\bExpr",
    r"\s*::\s*cust\w*\b|\.\s*cust\w*\s*\(",
);
const DML_SHAPES: &str = concat!(
    r"(?is)^\s*(?:INSERT",
    r"(?:\s|\\[nrt])+INTO\b|DELETE",
    r"(?:\s|\\[nrt])+FROM\b",
    r"|UPDATE",
    r"\b[^;]*?(?:\b|\\[nrt])SET\b|SELECT",
    r"\b[^;]*?(?:\b|\\[nrt])FROM\b)",
);
const RAW_SQL_ALLOWED: &[&str] = &[];

fn raw_sql_violations<'a>(rust: &'a RustSource<'_>, end: usize) -> Vec<&'a str> {
    static MARKER: LazyLock<Regex> = LazyLock::new(|| regex(RAW_SQL_MARKERS));
    static DML: LazyLock<Regex> = LazyLock::new(|| regex(DML_SHAPES));
    let code_matches = MARKER.find_iter(&rust.code[..end]);
    let string_matches = rust
        .strings
        .iter()
        .take_while(|(span, _)| span.start < end)
        .filter(|(_, text)| !text.trim().eq_ignore_ascii_case("SELECT 1"))
        .flat_map(|(_, text)| DML.find_iter(text));
    code_matches
        .chain(string_matches)
        .map(|m| m.as_str())
        .collect()
}

fn raw_sql_allowance(path: &str) -> Option<&'static str> {
    RAW_SQL_ALLOWED.iter().copied().find(|entry| {
        if entry.ends_with('/') {
            path.starts_with(entry)
        } else {
            path == *entry
        }
    })
}

fn all_src_raw_sql() -> impl Iterator<Item = (String, Vec<String>)> {
    rust_files("src").map(|path| {
        let path = path
            .iter()
            .map(|part| part.to_str().expect("UTF-8 path"))
            .collect::<Vec<_>>()
            .join("/");
        let source = read(&path);
        let rust = rust_source(&source);
        // Validate test_module_offset invariants as well, then scan the ENTIRE file (production,
        // migrations, and #[cfg(test)]) so zero raw SQL can hide anywhere under src/.
        let _ = test_module_offset(&rust).unwrap_or_else(|error| panic!("{path}: {error}"));
        let violations = raw_sql_violations(&rust, rust.code.len())
            .into_iter()
            .map(str::to_owned)
            .collect();
        (path, violations)
    })
}

#[test]
fn production_uses_typed_queries_outside_raw_sql_exceptions() {
    for (path, violations) in all_src_raw_sql() {
        assert!(
            violations.is_empty() || raw_sql_allowance(&path).is_some(),
            "{path}: raw SQL {violations:?}"
        );
    }
}

#[test]
fn no_raw_sql_handler_is_ever_exempted() {
    assert_eq!(
        RAW_SQL_ALLOWED,
        [] as [&str; 0],
        "RAW_SQL_ALLOWED must remain empty — zero raw SQL allowed anywhere under src/"
    );
    for path in rust_files("src/api").chain(rust_files("src/migration")) {
        let path = path.to_string_lossy().replace('\\', "/");
        assert!(
            raw_sql_allowance(&path).is_none(),
            "{path} must not be exempted"
        );
    }
}

#[test]
fn every_allowlisted_raw_sql_exception_still_exists_and_is_still_needed() {
    let needed: BTreeSet<_> = all_src_raw_sql()
        .filter_map(|(path, violations)| {
            (!violations.is_empty())
                .then(|| raw_sql_allowance(&path))
                .flatten()
        })
        .collect();
    for entry in RAW_SQL_ALLOWED {
        let path = repo_path(entry);
        assert!(
            if entry.ends_with('/') {
                path.is_dir()
            } else {
                path.is_file()
            },
            "missing raw SQL exception {entry}"
        );
        assert!(needed.contains(entry), "unused raw SQL exception {entry}");
    }
}

#[test]
fn raw_sql_check_rejects_raw_apis_and_dml_literals() {
    for source in [
        concat!("Statement::", "from_string(db, query)"),
        concat!("Statement::", "from_sql_and_values(db, query, values)"),
        concat!("db.execute_", "raw(statement)"),
        concat!("db.query_", "raw(statement)"),
        concat!("db.query_one_", "raw(statement)"),
        concat!("db.query_all_", "raw(statement)"),
        concat!("db.execute_", "unprepared(query)"),
        concat!("Entity::from_", "raw_sql(statement)"),
        concat!("Expr::", "cust_with_values(query, values)"),
        "expression.cust(query)",
        concat!("\"insert", " into records values (1)\""),
        concat!("\"UPDATE", " records\\nSET active = true\""),
        concat!("r#\"SELECT", " *\nFROM records\"#"),
        concat!("\"DELETE", " FROM records\""),
    ] {
        let rust = rust_source(source);
        assert_eq!(raw_sql_violations(&rust, source.len()).len(), 1, "{source}");
    }
    let source = concat!(
        "// SELECT",
        " * FROM records\n\"Statement::",
        "from_string\""
    );
    let advisory = r#""Demote the extra keys with `UPDATE api_keys SET is_master = false`.""#;
    let select_one = r#""SELECT 1""#;
    assert_eq!(
        raw_sql_violations(&rust_source(advisory), advisory.len()),
        [] as [&str; 0]
    );
    assert_eq!(
        raw_sql_violations(&rust_source(select_one), select_one.len()),
        [] as [&str; 0]
    );
    assert_eq!(
        raw_sql_violations(&rust_source(source), source.len()),
        [] as [&str; 0]
    );
}

fn syntax_errors(relative: &str, source: &str) -> Vec<String> {
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source, SourceType::cjs()).parse();
    parsed
        .diagnostics
        .iter()
        .map(|error| {
            let offset = (error
                .labels
                .first()
                .map_or(0, oxc_span::LabeledSpan::offset) as usize)
                .min(source.len());
            let prefix = &source.as_bytes()[..offset];
            let line = prefix.split(|byte| *byte == b'\n').count();
            let column = prefix
                .iter()
                .rposition(|byte| *byte == b'\n')
                .map_or(offset + 1, |newline| offset - newline);
            format!("{relative}:{line}:{column} {error}")
        })
        .collect()
}

#[test]
fn dashboard_assets_exist() {
    for path in ["static/app.js", "static/index.html", "static/style.css"] {
        assert!(repo_path(path).is_file(), "missing dashboard asset {path}");
    }
}

#[test]
fn app_js_parses_without_syntax_errors() {
    let errors = syntax_errors("static/app.js", &read("static/app.js"));
    assert_eq!(errors, [] as [String; 0], "{}", errors.join("\n"));
}

#[test]
fn the_syntax_check_rejects_broken_javascript() {
    let errors = syntax_errors("fixture.js", "const ok = true;\nconst broken = ;");
    assert!(
        errors
            .iter()
            .any(|error| error.starts_with("fixture.js:2:")),
        "{errors:?}"
    );
}

fn js_tokens(source: &str) -> Vec<&str> {
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source, SourceType::mjs())
        .with_config(TokensParserConfig)
        .parse();
    parsed
        .tokens
        .iter()
        .map(|token| &source[token.start() as usize..token.end() as usize])
        .collect()
}

fn quoted_capture<'a>(captures: &regex::Captures<'a>) -> &'a str {
    captures
        .iter()
        .skip(1)
        .flatten()
        .next()
        .expect("quoted value")
        .as_str()
}

fn html_ids(source: &str) -> impl Iterator<Item = &str> {
    static ID: LazyLock<Regex> =
        LazyLock::new(|| regex(r#"(?:^|[\s<])id\s*=\s*(?:"([^"]+)"|'([^']+)')"#));
    ID.captures_iter(source)
        .map(|captures| quoted_capture(&captures))
        .filter(|id| !id.contains("${"))
}

fn missing_dom_ids<'a>(html: &'a str, js: &'a str) -> BTreeSet<&'a str> {
    static ASSIGNED: LazyLock<Regex> =
        LazyLock::new(|| regex(r#"\.id\s*=\s*(?:"([^"]+)"|'([^']+)'|`([^`]+)`)"#));
    static LOOKUP: LazyLock<Regex> =
        LazyLock::new(|| regex(r#"\b(?:el|getElementById)\s*\(\s*(?:"([^"]+)"|'([^']+)')\s*\)"#));
    let declared: BTreeSet<_> = html_ids(html)
        .chain(html_ids(js))
        .chain(
            ASSIGNED
                .captures_iter(js)
                .map(|captures| quoted_capture(&captures)),
        )
        .filter(|id| !id.contains("${"))
        .collect();
    LOOKUP
        .captures_iter(js)
        .map(|captures| quoted_capture(&captures))
        .filter(|id| !id.contains("${") && !declared.contains(id))
        .collect()
}

#[test]
fn every_get_element_by_id_target_is_declared_in_html_or_rendered_by_js() {
    let html = read("static/index.html");
    let js = read("static/app.js");
    let missing = missing_dom_ids(&html, &js);
    assert!(
        missing.is_empty(),
        "DOM lookups have no declared IDs: {missing:?}"
    );
}

#[test]
fn dom_id_check_rejects_missing_single_and_double_quoted_ids() {
    let js = r#"
        el('single-el'); el("double-el");
        document.getElementById('single-get'); document.getElementById("double-get");
        panel("no"); model('no'); el('${dynamic}');
        el('html'); el("rendered"); el('assigned');
        node.innerHTML = `<div id='rendered'></div>`; node.id = "assigned";
    "#;
    assert_eq!(
        missing_dom_ids(r#"<div id="html"></div>"#, js),
        BTreeSet::from(["single-el", "double-el", "single-get", "double-get"])
    );
}

fn missing_tab_panels(html: &str) -> BTreeSet<String> {
    static TAB: LazyLock<Regex> =
        LazyLock::new(|| regex(r#"(?:^|\s)data-tab\s*=\s*(?:"([\w-]+)"|'([\w-]+)')"#));
    let ids: BTreeSet<_> = html_ids(html).collect();
    TAB.captures_iter(html)
        .map(|captures| format!("tab-{}", quoted_capture(&captures)))
        .filter(|panel| !ids.contains(panel.as_str()))
        .collect()
}

#[test]
fn every_tab_button_in_index_html_has_a_matching_panel() {
    let missing = missing_tab_panels(&read("static/index.html"));
    assert!(missing.is_empty(), "missing tab panels: {missing:?}");
}

#[test]
fn tab_pairing_rejects_a_missing_panel() {
    let html = r#"<button data-tab="keys"></button><button data-tab='rules'></button><div id='tab-rules'></div>"#;
    assert_eq!(
        missing_tab_panels(html),
        BTreeSet::from(["tab-keys".to_owned()])
    );
}

fn root_relative_fetches(source: &str) -> Vec<&str> {
    static FETCH: LazyLock<Regex> = LazyLock::new(|| regex(r#"\bfetch\s*\(\s*['"`]/"#));
    FETCH.find_iter(source).map(|call| call.as_str()).collect()
}

fn subpath_violations(js: &str) -> Vec<&'static str> {
    let tokens = js_tokens(js);
    let fetches: Vec<_> = tokens
        .windows(3)
        .filter(|call| call[..2] == ["fetch", "("])
        .collect();
    let mut violations = Vec::new();
    if !root_relative_fetches(js).is_empty()
        || fetches.is_empty()
        || fetches.iter().any(|call| call[2] != "requestPath")
    {
        violations.push("fetch must use requestPath");
    }
    for (pattern, diagnostic) in [
        (
            r"deriveRequestBase\s*\(\)\s*\{\s*const path\s*=\s*window\.location\.pathname",
            "derive the request base from the page path",
        ),
        (
            r"this\.requestBase\s*=\s*HookExecutorClient\.deriveRequestBase\(\)",
            "initialize requestBase from the page path",
        ),
        (
            r"this\.signingBase\s*=\s*HookExecutorClient\.normalizeBasePath\(",
            "initialize signingBase independently",
        ),
        (
            r"const requestPath\s*=\s*`\$\{this\.requestBase\}\$\{endpoint\}`",
            "build requestPath with requestBase",
        ),
        (
            r"const signedPath\s*=\s*`\$\{this\.signingBase\}\$\{endpoint\}`",
            "build signedPath with signingBase",
        ),
        (
            r"this\.signer\.headers\(method,\s*signedPath,\s*body\)",
            "sign signedPath",
        ),
        (
            r"const canonical\s*=\s*`\$\{method\.toUpperCase\(\)\}\\n\$\{pathAndQuery\}\\n",
            "cover the signed path in the canonical message",
        ),
        (r"this\.digest\(canonical\)", "digest the canonical message"),
    ] {
        if !regex(pattern).is_match(js) {
            violations.push(diagnostic);
        }
    }
    let request_base_assignments = tokens
        .windows(4)
        .filter(|tokens| *tokens == ["this", ".", "requestBase", "="])
        .count();
    if request_base_assignments != 1 {
        violations.push("initialize requestBase exactly once");
    }
    violations
}

#[test]
fn dashboard_routes_requests_and_signs_with_independent_bases() {
    let violations = subpath_violations(&read("static/app.js"));
    assert_eq!(violations, [] as [&str; 0], "{violations:?}");
}

#[test]
fn subpath_check_rejects_request_and_signing_regressions() {
    let js = read("static/app.js");
    for (original, replacement, diagnostic) in [
        (
            "this.signingBase = normalized;",
            "this.signingBase = normalized; this.requestBase = normalized;",
            "initialize requestBase exactly once",
        ),
        (
            "fetch(requestPath,",
            "fetch ('/api/keys',",
            "fetch must use requestPath",
        ),
        (
            "${this.signingBase}${endpoint}",
            "${this.requestBase}${endpoint}",
            "build signedPath with signingBase",
        ),
        (
            "headers(method, signedPath, body)",
            "headers(method, requestPath, body)",
            "sign signedPath",
        ),
    ] {
        assert!(subpath_violations(&js.replace(original, replacement)).contains(&diagnostic));
    }
}

const HTML_TAG_TAIL: &str = r#"(?:[^>"']|"[^"]*"|'[^']*')*>"#;

fn html_attributes(tag: &str) -> impl Iterator<Item = (&str, Option<&str>)> {
    static ATTRIBUTE: LazyLock<Regex> = LazyLock::new(|| {
        regex(r#"\s+([^\s"'<>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?"#)
    });
    ATTRIBUTE.captures_iter(tag).map(|attr| {
        (
            attr.get(1).expect("attribute name").as_str(),
            attr.iter()
                .skip(2)
                .flatten()
                .next()
                .map(|value| value.as_str()),
        )
    })
}

#[test]
fn login_form_exposes_an_optional_api_base_override_field() {
    let html = read("static/index.html");
    let input = regex(&format!(r"(?i)<input\b{HTML_TAG_TAIL}"));
    let field = input
        .find_iter(&html)
        .find(|tag| {
            html_attributes(tag.as_str()).any(|(name, value)| {
                name.eq_ignore_ascii_case("id") && value == Some("login-api-base")
            })
        })
        .expect("index.html must have an #login-api-base input");
    assert!(
        html_attributes(field.as_str()).all(|(name, _)| !name.eq_ignore_ascii_case("required")),
        "#login-api-base must be optional"
    );
}

fn literal_text(token: &str) -> Option<&str> {
    let first = token.as_bytes().first()?;
    if matches!(first, b'\'' | b'"' | b'`') {
        Some(
            token[1..]
                .strip_suffix(char::from(*first))
                .unwrap_or(&token[1..]),
        )
    } else {
        None
    }
}

fn key_route(token: &str) -> bool {
    literal_text(token)
        .and_then(|path| {
            path.strip_prefix("/api")
                .unwrap_or(path)
                .strip_prefix("/keys")
        })
        .is_some_and(|suffix| suffix.is_empty() || suffix.starts_with(['/', '?']))
}

fn master_property(tokens: &[&str]) -> bool {
    tokens.iter().enumerate().any(|(index, token)| {
        let next = tokens.get(index + 1).copied();
        let previous = index.checked_sub(1).and_then(|i| tokens.get(i)).copied();
        let property = *token == "is_master" || literal_text(token) == Some("is_master");
        property
            && match (previous, next) {
                (Some("{" | ","), Some(":" | "," | "}")) | (Some("."), Some("=")) => true,
                (Some("["), Some("]")) => {
                    tokens.get(index + 2) == Some(&"=") || tokens.get(index + 2) == Some(&":")
                }
                _ => false,
            }
    })
}

fn payload_includes_master(tokens: &[&str], payload: &[&str], call: usize) -> bool {
    if master_property(payload)
        || payload
            .windows(2)
            .any(|pair| pair[0] == "..." && payload_includes_master(tokens, &pair[1..], call))
        || payload.windows(5).any(|pair| {
            pair[..4] == ["JSON", ".", "stringify", "("]
                && payload_includes_master(tokens, &pair[4..], call)
        })
    {
        return true;
    }
    let [name] = payload else {
        return false;
    };
    let Some((binding, _)) = tokens[..call]
        .windows(3)
        .enumerate()
        .rev()
        .find(|(index, window)| {
            matches!(window[0], "const" | "let" | "var")
                && window[1] == *name
                && window[2] == "="
                && value_end(&tokens[*index..call], &["}"]) == call - index
        })
    else {
        return false;
    };
    let initializer = &tokens[binding + 3..call];
    let end = value_end(initializer, &[";", ","]);
    let mutations = &initializer[end..];
    payload_includes_master(tokens, &initializer[..end], binding)
        || mutations.iter().enumerate().any(|(index, token)| {
            token == name
                && match &mutations[index + 1..] {
                    [".", "is_master", "=", ..] => true,
                    ["[", key, "]", "=", ..] => literal_text(key) == Some("is_master"),
                    ["=", rhs @ ..] => {
                        let start = binding + 3 + end + index + 2;
                        payload_includes_master(tokens, &rhs[..value_end(rhs, &[";", "}"])], start)
                    }
                    _ => false,
                }
        })
}

fn key_payload_violations(js: &str) -> Vec<&str> {
    let tokens = js_tokens(js);
    tokens
        .windows(2)
        .enumerate()
        .filter_map(|(index, pair)| {
            let [operation, "("] = pair else {
                return None;
            };
            let args = &tokens[index + 2..];
            let route_index = match *operation {
                "post" | "put" | "patch" | "fetch" | "apiFetch" => 0,
                "request"
                    if args
                        .first()
                        .and_then(|method| literal_text(method))
                        .is_some_and(|m| matches!(m, "POST" | "PUT" | "PATCH")) =>
                {
                    2
                }
                _ => return None,
            };
            let route = args.get(route_index)?;
            if !key_route(route) {
                return None;
            }
            // A template route can contain one or more interpolated expressions.
            let rest = &args[route_index..];
            let comma = value_end(rest, &[",", ")"]);
            if rest.get(comma) != Some(&",") {
                return None;
            }
            let payload = rest.get(comma + 1..)?;
            let end = value_end(payload, &[",", ")"]);
            payload_includes_master(&tokens, &payload[..end], index).then_some(*route)
        })
        .collect()
}

#[test]
fn the_dashboard_never_sends_is_master_in_a_key_payload() {
    let js = read("static/app.js");
    let violations = key_payload_violations(&js);
    assert_eq!(
        violations,
        [] as [String; 0],
        "is_master sent in key payloads: {violations:?}"
    );
}

#[test]
fn key_payload_check_rejects_writing_is_master_but_accepts_reads() {
    let js = r"
        client.apiFetch('/keys', {method: 'POST', body: JSON.stringify({is_master: me.is_master})});
        const payload = { name: 'updated' };
        payload['is_master'] = true;
        client.put(`/api/keys/${existing.id}`, payload);
        const body = { 'is_master': true };
        client.patch('/api/keys/example', body);
        client.post('/api/keys', { ...body });
        fetch('/api/keys', { method: 'POST', body: JSON.stringify(body) });
        let replacement = {};
        replacement = { ['is_master']: true };
        client.request('PUT', '/api/keys/example', replacement);
        { const payload = { is_master: true }; client.post('/api/other', payload); }
        client.post('/api/other', {is_master: true});
        client.post('/api/keys', { name: existing?.is_master ? 'master' : 'regular' });
        if (profile.is_master || me.is_master) client.get('/api/keys');
    ";
    assert_eq!(key_payload_violations(js).len(), 6);
}

fn external_url(url: &str) -> bool {
    let url = url.trim_start().to_ascii_lowercase();
    ["https://", "http://", "//", "wss://", "ws://"]
        .iter()
        .any(|prefix| url.starts_with(prefix))
}

fn js_external_urls(source: &str) -> Vec<&str> {
    let tokens = js_tokens(source);
    tokens
        .iter()
        .enumerate()
        .filter_map(|(index, token)| {
            let url = literal_text(token)?;
            if !external_url(url) {
                return None;
            }
            let active = match &tokens[..index] {
                [.., "fetch" | "WebSocket" | "EventSource" | "import", "("]
                | [.., "new", "WebSocket" | "EventSource"]
                | [.., "import" | "from"] => true,
                [.., "[", property, "]", "="] => {
                    matches!(literal_text(property), Some("src" | "href"))
                }
                [.., property, "=" | ":"] => {
                    matches!(*property, "src" | "href")
                        || matches!(literal_text(property), Some("src" | "href"))
                }
                _ => false,
            };
            active.then_some(url)
        })
        .collect()
}

fn external_asset_violations<'a>(source: &'a str, extension: &str) -> Vec<&'a str> {
    static BANNED: LazyLock<Regex> = LazyLock::new(|| {
        regex(
            r"(?i)fonts\.(?:googleapis|gstatic)|cdn\.jsdelivr|unpkg\.com|cdnjs\.cloudflare|data:image/svg\+xml",
        )
    });
    static CSS: LazyLock<Regex> =
        LazyLock::new(|| regex(r#"(?i)@import\b|\burl\(\s*['"]?\s*(?:https?:)?//"#));
    static TAG: LazyLock<Regex> = LazyLock::new(|| {
        regex(&format!(
            r"(?i)<(?:script|link|img|iframe|source|object)\b{HTML_TAG_TAIL}"
        ))
    });
    let mut violations: Vec<_> = BANNED
        .find_iter(source)
        .chain(CSS.find_iter(source))
        .map(|m| m.as_str())
        .collect();
    if matches!(extension, "html" | "js") {
        for tag in TAG.find_iter(source) {
            for (name, value) in html_attributes(tag.as_str()) {
                let name = name.to_ascii_lowercase();
                if let Some(value) = value {
                    match name.as_str() {
                        "src" | "href" | "data" if external_url(value) => violations.push(value),
                        "srcset" => {
                            violations.extend(value.split(',').filter(|url| external_url(url)));
                        }
                        _ => (),
                    }
                }
            }
        }
    }
    if extension == "js" {
        violations.extend(js_external_urls(source));
    }
    violations
}

#[test]
fn frontend_has_no_external_assets_or_svg_data_uris() {
    for path in files_under("static", true) {
        if let Some(extension @ ("html" | "css" | "js")) =
            path.extension().and_then(|ext| ext.to_str())
        {
            let source = read(path.to_str().expect("UTF-8 path"));
            let violations = external_asset_violations(&source, extension);
            assert_eq!(
                violations,
                [] as [&str; 0],
                "{}: forbidden frontend assets {violations:?}",
                path.display()
            );
        }
    }
}

#[test]
fn offline_asset_check_rejects_external_resources_and_svg_data() {
    for (extension, source) in [
        (
            "html",
            "fonts.googleapis fonts.gstatic cdn.jsdelivr unpkg.com cdnjs.cloudflare",
        ),
        ("css", "background: url(data:image/svg+xml;base64,abc)"),
        ("css", "@import 'local.css';"),
        ("css", "background: url( 'https://example.test/bg' );"),
        ("css", "background: url(//example.test/bg);"),
        (
            "html",
            "<script src='https://example.test/app.js'></script>",
        ),
        (
            "html",
            "<link href=//example.test/style.css rel=stylesheet>",
        ),
        ("html", "<img src='http://example.test/img'>"),
        ("html", "<iframe src=//example.test/frame></iframe>"),
        (
            "html",
            "<source srcset='/local.png 1x, //example.test/large.png 2x'>",
        ),
        (
            "html",
            "<object data='https://example.test/plugin'></object>",
        ),
        ("js", "fetch (\n 'https://example.test/data');"),
        ("js", "new WebSocket('wss://example.test/socket');"),
        ("js", "new EventSource(`http://example.test/events`);"),
        ("js", "import('https://example.test/module.js');"),
        ("js", "import x from 'https://example.test/module.js';"),
        ("js", "node.src = 'https://example.test/img';"),
        ("js", "node.href = '//example.test/page';"),
        (
            "js",
            "node.innerHTML = `<img src='http://example.test/image'>`;",
        ),
    ] {
        assert_ne!(
            external_asset_violations(source, extension),
            [] as [&str; 0],
            "{source}"
        );
    }
    let benign = r#"const help = `<input placeholder="https://..."><code>http://...:2375</code>`;
        const example = "http://127.0.0.1:8080";
        const svg = `<svg xmlns="http://www.w3.org/2000/svg"></svg>`;
        const local = `<img src="./local.png" alt="try https://example.test">`;
        fetch(this.requestBase + path);"#;
    assert_eq!(external_asset_violations(benign, "js"), [] as [&str; 0]);
}

#[test]
fn retired_rust_dependencies_are_absent_from_sources() {
    let retired = regex(r"\b(?:chrono\s*::|sea_orm_migration\b|extern\s+crate\s+chrono\b)");
    for path in rust_files("src").chain(rust_files("tests")) {
        let source = read(path.to_str().expect("UTF-8 path"));
        assert!(
            !retired.is_match(&rust_source(&source).code),
            "{} imports a retired dependency",
            path.display()
        );
    }
}

#[test]
fn supply_chain_checks_have_no_advisory_suppressions() {
    let suppression =
        regex(r#"(?im)--ignore(?:\s|=)+["']?RUSTSEC-|^[ \t]*["']?ignore["']?\s*(?:=\s*\[|:)"#);
    let paths = std::iter::once(PathBuf::from(".cargo/audit.toml"))
        .chain(files_under(".github/workflows", true))
        .chain(files_under("scripts", true));
    for path in paths {
        let source = read(path.to_str().expect("UTF-8 path"));
        assert!(
            !suppression.is_match(&source),
            "{} contains an advisory suppression",
            path.display()
        );
    }
}

fn non_documentation_addresses(source: &str) -> Vec<&str> {
    use std::net::{Ipv4Addr, Ipv6Addr};

    let ipv6 = regex(r"(?i)(?:[0-9a-f]{0,4}:){2,}[0-9a-f:.]*");
    let dotted =
        regex(r"(?i)\b[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+\b");
    ipv6.find_iter(source)
        .map(|candidate| candidate.as_str().trim_end_matches('.'))
        .filter(|candidate| {
            candidate
                .parse::<Ipv6Addr>()
                .is_ok_and(|ip| ip != Ipv6Addr::LOCALHOST)
        })
        .chain(
            dotted
                .find_iter(source)
                .map(|candidate| candidate.as_str())
                .filter(|candidate| {
                    if let Ok(ip) = candidate.parse::<Ipv4Addr>() {
                        return !matches!(
                            ip.octets(),
                            [192, 0, 2, _]
                                | [198, 51, 100, _]
                                | [203, 0, 113, _]
                                | [127, 0, 0, 1]
                                | [0, 0, 0, 0]
                        );
                    }
                    let host = candidate.to_ascii_lowercase();
                    if Path::new(&host)
                        .extension()
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("md"))
                    {
                        return false;
                    }
                    !["example", "example.com", "example.net", "example.org"]
                        .iter()
                        .any(|domain| {
                            host == *domain
                                || host
                                    .strip_suffix(domain)
                                    .is_some_and(|prefix| prefix.ends_with('.'))
                        })
                }),
        )
        .collect()
}

#[test]
fn onboarding_links_goals_and_uses_documentation_addresses() {
    for document in ["AGENT.MD", "README.md"] {
        assert!(
            read(document)
                .lines()
                .take(10)
                .any(|line| line.contains("[GOALS.md](GOALS.md)")),
            "{document} must link GOALS.md near the top"
        );
    }
    let goals = read("GOALS.md");
    let addresses = non_documentation_addresses(&goals);
    assert_eq!(
        addresses,
        [] as [&str; 0],
        "Unexpected addresses in GOALS.md: {addresses:?}"
    );
}

#[test]
fn onboarding_address_check_rejects_network_address_drift() {
    assert_eq!(
        non_documentation_addresses(
            "http://hooks.example.com:3560 hooks.example test.example.net example.org \
             192.0.2.10 198.51.100.15/24 203.0.113.42 127.0.0.1 [::1] 0.0.0.0"
        ),
        [] as [&str; 0]
    );
    assert_eq!(
        non_documentation_addresses(
            "http://hooks.invalid-domain.test:3560 hooks.example.org.invalid \
             192.0.3.10 127.0.0.2 10.0.0.4 [2001:db8::1] fe80::12"
        ),
        [
            "2001:db8::1",
            "fe80::12",
            "hooks.invalid-domain.test",
            "hooks.example.org.invalid",
            "192.0.3.10",
            "127.0.0.2",
            "10.0.0.4",
        ]
    );
}

#[test]
fn agent_skill_exists_has_frontmatter_is_linked_and_uses_documentation_addresses() {
    use std::net::{Ipv4Addr, Ipv6Addr};

    let skill_rel = ".agents/skills/use-hook-executor/SKILL.md";
    assert!(repo_path(skill_rel).is_file(), "{skill_rel} must exist");
    let skill = read(skill_rel);

    let after_start = skill
        .strip_prefix("---\n")
        .expect("SKILL.md must start with YAML frontmatter");
    let (frontmatter, _body) = after_start
        .split_once("\n---\n")
        .expect("SKILL.md must close YAML frontmatter");
    assert!(
        frontmatter
            .lines()
            .any(|line| line.trim() == "name: use-hook-executor"),
        "SKILL.md frontmatter must declare `name: use-hook-executor`"
    );
    assert!(
        frontmatter
            .lines()
            .any(|line| line.trim_start().starts_with("description:")
                && line.trim_start()["description:".len()..].trim() != ""),
        "SKILL.md frontmatter must declare a non-empty `description:`"
    );

    for document in ["AGENT.MD", "README.md", "GOALS.md"] {
        assert!(
            read(document).contains(skill_rel),
            "{document} must link {skill_rel}"
        );
    }

    assert!(
        !skill.contains("127.0.0.1") && !skill.contains("169.254."),
        "SKILL.md must use RFC 5737 / RFC 3849 / RFC 2606 documentation addresses, not loopback/link-local"
    );

    let ipv4_re = regex(r"\b(?:\d{1,3}\.){3}\d{1,3}\b");
    for m in ipv4_re.find_iter(&skill) {
        let ip: Ipv4Addr = m.as_str().parse().expect("valid IPv4 in SKILL.md");
        assert!(
            matches!(
                ip.octets(),
                [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _]
            ),
            "SKILL.md contains non-RFC-5737 IPv4 address: {ip}"
        );
    }

    let ipv6_re = regex(r"(?i)\b(?:[0-9a-f]{0,4}:){2,}[0-9a-f:.]*\b");
    for m in ipv6_re.find_iter(&skill) {
        let candidate = m.as_str().trim_end_matches('.');
        if let Ok(ip) = candidate.parse::<Ipv6Addr>()
            && !ip.is_unspecified()
        {
            assert_eq!(
                ip.segments()[..2],
                [0x2001, 0x0db8],
                "SKILL.md contains non-RFC-3849 IPv6 address: {ip}"
            );
        }
    }

    let url_re = regex(r#"(?i)https?://([^/\s:)`"']+)"#);
    for caps in url_re.captures_iter(&skill) {
        let host = caps[1].trim_end_matches('.').to_ascii_lowercase();
        if host.starts_with('<') {
            continue;
        }
        let is_doc_domain = [
            "example.com",
            "example.org",
            "example.net",
            "example.test",
            "example.internal",
        ]
        .iter()
        .any(|d| host == *d || host.ends_with(&format!(".{d}")));
        assert!(
            is_doc_domain,
            "SKILL.md contains non-RFC-2606 URL host: {host}"
        );
    }
}
