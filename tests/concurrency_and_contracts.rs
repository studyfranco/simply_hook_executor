//! Races between simultaneous requests, and the refusal contract for malformed input.
//!
//! # Why this file exists
//!
//! Two gaps found by auditing the sibling projects under `example/`, both of which every other suite
//! here misses for the same structural reason: **nothing else in `tests/` runs two requests at
//! once.** Before this file there was not one `tokio::spawn` or `JoinSet` in the whole directory, so
//! every guard was proved sequentially — and a check-then-act bug is invisible to a sequential test
//! by construction. It needs two callers interleaving between the check and the act.
//!
//! | Pattern | Taken from | What it catches here |
//! | :--- | :--- | :--- |
//! | Two identical signed requests at once | `simply_ip_exporter::two_concurrent_identical_signed_requests_only_one_succeeds` | A replay ledger that reads-then-inserts lets both through, and the "single use" guarantee becomes "usually single use" |
//! | Two deletes of one resource at once | `simply_ip_exporter::two_concurrent_deletes_of_the_same_endpoint_do_not_both_succeed` | A delete that loads-then-deletes reports success twice for one row |
//! | Contended writes with an exact final count | `simply_ip_vault::test_concurrent_batch_writes_under_wal` | A lost write, a double insert, or a queued writer giving up with `SQLITE_BUSY` |
//! | Malformed body / path / query | `simply_ip_exporter`'s three "normal error envelope" tests | Whether a caller sending garbage gets a *reported* refusal rather than a panic or a hang |
//!
//! The peer's concurrency test makes its tasks contend for the **same** rows on purpose — disjoint
//! work exercises only insertion. That idea is kept; the collision target is adapted from their
//! overlapping address ranges to this service's equivalent uniqueness boundary, a contested
//! `hooks.name`.
//!
//! # What these tests do *not* claim
//!
//! `SQLITE_MAX_CONNECTIONS` is **1**, so these requests do not race inside SQLite — they queue on
//! the pool. That is the design. The races being tested are at the *application* layer: async tasks
//! interleaving at `.await` points, which happens regardless of how many connections exist.

// `common` is shared by five test binaries and each compiles all of it, so the helpers this one does
// not call are unused *here* while having real callers next door. The crate-wide convention is to
// allow it at the import rather than inside `common`, which keeps `common`'s own no-blanket-allow
// rule intact.
#[allow(dead_code)]
mod common;

use std::sync::Arc;

use axum::http::StatusCode;
use common::*;
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter};
use simply_hook_executor::entities::{hook, prelude::*};

/// Writes a no-op script and returns its path, kept alive by the returned directory.
///
/// The `TempDir` is returned rather than dropped: dropping it removes the script, and `create_hook`
/// validates that the path exists before inserting.
fn noop_script() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().expect("a temporary directory is available");
    let path = dir.path().join("noop.sh");
    std::fs::write(&path, "#!/bin/sh\nexit 0\n").expect("the script is writable");
    let rendered = path.display().to_string();
    (dir, rendered)
}

/// **A signature is single-use even when both uses arrive at once.**
///
/// `src/replay.rs` records each `CANONICAL_V1` signature digest and refuses the second sighting.
/// Sequentially that is already covered. The interesting case is simultaneous: if the ledger read
/// the digest, found it absent, and *then* inserted it, two tasks could both pass the read before
/// either wrote — and a captured request would be replayable exactly once more, forever, by racing
/// it against itself.
///
/// The assertion is **exactly one** success, not "at least one": a run where both are refused would
/// mean the first legitimate request had been lost, which is a different bug with the same shape.
#[tokio::test]
async fn two_concurrent_identical_signed_requests_only_one_succeeds() {
    let db = setup_test_db().await;
    let seeded = insert_key_full(&db, "Racer", "", KeyScopes::master()).await;
    let app = Arc::new(simply_hook_executor::create_app(
        test_state(&db).with_pinned_master(seeded.id),
    ));

    // One timestamp, one body, one URI — so both requests carry a byte-identical signature. Built
    // twice rather than cloned, because a `Request` is not `Clone` and rebuilding is what a replaying
    // attacker does anyway.
    let timestamp = now_timestamp();
    let build = || {
        signed_request_at(
            "GET",
            "/api/hooks",
            &seeded.plaintext,
            &seeded.signing_secret,
            "",
            timestamp,
        )
    };

    let first = { let app = Arc::clone(&app); let r = build(); tokio::spawn(async move { send(&app, r).await.status }) };
    let second = { let app = Arc::clone(&app); let r = build(); tokio::spawn(async move { send(&app, r).await.status }) };

    let statuses = [
        first.await.expect("the first task did not panic"),
        second.await.expect("the second task did not panic"),
    ];

    let accepted = statuses.iter().filter(|s| **s == StatusCode::OK).count();
    let refused = statuses.iter().filter(|s| **s == StatusCode::UNAUTHORIZED).count();

    assert_eq!(
        accepted, 1,
        "exactly one of two identical signatures may be honoured, got {statuses:?}. Two successes \
         mean the replay ledger checks then inserts, with a window in between"
    );
    assert_eq!(
        refused, 1,
        "the loser must be refused with 401, got {statuses:?}"
    );
}

/// **Two simultaneous deletes of one hook do not both report success.**
///
/// `delete_hook` loads the row, authorizes against it, and then writes the soft delete. Between the
/// load and the write is a window: two callers can both see a live hook. Deleting twice is not
/// destructive here — the second is a no-op against an already-trashed row — but reporting `204`
/// twice tells two operators they each removed something, and an audit trail with two `HOOK_DELETE`
/// entries for one deletion is a trail that disagrees with the database.
///
/// The tolerated outcomes are one `204` plus one `404` (the loser no longer sees a live hook). What
/// must not happen is two `204`s, or any 5xx.
#[tokio::test]
async fn two_concurrent_deletes_of_the_same_hook_do_not_both_report_success() {
    let db = setup_test_db().await;
    let (master_id, master_key) = insert_key(&db, "Deleter", "", KeyScopes::master()).await;
    let (_dir, script) = noop_script();
    let hook_id = insert_hook(&db, "doomed", &script, 30).await;
    let app = Arc::new(simply_hook_executor::create_app(
        test_state(&db).with_pinned_master(master_id),
    ));

    let uri = format!("/api/hooks/{hook_id}");
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..2 {
        let app = Arc::clone(&app);
        let request = json_request("DELETE", &uri, &master_key, None);
        tasks.spawn(async move { send(&app, request).await.status });
    }

    let mut statuses = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        statuses.push(joined.expect("no delete task may panic"));
    }

    let succeeded = statuses.iter().filter(|s| s.is_success()).count();
    assert!(
        statuses.iter().all(|s| !s.is_server_error()),
        "a concurrent double delete must not produce a 5xx, got {statuses:?}"
    );
    assert_eq!(
        succeeded, 1,
        "exactly one delete may report success, got {statuses:?}. Two successes mean the handler \
         loads and then writes without the second caller noticing the first"
    );

    // And the row is trashed exactly once, not double-counted anywhere.
    let row = fetch_hook_row(&db, hook_id).await.expect("the row still exists — deletion is soft");
    assert!(row.is_deleted, "the hook is in the trash");

    // The sharper half, and the reason the status code alone is not enough. The row is idempotent —
    // writing `is_deleted = true` twice leaves the same row — so a double success damages the
    // *trail*, not the data: two `HOOK_DELETE` entries for one deletion, and two operators each
    // holding a record saying they performed it. This is the assertion that would have gone red
    // before the conditional update, even if the status codes had somehow agreed.
    let deletions = AuditLog::find()
        .filter(simply_hook_executor::entities::audit_log::Column::Action.eq("HOOK_DELETE"))
        .count(&db)
        .await
        .expect("audit rows are countable");
    assert_eq!(
        deletions, 1,
        "one deletion must leave exactly one HOOK_DELETE entry; {deletions} means the audit trail \
         disagrees with the database about how many times this happened"
    );
}

/// Concurrent writers all complete, none reports a lock error, and the row count is exact.
///
/// # What this demonstrates, precisely
///
/// Not parallel writing — see the module header. What it demonstrates is that the queueing is
/// **correct and bounded**: every task gets an answer, none of them a 5xx, and the database ends up
/// holding exactly what the successful requests asked for.
///
/// # Two phases, because they fail differently
///
/// **Disjoint names** exercise throughput: every request should succeed and the count should be the
/// sum. **One contested name** exercises the uniqueness boundary — `hooks.name` is unique, and
/// `create_hook` handles a collision by catching the constraint violation rather than by checking
/// first and inserting after. Under concurrency a check-then-insert interleaves two callers in that
/// window, so the assertion is *exactly one* winner rather than "at least one".
#[tokio::test]
async fn concurrent_writers_queue_cleanly_and_the_row_count_is_exact() {
    const TASKS: usize = 8;
    const PER_TASK: usize = 5;

    let db = setup_test_db().await;
    let (master_id, master_key) = insert_key(&db, "Pool Master", "", KeyScopes::master()).await;
    let (_dir, script) = noop_script();
    let app = Arc::new(simply_hook_executor::create_app(
        test_state(&db).with_pinned_master(master_id),
    ));

    // ── Phase 1: disjoint names ─────────────────────────────────────────────
    let mut disjoint = tokio::task::JoinSet::new();
    for task in 0..TASKS {
        let app = Arc::clone(&app);
        let key = master_key.clone();
        let path = script.clone();
        disjoint.spawn(async move {
            let mut statuses = Vec::with_capacity(PER_TASK);
            for i in 0..PER_TASK {
                let body = serde_json::json!({
                    "name": format!("conc_{task}_{i}"),
                    "script_path": path,
                });
                statuses
                    .push(send(&app, json_request("POST", "/api/hooks", &key, Some(body))).await.status);
            }
            (task, statuses)
        });
    }

    let mut created = 0usize;
    while let Some(joined) = disjoint.join_next().await {
        let (task, statuses) = joined.expect(
            "no task may panic — a poisoned lock or an unhandled database error surfaces here",
        );
        for (i, status) in statuses.into_iter().enumerate() {
            assert_eq!(
                status,
                StatusCode::OK,
                "task {task} request {i} returned {status}. A 5xx here means a queued writer gave \
                 up instead of waiting; busy_timeout is what prevents that"
            );
            created += 1;
        }
    }
    assert_eq!(created, TASKS * PER_TASK, "every disjoint create succeeded");

    let hooks = Hook::find().count(&db).await.expect("hooks are countable");
    assert_eq!(
        hooks as usize,
        TASKS * PER_TASK,
        "the database holds exactly the hooks that were accepted — a lost write leaves this short, \
         a double insert would have violated the unique index and failed a request above"
    );

    // Every accepted create also wrote an audit row. Attribution must not be what gets dropped when
    // the pool is busy: a trail that develops holes precisely under load is a trail you cannot use
    // to reconstruct an incident.
    let audits = AuditLog::find().count(&db).await.expect("audit rows are countable");
    assert!(
        audits as usize >= TASKS * PER_TASK,
        "expected at least one audit row per accepted create ({}), found {audits}",
        TASKS * PER_TASK
    );

    // ── Phase 2: one contested name ─────────────────────────────────────────
    let mut contested = tokio::task::JoinSet::new();
    for _ in 0..TASKS {
        let app = Arc::clone(&app);
        let key = master_key.clone();
        let path = script.clone();
        contested.spawn(async move {
            let body = serde_json::json!({ "name": "contested", "script_path": path });
            send(&app, json_request("POST", "/api/hooks", &key, Some(body))).await.status
        });
    }

    let mut winners = 0usize;
    let mut conflicts = 0usize;
    while let Some(joined) = contested.join_next().await {
        match joined.expect("no task may panic") {
            StatusCode::OK => winners += 1,
            StatusCode::CONFLICT => conflicts += 1,
            other => panic!(
                "got {other} racing for a contested hook name; the only correct answers are 200 for \
                 the winner and 409 for the rest"
            ),
        }
    }

    assert_eq!(
        winners, 1,
        "exactly one caller may win a contested unique name. More than one means the handler checks \
         for the name and then inserts, with a window in between; zero means the winner's insert \
         was lost"
    );
    assert_eq!(conflicts, TASKS - 1, "every other caller was told it was a conflict");

    let contested_rows = Hook::find()
        .filter(hook::Column::Name.eq("contested"))
        .count(&db)
        .await
        .expect("the contested hook is countable");
    assert_eq!(contested_rows, 1, "the unique index left exactly one row behind");
}

/// Asserts one refusal is a real `{"error": …}` JSON document, not merely a correct status.
///
/// Three separate properties, because they fail independently and a partial fix would satisfy any
/// two of them: the **status**, the **`Content-Type`** (a client picks its parser from this header
/// before it ever looks at the bytes), and an `error` field carrying **non-empty text** (an envelope
/// whose message is blank is a machine-readable way of saying nothing).
fn assert_error_envelope(response: &TestResponse, expected: StatusCode, context: &str) {
    assert_eq!(
        response.status, expected,
        "{context}: expected {expected}, got {} — body: {}",
        response.status, response.raw
    );
    assert_eq!(
        response.content_type.as_deref().map(|ct| ct.starts_with("application/json")),
        Some(true),
        "{context}: refusals must be served as application/json, got {:?} — a client picks its \
         parser from this header before it reads a byte of the body",
        response.content_type
    );
    let message = response
        .json
        .get("error")
        .unwrap_or_else(|| panic!("{context}: no `error` field in {}", response.raw));
    let text = message
        .as_str()
        .unwrap_or_else(|| panic!("{context}: `error` must be a string, got {message}"));
    assert!(
        !text.trim().is_empty(),
        "{context}: the envelope carried an empty message, which tells a caller nothing"
    );
}

/// Malformed input on **every** extractor is refused in the standard envelope.
///
/// Adapted from `simply_ip_exporter`, which covers a malformed body, an unparseable UUID path
/// parameter, and a bad query as three separate contract tests. They exercise different Axum
/// extractors and fail in different places, so a service can easily handle one and leak plain text
/// from another — which is exactly what this service used to do on all three.
///
/// # Why this is a security-adjacent contract and not cosmetics
///
/// A refusal a client cannot parse is a refusal a client cannot *act* on. The three inputs below are
/// the most common things a caller gets wrong — a truncated body, a mistyped identifier, a bad
/// filter — and before this they were the only refusals in the service that arrived as bare
/// `text/plain`, with no `error` field for a client written against the documented envelope. Worse,
/// they are produced *before any handler runs*, so no handler test covered them: the gap was
/// invisible from inside the code that appeared to own those routes.
///
/// The sweep is deliberately over every extractor rather than a representative one. The contract is
/// "every refusal looks the same", and a contract verified at one of five sites is a contract with
/// four places left to drift.
#[tokio::test]
async fn malformed_input_is_refused_in_the_json_envelope_on_every_extractor() {
    let db = setup_test_db().await;
    let (master_id, master_key) = insert_key(&db, "Fuzzer", "", KeyScopes::master()).await;
    let (_dir, script) = noop_script();
    let hook_id = insert_hook(&db, "probe", &script, 30).await;
    let app = simply_hook_executor::create_app(test_state(&db).with_pinned_master(master_id));

    // 1. `StrictJson` — a body that is not JSON at all.
    let broken_body = with_connect_info(
        axum::http::Request::builder()
            .method("POST")
            .uri("/api/hooks")
            .header("X-API-Key", &master_key)
            .header("Content-Type", "application/json"),
    )
    .body(axum::body::Body::from("{not json"))
    .expect("the request builds");
    let response = send(&app, broken_body).await;
    assert_error_envelope(&response, StatusCode::BAD_REQUEST, "malformed JSON body");
    assert!(
        response.field("error").as_str().unwrap_or_default().to_lowercase().contains("json"),
        "the message should still name the problem — wrapping the shape must not withhold the \
         reason: {}",
        response.raw
    );

    // 2. `StrictPath` — a path parameter that cannot be a UUID.
    let response = send(&app, json_request("GET", "/api/executions/not-a-uuid", &master_key, None)).await;
    assert_error_envelope(&response, StatusCode::BAD_REQUEST, "unparseable UUID path parameter");

    // 3. `StrictPath` again, on a *tuple* path. Two-parameter routes deserialize through a different
    //    code path than single ones, so one working proves little about the other.
    let response = send(
        &app,
        json_request("DELETE", "/api/hooks/probe/parameters/not-a-uuid", &master_key, None),
    )
    .await;
    assert_error_envelope(&response, StatusCode::BAD_REQUEST, "unparseable UUID in a tuple path");

    // 4. `StrictQuery` — a query parameter of the wrong type.
    let response = send(&app, json_request("GET", "/api/executions?limit=abc", &master_key, None)).await;
    assert_error_envelope(&response, StatusCode::BAD_REQUEST, "non-numeric query parameter");

    // 5. `StrictBytes` — the raw-body routes. Their rejection type is different again, and they are
    //    the endpoints most likely to receive a body worth rejecting.
    let oversized = with_connect_info(
        axum::http::Request::builder()
            .method("POST")
            .uri(format!("/api/hooks/{hook_id}/execute"))
            .header("X-API-Key", &master_key)
            .header("Content-Type", "application/json"),
    )
    .body(axum::body::Body::from(vec![
        b'a';
        simply_hook_executor::MAX_REQUEST_BODY_BYTES + 1024
    ]))
    .expect("the request builds");
    let response = send(&app, oversized).await;
    // Status is Axum's, not flattened: an oversized body is `413`, and demoting it to `400` would
    // lose the one piece of information that tells a client to send less rather than send different.
    assert_error_envelope(&response, StatusCode::PAYLOAD_TOO_LARGE, "oversized raw body");

    // 6. The service is unharmed by all of it — the point of the sweep. A rejection that poisoned
    //    shared state would show up here and nowhere else.
    let response = send(&app, json_request("GET", "/api/hooks", &master_key, None)).await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "an ordinary request still succeeds after five malformed ones"
    );
}
