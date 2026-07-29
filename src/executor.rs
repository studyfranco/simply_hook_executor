//! The safe script execution engine.
//!
//! Every hook invocation flows through this module, which is responsible for the four security
//! properties `AGENT.MD` demands of it:
//!
//! 1. **No shell, ever.** The hook's `script_path` is handed straight to
//!    [`tokio::process::Command::new`] with an argument *vector*. Nothing is ever concatenated
//!    into a command string, so no parameter value can escape into shell syntax.
//! 2. **Environment isolation.** The child starts from a cleared environment
//!    ([`std::process::Command::env_clear`]); only the operator-controlled passthrough list
//!    ([`RuntimeConfig::allowed_env_vars`]) and the `HOOK_PARAM_*` injections survive. Because
//!    every injected name is prefixed, a caller can never set `LD_PRELOAD` or similar.
//! 3. **Bounded runtime.** Each hook carries a timeout; on expiry the child's entire *process
//!    group* is `SIGKILL`ed, so grandchildren cannot outlive the request.
//! 4. **Bounded output.** stdout/stderr are captured up to `MAX_OUTPUT_BYTES` each and then
//!    drained-and-discarded, so a runaway hook can neither exhaust memory nor deadlock on a
//!    full pipe.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use sea_orm::{ActiveModelTrait, ActiveValue::Set};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;

use crate::config::RuntimeConfig;
use crate::entities::{api_key, execution, execution::ExecutionStatus, hook, hook_parameter};
use crate::error::AppError;
use crate::state::AppState;

/// Prefix applied to every parameter injected into a hook's environment.
pub const PARAM_ENV_PREFIX: &str = "HOOK_PARAM_";

/// How long to wait for the stdout/stderr readers to observe EOF after the process has been
/// reaped. Reaching this bound is not an error — whatever was captured so far is kept — it only
/// guards against a detached grandchild holding a pipe open forever.
const READER_GRACE: Duration = Duration::from_secs(5);

/// Size of each read from a captured pipe.
const PIPE_CHUNK_BYTES: usize = 8192;

// ─────────────────────────────────────────────────────────────
// Parameter resolution
// ─────────────────────────────────────────────────────────────

/// A hook's declared parameters merged with the values supplied by the caller.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResolvedParameters {
    /// Resolved `(key, value)` pairs in declaration order (`created_at`, then `param_key`) — the
    /// same order used for positional CLI arguments.
    pub values: Vec<(String, String)>,
    /// Declared parameters that are required, carry no `default_value`, and were not supplied.
    /// A non-empty list makes `POST /api/hooks/{id}/execute` a `400`; the dry-run `/test`
    /// endpoint reports it as data instead.
    pub missing_required: Vec<String>,
}

impl ResolvedParameters {
    /// Serializes the resolved values as a JSON object for `executions.parameters_json`.
    pub fn to_json_string(&self) -> String {
        let map: serde_json::Map<String, serde_json::Value> = self
            .values
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
            .collect();
        serde_json::to_string(&map).unwrap_or_else(|_| "{}".to_owned())
    }
}

/// Whether `key` is usable as the suffix of a `HOOK_PARAM_<KEY>` environment variable, i.e.
/// matches `[A-Za-z_][A-Za-z0-9_]*`. Enforced when a parameter is *declared* so that no
/// unusable contract can ever be stored, rather than failing later at execution time.
pub fn is_valid_param_key(key: &str) -> bool {
    let mut chars = key.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Converts a supplied JSON value into the string that will reach the sub-process.
///
/// `null` is deliberately treated as "not supplied" (so the declared default still applies)
/// rather than as an empty string. Arrays/objects are rejected: an environment variable or argv
/// entry is a flat string, and silently JSON-encoding a structure would hide that from the caller.
fn coerce_param_value(key: &str, value: &serde_json::Value) -> Result<Option<String>, AppError> {
    let coerced = match value {
        serde_json::Value::Null => return Ok(None),
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        _ => {
            return Err(AppError::InvalidInput(format!(
                "Parameter '{key}' must be a string, number, or boolean"
            )));
        }
    };
    if coerced.contains('\0') {
        return Err(AppError::InvalidInput(format!(
            "Parameter '{key}' must not contain NUL bytes"
        )));
    }
    Ok(Some(coerced))
}

/// Merges caller-supplied values over a hook's declared parameter contract.
///
/// `declared` is expected in declaration order; [`crate::api`] queries it ordered by
/// `created_at, param_key` so the resulting positional argument list is stable and reproducible.
///
/// Unknown keys are rejected rather than ignored: a hook's contract is also its allowlist, and
/// silently dropping an unrecognized parameter would let a caller believe they had influenced an
/// execution that in fact ignored them.
pub fn resolve_parameters(
    declared: &[hook_parameter::Model],
    supplied: &serde_json::Map<String, serde_json::Value>,
) -> Result<ResolvedParameters, AppError> {
    let mut unknown: Vec<&str> = supplied
        .keys()
        .filter(|k| !declared.iter().any(|d| &&d.param_key == k))
        .map(|k| k.as_str())
        .collect();
    if !unknown.is_empty() {
        unknown.sort_unstable();
        return Err(AppError::InvalidInput(format!(
            "Unknown parameter(s) for this hook: {}",
            unknown.join(", ")
        )));
    }

    let mut resolved = ResolvedParameters::default();
    for decl in declared {
        let supplied_value = match supplied.get(&decl.param_key) {
            Some(raw) => coerce_param_value(&decl.param_key, raw)?,
            None => None,
        };

        match supplied_value.or_else(|| decl.default_value.clone()) {
            Some(value) => resolved.values.push((decl.param_key.clone(), value)),
            None if decl.is_required => resolved.missing_required.push(decl.param_key.clone()),
            // Optional, unsupplied, and undefaulted: omitted from both the environment and argv
            // entirely, so the script can distinguish "not given" from "given as empty".
            None => {}
        }
    }

    Ok(resolved)
}

// ─────────────────────────────────────────────────────────────
// Command planning
// ─────────────────────────────────────────────────────────────

/// Exactly what would be executed: the program, its argument vector, and its complete environment.
///
/// Returned verbatim by the dry-run endpoint (`POST /api/hooks/{id}/test`), which is the whole
/// point of building the plan as a separate, inspectable value rather than configuring a
/// [`Command`] inline.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct CommandPlan {
    /// Absolute path of the binary/script to run. Never a shell.
    pub program: String,
    /// Positional arguments, in declaration order of the resolved parameters.
    pub args: Vec<String>,
    /// The child's complete environment after `env_clear()`.
    pub env: BTreeMap<String, String>,
}

/// Builds the [`CommandPlan`] for a hook and a set of resolved parameters.
///
/// Each resolved parameter is passed **both** ways, so a script may consume whichever suits it:
/// as `HOOK_PARAM_<UPPERCASED_KEY>` in the environment, and as a bare positional argument (for
/// Python/shell scripts reading `sys.argv`/`$1`). Positional order is the parameter declaration
/// order, which the `/test` endpoint surfaces explicitly so it never has to be guessed.
pub fn build_command_plan(
    hook: &hook::Model,
    resolved: &ResolvedParameters,
    config: &RuntimeConfig,
) -> CommandPlan {
    let mut env = BTreeMap::new();

    // Controlled inheritance: only the operator's passthrough allowlist, and only those names
    // actually present in the daemon's own environment.
    for name in &config.allowed_env_vars {
        if let Ok(value) = std::env::var(name) {
            env.insert(name.clone(), value);
        }
    }

    // Injected parameters land last, so a HOOK_PARAM_* name can never be shadowed by a
    // same-named passthrough variable.
    for (key, value) in &resolved.values {
        env.insert(format!("{PARAM_ENV_PREFIX}{}", key.to_uppercase()), value.clone());
    }

    CommandPlan {
        program: hook.script_path.clone(),
        args: resolved.values.iter().map(|(_, v)| v.clone()).collect(),
        env,
    }
}

/// Rejects a hook whose `script_path` is not a runnable file, before anything is spawned or any
/// history row is written.
///
/// This is what turns "the hook points at a typo'd path" into a `400 Bad Request` naming the
/// problem, instead of a `FAILED` execution whose stderr says `No such file or directory`.
pub fn ensure_executable(script_path: &str) -> Result<(), AppError> {
    let path = std::path::Path::new(script_path);

    let metadata = std::fs::metadata(path).map_err(|e| {
        AppError::InvalidInput(format!("Hook script '{script_path}' is not accessible: {e}"))
    })?;

    if !metadata.is_file() {
        return Err(AppError::InvalidInput(format!(
            "Hook script '{script_path}' is not a regular file"
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(AppError::InvalidInput(format!(
                "Hook script '{script_path}' is not executable (chmod +x required)"
            )));
        }
    }

    Ok(())
}

/// Validates a `script_path` at hook *definition* time.
///
/// Deliberately stricter than [`ensure_executable`] in one dimension and looser in another: the
/// path must be absolute and free of `..` traversal (a relative or traversing path would resolve
/// against whatever working directory the daemon happens to have), but the file need not exist
/// yet — hooks are routinely declared before the script is deployed alongside them.
pub fn validate_script_path(script_path: &str) -> Result<(), AppError> {
    let path = std::path::Path::new(script_path);
    if !path.is_absolute() {
        return Err(AppError::InvalidInput(
            "script_path must be an absolute path".to_owned(),
        ));
    }
    if path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        return Err(AppError::InvalidInput(
            "script_path must not contain '..' traversal segments".to_owned(),
        ));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────
// Per-key concurrency throttling
// ─────────────────────────────────────────────────────────────

/// One API key's live execution budget.
struct KeyBudget {
    /// The permit count this semaphore was built with, so a later change to the key's
    /// `max_concurrent_jobs` can be detected and the budget rebuilt.
    permits: usize,
    semaphore: Arc<Semaphore>,
}

/// Enforces `api_keys.max_concurrent_jobs` across concurrent requests.
///
/// Each key gets its own [`Semaphore`], created lazily on first use. Permits are acquired with
/// `try_acquire` rather than `acquire`: exceeding the budget must fail fast with
/// `429 Too Many Requests`, never silently queue the caller behind other jobs.
#[derive(Default)]
pub struct ConcurrencyLimiter {
    budgets: Mutex<HashMap<Uuid, KeyBudget>>,
}

impl ConcurrencyLimiter {
    /// Creates an empty limiter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Attempts to reserve one execution slot for `key`.
    ///
    /// The returned permit must be held for the lifetime of the sub-process; dropping it frees
    /// the slot. Returns [`AppError::TooManyRequests`] when the key is already at its limit.
    pub fn try_acquire(&self, key: &api_key::Model) -> Result<OwnedSemaphorePermit, AppError> {
        // At least one slot always exists: a key stored with 0 (or a negative value) would
        // otherwise be permanently unable to execute anything, which is a configuration mistake
        // rather than a policy anyone sets deliberately.
        let permits = key.max_concurrent_jobs.max(1) as usize;

        let semaphore = {
            let mut budgets = lock(&self.budgets);
            let entry = budgets.entry(key.id).or_insert_with(|| KeyBudget {
                permits,
                semaphore: Arc::new(Semaphore::new(permits)),
            });
            // The key's budget was edited since this semaphore was built: replace it. Permits
            // already handed out belong to the old semaphore and simply stop being counted once
            // their jobs finish, which is the intended "new limit applies from now on" behavior.
            if entry.permits != permits {
                *entry = KeyBudget {
                    permits,
                    semaphore: Arc::new(Semaphore::new(permits)),
                };
            }
            Arc::clone(&entry.semaphore)
        };

        Semaphore::try_acquire_owned(semaphore).map_err(|_| {
            AppError::TooManyRequests(format!(
                "Concurrency limit reached for this API key ({permits} simultaneous job(s) allowed)"
            ))
        })
    }
}

// ─────────────────────────────────────────────────────────────
// Process execution
// ─────────────────────────────────────────────────────────────

/// The result of running a hook's sub-process to completion (or to its timeout).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionOutcome {
    /// Outcome classification recorded on the `executions` row.
    pub status: ExecutionStatus,
    /// Exit code, or `128 + signal` for a signalled process (so a `SIGKILL`ed hook records `137`).
    pub exit_code: Option<i32>,
    /// Captured standard output, truncated at the configured cap.
    pub stdout: String,
    /// Captured standard error, truncated at the configured cap.
    pub stderr: String,
    /// Wall-clock duration in milliseconds.
    pub duration_ms: i32,
}

/// A captured output stream plus whether it hit the size cap.
#[derive(Default)]
struct CapturedStream {
    bytes: Vec<u8>,
    truncated: bool,
}

/// Locks a mutex, recovering the guard if a previous holder panicked.
///
/// Poisoning here carries no correctness meaning: the protected data is either an output buffer
/// or a map of semaphores, both of which stay perfectly usable. Recovering keeps the daemon
/// serving instead of turning one panicked task into a permanently broken endpoint.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Drains a pipe into `sink`, retaining at most `limit` bytes.
///
/// Reading continues past the limit (discarding the excess) rather than stopping: a hook that
/// writes more than the cap must not block forever on a full pipe and get misreported as a
/// timeout.
async fn pump<R>(mut reader: R, sink: Arc<Mutex<CapturedStream>>, limit: usize)
where
    R: AsyncRead + Unpin,
{
    let mut buf = vec![0u8; PIPE_CHUNK_BYTES];
    loop {
        let read = match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let mut guard = lock(&sink);
        let remaining = limit.saturating_sub(guard.bytes.len());
        if remaining == 0 {
            guard.truncated = true;
        } else if read > remaining {
            guard.bytes.extend_from_slice(&buf[..remaining]);
            guard.truncated = true;
        } else {
            guard.bytes.extend_from_slice(&buf[..read]);
        }
    }
}

/// Renders a captured stream as UTF-8 (lossily — hook output is arbitrary bytes), appending a
/// marker when output was dropped so a truncated log is never mistaken for a complete one.
fn finish_stream(sink: &Mutex<CapturedStream>) -> String {
    let guard = lock(sink);
    let mut text = String::from_utf8_lossy(&guard.bytes).into_owned();
    if guard.truncated {
        text.push_str("\n[output truncated: exceeded MAX_OUTPUT_BYTES]");
    }
    text
}

/// Sends `SIGKILL` to the whole process group led by `pid`.
///
/// [`tokio::process::Child::kill`] signals only the direct child; a script that backgrounded work
/// would leave those grandchildren running past the timeout. The child is placed in its own
/// process group at spawn time, so this can never reach the daemon or any unrelated process.
#[cfg(unix)]
fn kill_process_group(pid: u32) {
    let pgid = pid as libc::pid_t;
    // SAFETY: `killpg` is async-signal-safe and takes only scalars. `pgid` is the pid of a child
    // this process spawned with `process_group(0)`, making it the leader of its own group, so the
    // signal is confined to that group's members.
    unsafe {
        libc::killpg(pgid, libc::SIGKILL);
    }
}

#[cfg(not(unix))]
fn kill_process_group(_pid: u32) {
    // Non-Unix platforms have no process groups in this sense; `Child::kill()` (called by the
    // timeout path directly) is the best available equivalent.
}

/// Maps a finished [`std::process::ExitStatus`] to a recorded exit code, translating a fatal
/// signal into the conventional `128 + signum` (matching what a shell would report).
fn exit_code_of(status: &std::process::ExitStatus) -> Option<i32> {
    status.code().or_else(|| signal_exit_code(status))
}

/// The `128 + signum` form of a signalled process's exit, where the platform has signals.
#[cfg(unix)]
fn signal_exit_code(status: &std::process::ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    status.signal().map(|sig| 128 + sig)
}

#[cfg(not(unix))]
fn signal_exit_code(_status: &std::process::ExitStatus) -> Option<i32> {
    None
}

/// Spawns and supervises a hook's sub-process.
///
/// Never returns an error: a hook that cannot be launched is a `FAILED` execution with the
/// spawn error captured in `stderr`, which belongs in the history like any other failure rather
/// than surfacing as a `500`.
pub async fn run_process(
    plan: &CommandPlan,
    timeout: Duration,
    max_output_bytes: usize,
) -> ExecutionOutcome {
    let started = Instant::now();

    let mut command = Command::new(&plan.program);
    command
        .args(&plan.args)
        .env_clear()
        .envs(&plan.env)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        // If this future is dropped (e.g. the client disconnects and axum cancels the handler),
        // the child is killed rather than left running unattended.
        .kill_on_drop(true);

    #[cfg(unix)]
    // Its own process group, so the timeout path can kill the entire tree with one `killpg`.
    command.process_group(0);

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(e) => {
            return ExecutionOutcome {
                status: ExecutionStatus::Failed,
                exit_code: None,
                stdout: String::new(),
                stderr: format!("Failed to launch '{}': {e}", plan.program),
                duration_ms: elapsed_ms(started),
            };
        }
    };

    let out_sink = Arc::new(Mutex::new(CapturedStream::default()));
    let err_sink = Arc::new(Mutex::new(CapturedStream::default()));
    // Captured through shared buffers rather than task return values so that partial output is
    // still available when a timeout cuts the readers short.
    let out_task = child
        .stdout
        .take()
        .map(|pipe| tokio::spawn(pump(pipe, Arc::clone(&out_sink), max_output_bytes)));
    let err_task = child
        .stderr
        .take()
        .map(|pipe| tokio::spawn(pump(pipe, Arc::clone(&err_sink), max_output_bytes)));

    let pid = child.id();
    let (status, exit_code) = match tokio::time::timeout(timeout, child.wait()).await {
        Ok(Ok(exit)) => {
            let code = exit_code_of(&exit);
            let status = if exit.success() {
                ExecutionStatus::Success
            } else {
                ExecutionStatus::Failed
            };
            (status, code)
        }
        Ok(Err(e)) => {
            tracing::error!("Failed to wait on hook process: {e}");
            (ExecutionStatus::Failed, None)
        }
        Err(_elapsed) => {
            if let Some(pid) = pid {
                kill_process_group(pid);
            }
            // Also kills-and-reaps the direct child, so it can never become a zombie even if the
            // group signal above found nothing to do.
            if let Err(e) = child.kill().await {
                tracing::error!("Failed to kill timed-out hook process: {e}");
            }
            let code = match child.wait().await {
                Ok(exit) => exit_code_of(&exit),
                Err(_) => None,
            };
            (ExecutionStatus::Timeout, code)
        }
    };

    // Bounded wait: whatever the readers captured before this point is kept either way.
    for task in [out_task, err_task].into_iter().flatten() {
        if tokio::time::timeout(READER_GRACE, task).await.is_err() {
            tracing::warn!("Timed out draining hook output; captured data may be incomplete");
        }
    }

    ExecutionOutcome {
        status,
        exit_code,
        stdout: finish_stream(&out_sink),
        stderr: finish_stream(&err_sink),
        duration_ms: elapsed_ms(started),
    }
}

/// Milliseconds since `started`, saturating rather than wrapping at `i32::MAX` (~24 days).
fn elapsed_ms(started: Instant) -> i32 {
    i32::try_from(started.elapsed().as_millis()).unwrap_or(i32::MAX)
}

/// Runs a hook end to end and records the result in `executions`.
///
/// Order of operations is deliberate: validate the script, *then* reserve a concurrency slot,
/// then execute. A hook with a broken `script_path` therefore cannot consume a caller's execution
/// budget, and the permit is held until the sub-process has fully exited.
pub async fn execute_hook(
    state: &AppState,
    hook: &hook::Model,
    key: &api_key::Model,
    resolved: &ResolvedParameters,
) -> Result<execution::Model, AppError> {
    ensure_executable(&hook.script_path)?;

    let _permit = state.limiter.try_acquire(key)?;

    let plan = build_command_plan(hook, resolved, &state.config);
    let timeout = state.config.timeout_for(hook.default_timeout_seconds);
    let started_at = chrono::Utc::now().naive_utc();

    tracing::info!(
        hook = %hook.name,
        key = %key.prefix,
        timeout_s = timeout.as_secs(),
        "Executing hook"
    );

    let outcome = run_process(&plan, timeout, state.config.max_output_bytes).await;

    tracing::info!(
        hook = %hook.name,
        status = ?outcome.status,
        exit_code = ?outcome.exit_code,
        duration_ms = outcome.duration_ms,
        "Hook execution finished"
    );

    let record = execution::ActiveModel {
        id: Set(Uuid::new_v4()),
        hook_id: Set(hook.id),
        api_key_id: Set(Some(key.id)),
        status: Set(outcome.status),
        exit_code: Set(outcome.exit_code),
        stdout: Set(outcome.stdout),
        stderr: Set(outcome.stderr),
        parameters_json: Set(resolved.to_json_string()),
        duration_ms: Set(outcome.duration_ms),
        timestamp: Set(started_at),
    };

    Ok(record.insert(&state.db).await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn declared(key: &str, default: Option<&str>, required: bool) -> hook_parameter::Model {
        hook_parameter::Model {
            id: Uuid::new_v4(),
            hook_id: Uuid::new_v4(),
            param_key: key.to_owned(),
            description: None,
            default_value: default.map(str::to_owned),
            is_required: required,
            created_at: Utc::now().naive_utc(),
        }
    }

    fn supplied(pairs: &[(&str, serde_json::Value)]) -> serde_json::Map<String, serde_json::Value> {
        pairs.iter().map(|(k, v)| ((*k).to_owned(), v.clone())).collect()
    }

    #[test]
    fn validates_param_key_shape() {
        assert!(is_valid_param_key("target_address"));
        assert!(is_valid_param_key("_private1"));
        assert!(!is_valid_param_key(""));
        assert!(!is_valid_param_key("1leading_digit"));
        assert!(!is_valid_param_key("has-dash"));
        assert!(!is_valid_param_key("has space"));
        assert!(!is_valid_param_key("semi;colon"));
    }

    #[test]
    fn applies_defaults_and_flags_missing_required() {
        let declared = [
            declared("target", None, true),
            declared("reason", Some("unspecified"), true),
            declared("optional", None, false),
        ];

        let resolved = resolve_parameters(&declared, &supplied(&[])).expect("no unknown keys");
        assert_eq!(resolved.missing_required, vec!["target"]);
        assert_eq!(resolved.values, vec![("reason".to_owned(), "unspecified".to_owned())]);

        let resolved = resolve_parameters(
            &declared,
            &supplied(&[("target", serde_json::json!("1.2.3.4")), ("reason", serde_json::json!("abuse"))]),
        )
        .expect("no unknown keys");
        assert!(resolved.missing_required.is_empty());
        assert_eq!(
            resolved.values,
            vec![
                ("target".to_owned(), "1.2.3.4".to_owned()),
                ("reason".to_owned(), "abuse".to_owned())
            ]
        );
    }

    #[test]
    fn rejects_unknown_and_unrepresentable_parameters() {
        let declared = [declared("target", None, true)];

        let err = resolve_parameters(&declared, &supplied(&[("nope", serde_json::json!("x"))]))
            .expect_err("unknown key must be rejected");
        assert!(matches!(err, AppError::InvalidInput(_)));

        let err = resolve_parameters(&declared, &supplied(&[("target", serde_json::json!(["a"]))]))
            .expect_err("array value must be rejected");
        assert!(matches!(err, AppError::InvalidInput(_)));

        let err = resolve_parameters(&declared, &supplied(&[("target", serde_json::json!("a\0b"))]))
            .expect_err("NUL byte must be rejected");
        assert!(matches!(err, AppError::InvalidInput(_)));
    }

    #[test]
    fn coerces_scalars_and_treats_null_as_omitted() {
        let declared = [
            declared("count", Some("0"), true),
            declared("enabled", Some("false"), true),
            declared("nulled", Some("fallback"), true),
        ];
        let resolved = resolve_parameters(
            &declared,
            &supplied(&[
                ("count", serde_json::json!(42)),
                ("enabled", serde_json::json!(true)),
                ("nulled", serde_json::Value::Null),
            ]),
        )
        .expect("scalars are representable");

        assert_eq!(
            resolved.values,
            vec![
                ("count".to_owned(), "42".to_owned()),
                ("enabled".to_owned(), "true".to_owned()),
                ("nulled".to_owned(), "fallback".to_owned())
            ]
        );
    }

    #[test]
    fn plan_injects_prefixed_env_and_positional_args() {
        let hook = hook::Model {
            id: Uuid::new_v4(),
            name: "demo".to_owned(),
            description: None,
            script_path: "/usr/local/bin/demo.sh".to_owned(),
            default_timeout_seconds: 30,
            created_at: Utc::now().naive_utc(),
            updated_at: Utc::now().naive_utc(),
        };
        let resolved = ResolvedParameters {
            values: vec![
                ("target_address".to_owned(), "203.0.113.7".to_owned()),
                ("reason".to_owned(), "abuse".to_owned()),
            ],
            missing_required: Vec::new(),
        };
        // An empty passthrough list keeps this assertion independent of the host environment.
        let config = RuntimeConfig {
            allowed_env_vars: Vec::new(),
            ..RuntimeConfig::default()
        };

        let plan = build_command_plan(&hook, &resolved, &config);
        assert_eq!(plan.program, "/usr/local/bin/demo.sh");
        assert_eq!(plan.args, vec!["203.0.113.7", "abuse"]);
        assert_eq!(plan.env.get("HOOK_PARAM_TARGET_ADDRESS").map(String::as_str), Some("203.0.113.7"));
        assert_eq!(plan.env.get("HOOK_PARAM_REASON").map(String::as_str), Some("abuse"));
        assert_eq!(plan.env.len(), 2, "no host variables leak in with an empty allowlist");
    }

    #[test]
    fn rejects_relative_and_traversing_script_paths() {
        assert!(validate_script_path("/usr/local/bin/ok.sh").is_ok());
        assert!(validate_script_path("relative.sh").is_err());
        assert!(validate_script_path("/usr/local/../../etc/shadow").is_err());
    }

    #[test]
    fn serializes_resolved_parameters_as_json_object() {
        let resolved = ResolvedParameters {
            values: vec![("a".to_owned(), "1".to_owned())],
            missing_required: Vec::new(),
        };
        assert_eq!(resolved.to_json_string(), r#"{"a":"1"}"#);
        assert_eq!(ResolvedParameters::default().to_json_string(), "{}");
    }
}
