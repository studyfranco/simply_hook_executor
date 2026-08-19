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

/// Absolute path to `sudo`, used when a hook declares `run_as_user`.
///
/// Hard-coded rather than resolved through `PATH`: a hook's elevation path must not depend on a
/// mutable environment variable, and `PATH` is itself an operator-configurable passthrough.
pub const SUDO_BINARY: &str = "/usr/bin/sudo";

/// Longest accepted `run_as_user` value — `useradd` caps usernames at 32 characters.
const MAX_USERNAME_LEN: usize = 32;

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
    /// Absolute path of the binary to run: the hook's script, or [`SUDO_BINARY`] when the hook
    /// declares a `run_as_user`. Never a shell.
    pub program: String,
    /// The full argument vector, in order. For a privileged hook this begins with sudo's own
    /// `-n -u <user> --` and the script path, followed by the hook's positional parameters.
    pub args: Vec<String>,
    /// The child's complete environment after `env_clear()`.
    pub env: BTreeMap<String, String>,
    /// The account the script will run as, when elevation is configured. Surfaced so the dry-run
    /// preview can state plainly that a hook is privileged.
    pub run_as_user: Option<String>,
}

/// Normalizes a stored `run_as_user` into `Some(user)` only when it carries an actual value.
///
/// An empty or whitespace-only column is treated as "unset" rather than as a username, so a UI
/// that submits an empty text field can never accidentally request elevation to `""`.
pub fn effective_run_as_user(run_as_user: Option<&str>) -> Option<&str> {
    run_as_user.map(str::trim).filter(|user| !user.is_empty())
}

/// Validates a `run_as_user` value.
///
/// This is the primary guard against option injection into `sudo`. The value lands in the argument
/// vector immediately after `-u`, so a hostile value such as `-i` or `--login` must never reach
/// it. Restricting to the POSIX-portable username shape (`[A-Za-z_][A-Za-z0-9_-]*`, plus a
/// trailing `$` for Samba machine accounts) makes an argument that starts with `-` unrepresentable
/// by construction, rather than relying on sudo's own parsing to be defensive.
pub fn validate_run_as_user(run_as_user: &str) -> Result<(), ScriptError> {
    let user = run_as_user.trim();

    let invalid = |reason: &str| {
        Err(ScriptError::new(
            ScriptRejection::InvalidRunAsUser,
            format!("Invalid run_as_user '{run_as_user}': {reason}"),
        ))
    };

    if user.is_empty() {
        return invalid("must not be empty (omit the field to run as the daemon user)");
    }
    if user.len() > MAX_USERNAME_LEN {
        return invalid(&format!("must be at most {MAX_USERNAME_LEN} characters"));
    }

    let mut chars = user.chars();
    match chars.next() {
        // A leading '-' is exactly the option-injection case this rejects.
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return invalid("must start with an ASCII letter or underscore"),
    }

    let body: Vec<char> = chars.collect();
    let (body, _trailing_dollar) = match body.split_last() {
        Some((&'$', rest)) => (rest, true),
        _ => (body.as_slice(), false),
    };
    if !body.iter().all(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-') {
        return invalid("may only contain ASCII letters, digits, '_' and '-'");
    }

    Ok(())
}

/// Builds the [`CommandPlan`] for a hook and a set of resolved parameters.
///
/// Each resolved parameter is passed **both** ways, so a script may consume whichever suits it:
/// as `HOOK_PARAM_<UPPERCASED_KEY>` in the environment, and as a bare positional argument (for
/// Python/shell scripts reading `sys.argv`/`$1`). Positional order is the parameter declaration
/// order, which the `/test` endpoint surfaces explicitly so it never has to be guessed.
///
/// When the hook declares a `run_as_user`, the program becomes [`SUDO_BINARY`] and the vector is
/// prefixed with `-n -u <user> --`:
///
/// - `-n` keeps sudo non-interactive, so a missing NOPASSWD rule fails immediately instead of
///   blocking on a password prompt that nothing can ever answer.
/// - `--` terminates sudo's own option parsing, so a script path or parameter beginning with `-`
///   is passed through as data rather than absorbed as a sudo flag.
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

    let positional = resolved.values.iter().map(|(_, v)| v.clone());
    let run_as_user = effective_run_as_user(hook.run_as_user.as_deref());

    let (program, mut args) = match run_as_user {
        Some(user) => (
            SUDO_BINARY.to_owned(),
            vec![
                "-n".to_owned(),
                "-u".to_owned(),
                user.to_owned(),
                "--".to_owned(),
                hook.script_path.clone(),
            ],
        ),
        None => (hook.script_path.clone(), Vec::new()),
    };
    args.extend(positional);

    CommandPlan {
        program,
        args,
        env,
        run_as_user: run_as_user.map(str::to_owned),
    }
}

// ─────────────────────────────────────────────────────────────
// Script path validation & permission diagnostics
// ─────────────────────────────────────────────────────────────

/// Why a hook's script cannot be executed.
///
/// Kept as a distinct classification rather than a bare string so callers (and tests) can assert
/// on *which* failure occurred, and so the operator-facing text can be written once, in one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptRejection {
    /// The path does not exist (`ENOENT`).
    NotFound,
    /// A path component denied access (`EACCES`) — a missing execute/search bit somewhere.
    PermissionDenied,
    /// The path exists but is a directory, socket, device, ...
    NotARegularFile,
    /// The file exists and is readable but carries no execute bit.
    NotExecutable,
    /// The path resolves outside every configured `ALLOWED_SCRIPT_ROOTS` entry.
    OutsideAllowedRoots,
    /// The path is relative, traverses with `..`, or is otherwise malformed.
    MalformedPath,
    /// `run_as_user` is not a syntactically valid account name.
    InvalidRunAsUser,
    /// `sudo` is required by this hook but is not usable.
    SudoUnavailable,
    /// Anything else the OS reported.
    Unusable,
}

/// A classified script failure plus the full operator-facing diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptError {
    /// What went wrong.
    pub rejection: ScriptRejection,
    /// A `[ERROR] Cannot execute '<path>': <cause>. <remedy>` line, written verbatim to the HTTP
    /// error body, the `tracing` log, and (for spawn-time failures) `executions.stderr`.
    pub detail: String,
}

impl ScriptError {
    fn new(rejection: ScriptRejection, detail: String) -> Self {
        Self { rejection, detail }
    }
}

impl std::fmt::Display for ScriptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}

impl From<ScriptError> for AppError {
    /// Surfaces as `400 Bad Request`: the hook's configuration (or the filesystem it points at) is
    /// wrong, which the caller must fix — it is not a transient server fault.
    fn from(error: ScriptError) -> Self {
        AppError::InvalidInput(error.detail)
    }
}

/// Builds the standard diagnostic line: what failed, the precise cause, and what to do about it.
fn diagnostic(script_path: &str, cause: &str, remedy: &str) -> String {
    format!("[ERROR] Cannot execute '{script_path}': {cause}. {remedy}")
}

/// The daemon's effective identity, for permission diagnostics.
///
/// `USER`/`LOGNAME` are set by systemd from the unit's `User=`, so this usually renders the actual
/// service account name (e.g. `hookrunner`); the numeric ids are always available and are what
/// `ls -n` / `stat` will show when an operator goes looking.
#[cfg(unix)]
fn process_identity() -> String {
    // SAFETY: `geteuid`/`getegid` take no arguments, cannot fail, and only read this process's
    // own credentials.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    match std::env::var("USER").or_else(|_| std::env::var("LOGNAME")) {
        Ok(name) if !name.is_empty() => format!("'{name}' (uid={uid} gid={gid})"),
        _ => format!("uid={uid} gid={gid}"),
    }
}

#[cfg(not(unix))]
fn process_identity() -> String {
    std::env::var("USERNAME")
        .map(|name| format!("'{name}'"))
        .unwrap_or_else(|_| "the service account".to_owned())
}

/// Finds the shallowest directory the daemon lacks *search* (`x`) permission on.
///
/// An `EACCES` on a file almost always means some parent directory lacks the search bit rather
/// than the file itself — pinpointing which one is the difference between an actionable log line
/// and a scavenger hunt.
///
/// Note the indirection: stat'ing a directory only requires search permission on *its* parents, so
/// an unsearchable directory stats perfectly well. What fails is stat'ing something *inside* it.
/// The offender is therefore the parent of the first path in the chain that reports `EACCES`.
fn first_unsearchable_directory(path: &std::path::Path) -> Option<std::path::PathBuf> {
    // `ancestors()` yields the path itself first, then each parent up to the root; reversing walks
    // root-downward, so the first failure encountered is the shallowest one.
    let mut chain: Vec<_> = path.ancestors().collect();
    chain.reverse();

    chain
        .into_iter()
        .find(|candidate| {
            matches!(
                std::fs::metadata(candidate).map_err(|e| e.kind()),
                Err(std::io::ErrorKind::PermissionDenied)
            )
        })
        .and_then(std::path::Path::parent)
        .map(std::path::Path::to_path_buf)
}

/// Turns a filesystem/spawn [`std::io::Error`] into a classified, actionable diagnostic.
///
/// `context` distinguishes the two moments this can happen: the pre-flight check, and the actual
/// `execve` (where the same errno can mean something different — a `noexec` mount, for instance,
/// only shows up at exec time).
fn classify_io_error(script_path: &str, error: &std::io::Error, at_spawn: bool) -> ScriptError {
    let identity = process_identity();

    match error.kind() {
        std::io::ErrorKind::NotFound => ScriptError::new(
            ScriptRejection::NotFound,
            diagnostic(
                script_path,
                "No such file or directory (ENOENT)",
                "The path does not exist. Deploy the script there, or correct the hook's \
                 script_path.",
            ),
        ),
        std::io::ErrorKind::PermissionDenied => {
            let blocked = first_unsearchable_directory(std::path::Path::new(script_path));
            let remedy = match (&blocked, at_spawn) {
                (Some(dir), _) => format!(
                    "Running as {identity}, which cannot search the directory '{}'. Grant traverse \
                     permission on it and every parent (chmod +x), or adjust ownership.",
                    dir.display()
                ),
                (None, true) => format!(
                    "Running as {identity}. The file is reachable but exec was refused — check the \
                     execution bit (chmod +x '{script_path}'), that {identity} owns it or matches \
                     its group, and that its filesystem is not mounted 'noexec'.",
                ),
                (None, false) => format!(
                    "Running as {identity}. Check the execution bit (chmod +x '{script_path}') and \
                     the user/group ownership of the script and its parent directories.",
                ),
            };
            ScriptError::new(
                ScriptRejection::PermissionDenied,
                diagnostic(script_path, "Permission denied (EACCES)", &remedy),
            )
        }
        _ => ScriptError::new(
            ScriptRejection::Unusable,
            diagnostic(
                script_path,
                &format!("{error} (os error kind: {:?})", error.kind()),
                &format!("Running as {identity}. Inspect the path with 'ls -l' and 'stat'."),
            ),
        ),
    }
}

/// Whether `candidate` lies inside one of `roots`.
///
/// Comparison is component-wise via [`std::path::Path::starts_with`], not string-prefix: a root of
/// `/opt/hooks` must not accidentally admit `/opt/hooks-evil`. An empty root list means
/// confinement is disabled.
fn is_within_roots(candidate: &std::path::Path, roots: &[std::path::PathBuf]) -> bool {
    roots.is_empty() || roots.iter().any(|root| candidate.starts_with(root))
}

/// Renders the configured roots for an error message.
fn describe_roots(roots: &[std::path::PathBuf]) -> String {
    roots
        .iter()
        .map(|r| r.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Rejects a hook whose `script_path` is not a runnable file, before anything is spawned or any
/// history row is written.
///
/// Performs the *physical* containment check as well: the path is canonicalized first, so a
/// symlink planted inside an allowed root that points at `/bin/sh` or `/etc/shadow` is caught here
/// even though its literal path passed [`validate_script_path`] at definition time.
pub fn ensure_executable(
    script_path: &str,
    allowed_roots: &[std::path::PathBuf],
) -> Result<(), ScriptError> {
    let path = std::path::Path::new(script_path);

    // `canonicalize` resolves symlinks and `.` segments, and reports ENOENT/EACCES precisely —
    // it is both the existence probe and the input to the containment check.
    let canonical = std::fs::canonicalize(path).map_err(|e| classify_io_error(script_path, &e, false))?;

    if !is_within_roots(&canonical, allowed_roots) {
        return Err(ScriptError::new(
            ScriptRejection::OutsideAllowedRoots,
            diagnostic(
                script_path,
                &format!(
                    "it resolves to '{}', which is outside the allowed script roots",
                    canonical.display()
                ),
                &format!(
                    "Allowed roots are: {}. Move the script inside one of them, or extend \
                     ALLOWED_SCRIPT_ROOTS. (A symlink pointing outside the roots is rejected here \
                     even when its own path looks contained.)",
                    describe_roots(allowed_roots)
                ),
            ),
        ));
    }

    let metadata =
        std::fs::metadata(&canonical).map_err(|e| classify_io_error(script_path, &e, false))?;

    if !metadata.is_file() {
        return Err(ScriptError::new(
            ScriptRejection::NotARegularFile,
            diagnostic(
                script_path,
                "not a regular file (it is a directory, socket, or device node)",
                "Point script_path at an executable file.",
            ),
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        // Deliberately "executable by *someone*", not "executable by us": a privileged hook is
        // routinely a root-owned `0700` script that the daemon user is not meant to be able to run
        // directly — that is precisely what `sudo` is for. Requiring an owner/group/other execute
        // bit still catches the real mistake (a file deployed without `chmod +x` at all), while
        // stat'ing and canonicalizing such a file only needs search permission on its parents,
        // which the daemon does have.
        if mode & 0o111 == 0 {
            return Err(ScriptError::new(
                ScriptRejection::NotExecutable,
                diagnostic(
                    script_path,
                    &format!("the file exists but has no execute bit set (mode {:04o})", mode & 0o7777),
                    &format!(
                        "Run 'chmod +x {script_path}' and ensure {} owns it or matches its group.",
                        process_identity()
                    ),
                ),
            ));
        }
    }

    Ok(())
}

/// Verifies that `sudo` itself is present and executable before a privileged hook is attempted.
///
/// Without this, a missing or non-executable `sudo` surfaces as a bare `ENOENT` naming
/// `/usr/bin/sudo` — technically accurate but baffling to an operator who was looking at their own
/// script path.
fn ensure_sudo_available(run_as_user: &str) -> Result<(), ScriptError> {
    let sudo_error = |cause: &str, remedy: &str| {
        ScriptError::new(
            ScriptRejection::SudoUnavailable,
            format!(
                "[ERROR] Cannot run this hook as '{run_as_user}': {cause}. {remedy}"
            ),
        )
    };

    let metadata = std::fs::metadata(SUDO_BINARY).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => sudo_error(
            &format!("'{SUDO_BINARY}' does not exist"),
            "Install sudo, or clear the hook's run_as_user to run it as the daemon user.",
        ),
        _ => sudo_error(
            &format!("'{SUDO_BINARY}' is not accessible ({e})"),
            "Check that the daemon user can reach it.",
        ),
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(sudo_error(
                &format!("'{SUDO_BINARY}' is not executable"),
                "Restore its permissions (normally 4755).",
            ));
        }
    }

    Ok(())
}

/// Full pre-flight for a hook: elevation configuration first, then the script itself.
///
/// Order matters. A hook whose `run_as_user` is malformed is rejected before the filesystem is
/// touched, so a bad account name can never be reported as a confusing path problem.
pub fn ensure_runnable(hook: &hook::Model, config: &RuntimeConfig) -> Result<(), ScriptError> {
    if let Some(user) = effective_run_as_user(hook.run_as_user.as_deref()) {
        validate_run_as_user(user)?;
        ensure_sudo_available(user)?;
    }

    ensure_executable(&hook.script_path, &config.allowed_script_roots)
}

/// Validates a `script_path` at hook *definition* time.
///
/// Deliberately stricter than [`ensure_executable`] in one dimension and looser in another: the
/// path must be absolute, free of `..` traversal, and (when `ALLOWED_SCRIPT_ROOTS` is configured)
/// lexically inside a permitted root — but the file need not exist yet, since hooks are routinely
/// declared before the script is deployed alongside them. Symlink resolution therefore cannot
/// happen here; [`ensure_executable`] repeats the containment check physically at execution time.
pub fn validate_script_path(
    script_path: &str,
    allowed_roots: &[std::path::PathBuf],
) -> Result<(), ScriptError> {
    let path = std::path::Path::new(script_path);

    if script_path.contains('\0') {
        return Err(ScriptError::new(
            ScriptRejection::MalformedPath,
            "script_path must not contain NUL bytes".to_owned(),
        ));
    }

    if !path.is_absolute() {
        return Err(ScriptError::new(
            ScriptRejection::MalformedPath,
            format!(
                "script_path must be an absolute path (got '{script_path}'); a relative path would \
                 resolve against the daemon's working directory, which is not a stable boundary"
            ),
        ));
    }

    if path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        return Err(ScriptError::new(
            ScriptRejection::MalformedPath,
            format!("script_path must not contain '..' traversal segments (got '{script_path}')"),
        ));
    }

    // `.` segments are harmless but would defeat the component-wise root comparison below, so
    // normalize them away before checking containment.
    let normalized: std::path::PathBuf = path
        .components()
        .filter(|c| !matches!(c, std::path::Component::CurDir))
        .collect();

    if !is_within_roots(&normalized, allowed_roots) {
        return Err(ScriptError::new(
            ScriptRejection::OutsideAllowedRoots,
            format!(
                "script_path '{script_path}' is outside the allowed script roots ({}). Choose a \
                 path inside one of them, or extend ALLOWED_SCRIPT_ROOTS.",
                describe_roots(allowed_roots)
            ),
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
            // Reaching here means the pre-flight check passed but `execve` still failed — a
            // `noexec` mount, a permission or path change in the intervening moment, an exhausted
            // process table. The classified diagnostic goes to both the system log and the
            // execution record, so neither an operator tailing journald nor one reading the
            // dashboard has to guess.
            let diagnosis = classify_io_error(&plan.program, &e, true);
            tracing::error!(
                script = %plan.program,
                rejection = ?diagnosis.rejection,
                io_kind = ?e.kind(),
                "Hook spawn failed: {}",
                diagnosis.detail
            );
            return ExecutionOutcome {
                status: ExecutionStatus::Failed,
                exit_code: None,
                stdout: String::new(),
                stderr: diagnosis.detail,
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
    key: Option<&api_key::Model>,
    resolved: &ResolvedParameters,
) -> Result<execution::Model, AppError> {
    let key_prefix = key.map(|k| k.prefix.as_str()).unwrap_or("(keyless)");

    if let Err(diagnosis) = ensure_runnable(hook, &state.config) {
        // Logged at WARN with the classification attached, so a misconfigured or tampered-with
        // hook is greppable in journald (`rejection=PermissionDenied`) and not merely a 400 that
        // only the caller ever sees.
        tracing::warn!(
            hook = %hook.name,
            key = %key_prefix,
            script = %hook.script_path,
            rejection = ?diagnosis.rejection,
            "Refusing to execute hook: {}",
            diagnosis.detail
        );
        return Err(diagnosis.into());
    }

    // A keyless invocation (`HMAC_ONLY`/`NONE` `auth_mode`) has no `api_keys.max_concurrent_jobs`
    // to throttle against — there is no key. It is not exempt from every limit: `ensure_runnable`,
    // `MAX_REQUEST_BODY_BYTES`, and the process timeout all still apply, and the operator who opted
    // the hook into keyless access accepted the absence of this one specifically.
    let _permit = match key {
        Some(key) => Some(state.limiter.try_acquire(key)?),
        None => None,
    };

    let plan = build_command_plan(hook, resolved, &state.config);
    let timeout = state.config.timeout_for(hook.default_timeout_seconds);
    let started_at = chrono::Utc::now().naive_utc();

    // `run_as_user` is logged on every privileged execution: an operator auditing what ran as root
    // should be able to find it in journald without cross-referencing the hooks table.
    tracing::info!(
        hook = %hook.name,
        key = %key_prefix,
        timeout_s = timeout.as_secs(),
        run_as_user = plan.run_as_user.as_deref().unwrap_or("-"),
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
        api_key_id: Set(key.map(|k| k.id)),
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

    /// A hook fixture, optionally elevated.
    fn demo_hook(run_as_user: Option<&str>) -> hook::Model {
        hook::Model {
            id: Uuid::new_v4(),
            name: "demo".to_owned(),
            description: None,
            script_path: "/usr/local/bin/demo.sh".to_owned(),
            default_timeout_seconds: 30,
            run_as_user: run_as_user.map(str::to_owned),
            owner_key_id: None,
            is_deleted: false,
            deleted_at: None,
            deleted_by: None,
            created_at: Utc::now().naive_utc(),
            updated_at: Utc::now().naive_utc(),
            auth_mode: hook::AuthMode::CanonicalV1,
            hmac_secret: None,
            signature_header: None,
            signature_prefix: None,
            canonical_template: None,
        }
    }

    /// A config with no host passthrough, so env assertions are independent of the test machine.
    fn isolated_config() -> RuntimeConfig {
        RuntimeConfig {
            allowed_env_vars: Vec::new(),
            ..RuntimeConfig::default()
        }
    }

    #[test]
    fn plan_injects_prefixed_env_and_positional_args() {
        let hook = demo_hook(None);
        let resolved = ResolvedParameters {
            values: vec![
                ("target_address".to_owned(), "203.0.113.7".to_owned()),
                ("reason".to_owned(), "abuse".to_owned()),
            ],
            missing_required: Vec::new(),
        };
        // An empty passthrough list keeps this assertion independent of the host environment.
        let plan = build_command_plan(&hook, &resolved, &isolated_config());
        assert_eq!(plan.program, "/usr/local/bin/demo.sh");
        assert_eq!(plan.args, vec!["203.0.113.7", "abuse"]);
        assert_eq!(plan.run_as_user, None);
        assert_eq!(plan.env.get("HOOK_PARAM_TARGET_ADDRESS").map(String::as_str), Some("203.0.113.7"));
        assert_eq!(plan.env.get("HOOK_PARAM_REASON").map(String::as_str), Some("abuse"));
        assert_eq!(plan.env.len(), 2, "no host variables leak in with an empty allowlist");
    }

    #[test]
    fn plan_wraps_privileged_hooks_in_sudo() {
        let hook = demo_hook(Some("root"));
        let resolved = ResolvedParameters {
            values: vec![
                ("target_address".to_owned(), "203.0.113.7".to_owned()),
                ("reason".to_owned(), "abuse".to_owned()),
            ],
            missing_required: Vec::new(),
        };

        let plan = build_command_plan(&hook, &resolved, &isolated_config());

        assert_eq!(plan.program, SUDO_BINARY);
        // The exact vector matters: -n (never prompt), -u <user>, then `--` before anything
        // attacker-influenceable, then the script and its positional parameters.
        assert_eq!(
            plan.args,
            vec!["-n", "-u", "root", "--", "/usr/local/bin/demo.sh", "203.0.113.7", "abuse"]
        );
        assert_eq!(plan.run_as_user.as_deref(), Some("root"));

        // `--` must sit immediately before the script path, so nothing after it can be parsed as
        // a sudo option.
        let separator = plan.args.iter().position(|a| a == "--").expect("the -- separator is present");
        assert_eq!(plan.args[separator + 1], "/usr/local/bin/demo.sh");

        // Environment injection is identical to the unprivileged path.
        assert_eq!(plan.env.get("HOOK_PARAM_TARGET_ADDRESS").map(String::as_str), Some("203.0.113.7"));
        assert_eq!(plan.env.get("HOOK_PARAM_REASON").map(String::as_str), Some("abuse"));
        assert_eq!(plan.env.len(), 2, "no host variables leak in with an empty allowlist");
    }

    #[test]
    fn plan_treats_blank_run_as_user_as_unprivileged() {
        let resolved = ResolvedParameters::default();
        for blank in ["", "   ", "\t"] {
            let plan = build_command_plan(&demo_hook(Some(blank)), &resolved, &isolated_config());
            assert_eq!(plan.program, "/usr/local/bin/demo.sh", "{blank:?} must not trigger sudo");
            assert!(plan.args.is_empty());
            assert_eq!(plan.run_as_user, None);
        }
    }

    #[test]
    fn plan_trims_surrounding_whitespace_from_run_as_user() {
        let plan = build_command_plan(&demo_hook(Some("  postgres  ")), &ResolvedParameters::default(), &isolated_config());
        assert_eq!(plan.args, vec!["-n", "-u", "postgres", "--", "/usr/local/bin/demo.sh"]);
        assert_eq!(plan.run_as_user.as_deref(), Some("postgres"));
    }

    #[test]
    fn privileged_plan_keeps_parameters_positional_after_the_separator() {
        // A parameter value that looks like a sudo option must land after `--`, where sudo can
        // only treat it as an argument to the script.
        let resolved = ResolvedParameters {
            values: vec![("flag".to_owned(), "--login".to_owned())],
            missing_required: Vec::new(),
        };
        let plan = build_command_plan(&demo_hook(Some("root")), &resolved, &isolated_config());

        let separator = plan.args.iter().position(|a| a == "--").expect("the -- separator is present");
        let hostile = plan.args.iter().position(|a| a == "--login").expect("the value is present");
        assert!(hostile > separator, "a option-shaped value must sit after the separator");
    }

    #[test]
    fn validates_run_as_user_against_option_injection() {
        for valid in ["root", "postgres", "_svc", "deploy-bot", "user_1", "machine$"] {
            assert!(validate_run_as_user(valid).is_ok(), "{valid} should be accepted");
        }

        // The leading-dash cases are the option-injection attempts this exists to stop.
        for invalid in [
            "-i", "--login", "-u", "", "   ", "root user", "root;id", "root\0", "root/../x",
            "1user", "user$name", "üser", "root\n-i",
        ] {
            let err = validate_run_as_user(invalid).expect_err("{invalid} should be rejected");
            assert_eq!(err.rejection, ScriptRejection::InvalidRunAsUser, "for {invalid:?}");
        }

        // Length cap.
        assert!(validate_run_as_user(&"a".repeat(MAX_USERNAME_LEN)).is_ok());
        assert!(validate_run_as_user(&"a".repeat(MAX_USERNAME_LEN + 1)).is_err());
    }

    #[test]
    fn normalizes_effective_run_as_user() {
        assert_eq!(effective_run_as_user(None), None);
        assert_eq!(effective_run_as_user(Some("")), None);
        assert_eq!(effective_run_as_user(Some("  ")), None);
        assert_eq!(effective_run_as_user(Some(" root ")), Some("root"));
    }

    #[test]
    fn rejects_relative_and_traversing_script_paths() {
        let unrestricted: [std::path::PathBuf; 0] = [];
        assert!(validate_script_path("/usr/local/bin/ok.sh", &unrestricted).is_ok());

        for traversal in [
            "relative.sh",
            "./relative.sh",
            "../escape.sh",
            "/usr/local/../../etc/shadow",
            "/opt/hooks/../../../etc/shadow",
            "/scripts/../../etc/shadow",
        ] {
            let err = validate_script_path(traversal, &unrestricted)
                .expect_err("{traversal} must be rejected");
            assert_eq!(err.rejection, ScriptRejection::MalformedPath, "for {traversal}");
        }
    }

    #[test]
    fn confines_script_paths_to_allowed_roots() {
        let roots = [std::path::PathBuf::from("/opt/hooks"), std::path::PathBuf::from("/usr/local/bin")];

        assert!(validate_script_path("/opt/hooks/deploy.sh", &roots).is_ok());
        assert!(validate_script_path("/opt/hooks/nested/deploy.sh", &roots).is_ok());
        assert!(validate_script_path("/usr/local/bin/ban.sh", &roots).is_ok());
        // A `.` segment must not defeat the component-wise comparison.
        assert!(validate_script_path("/opt/./hooks/deploy.sh", &roots).is_ok());

        for outside in ["/etc/shadow", "/bin/sh", "/opt/other/x.sh", "/tmp/evil.sh"] {
            let err = validate_script_path(outside, &roots).expect_err("{outside} must be rejected");
            assert_eq!(err.rejection, ScriptRejection::OutsideAllowedRoots, "for {outside}");
        }

        // Component-wise, not string-prefix: a sibling directory sharing a name prefix is outside.
        let err = validate_script_path("/opt/hooks-evil/x.sh", &roots)
            .expect_err("a name-prefixed sibling is not contained");
        assert_eq!(err.rejection, ScriptRejection::OutsideAllowedRoots);
    }

    #[test]
    fn empty_root_list_disables_confinement() {
        let unrestricted: [std::path::PathBuf; 0] = [];
        assert!(is_within_roots(std::path::Path::new("/anywhere/at/all"), &unrestricted));
        assert!(validate_script_path("/anywhere/at/all.sh", &unrestricted).is_ok());
    }

    #[test]
    fn rejects_nul_bytes_in_script_paths() {
        let unrestricted: [std::path::PathBuf; 0] = [];
        let err = validate_script_path("/opt/hooks/x\0.sh", &unrestricted)
            .expect_err("interior NUL must be rejected");
        assert_eq!(err.rejection, ScriptRejection::MalformedPath);
    }

    #[test]
    fn classifies_io_errors_with_actionable_diagnostics() {
        let not_found = classify_io_error(
            "/opt/hooks/missing.sh",
            &std::io::Error::from(std::io::ErrorKind::NotFound),
            false,
        );
        assert_eq!(not_found.rejection, ScriptRejection::NotFound);
        assert!(not_found.detail.starts_with("[ERROR] Cannot execute '/opt/hooks/missing.sh':"));
        assert!(not_found.detail.contains("ENOENT"));

        let denied = classify_io_error(
            "/opt/hooks/locked.sh",
            &std::io::Error::from(std::io::ErrorKind::PermissionDenied),
            false,
        );
        assert_eq!(denied.rejection, ScriptRejection::PermissionDenied);
        assert!(denied.detail.contains("EACCES"));
        // The remedy must name both halves of the usual cause: the bit and the ownership.
        assert!(denied.detail.contains("chmod +x"));
        assert!(denied.detail.contains("ownership") || denied.detail.contains("search"));

        // At spawn time the same errno additionally implicates a noexec mount.
        let at_spawn = classify_io_error(
            "/opt/hooks/locked.sh",
            &std::io::Error::from(std::io::ErrorKind::PermissionDenied),
            true,
        );
        assert!(at_spawn.detail.contains("noexec") || at_spawn.detail.contains("search"));

        let other = classify_io_error(
            "/opt/hooks/weird.sh",
            &std::io::Error::from(std::io::ErrorKind::InvalidInput),
            false,
        );
        assert_eq!(other.rejection, ScriptRejection::Unusable);
    }

    #[test]
    fn script_errors_surface_as_bad_request() {
        let error = ScriptError::new(ScriptRejection::NotFound, "[ERROR] boom".to_owned());
        assert!(matches!(AppError::from(error), AppError::InvalidInput(msg) if msg == "[ERROR] boom"));
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
