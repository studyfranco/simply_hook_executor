//! Remote SSH execution engine.
//!
//! [`crate::executor`]'s own module doc states its first invariant as "No shell, ever" — the hook's
//! program is handed to [`tokio::process::Command`] as a binary plus an argument *vector*, never a
//! string. SSH's `exec` channel has no equivalent primitive: [RFC 4254 §6.5](https://www.rfc-editor.org/rfc/rfc4254#section-6.5)
//! defines it as exactly one opaque command string, interpreted by whatever shell the remote
//! account's `sshd` invokes. There is no shell-free SSH exec request to fall back to — the protocol
//! itself only offers this one shape.
//!
//! This module's safety property is therefore necessarily different in kind from `executor`'s, not
//! merely a network-attached copy of it: every token that goes into that one command string —
//! [`crate::executor::CommandPlan::program`], every argument, every `KEY=VALUE` environment
//! assignment — is unconditionally wrapped with [`shell_quote`] before being joined, so no value a
//! caller ever influences (a parameter, a rendered `args_template` entry) can break out of its own
//! quoting no matter what characters it contains. "No shell" becomes "the shell only ever sees
//! single-quoted literals, never syntax it can act on".
//!
//! Two more properties this module owns that `executor` does not need to:
//!
//! - **Environment passthrough without `SetEnv`.** SSH's `SetEnv` channel request
//!   ([RFC 4254 §6.7 erratum](https://www.rfc-editor.org/rfc/rfc4254#section-6.7)) is routinely
//!   refused by real-world `sshd` configurations (`AcceptEnv` allowlisting, disabled by default in
//!   most distributions), so it cannot be relied on to deliver `HOOK_PARAM_*` values. Instead, the
//!   remote command line is always `env <KEY=VALUE...> <program> <args...>` — `env`(1) is
//!   effectively universal on any host worth running a hook on, and setting variables this way needs
//!   no server-side configuration at all. [`crate::executor::validate_remote_command`] guards the one
//!   sharp edge this creates: `env` tells an assignment from the command to run purely by whether a
//!   token is shaped like `NAME=VALUE`, so `program` itself must never be.
//! - **Fingerprint pinning, not trust-on-first-use.** [`HostKeyPinning`] rejects every host key
//!   except the one byte-for-byte fingerprint recorded on the [`ssh_target::Model`] row
//!   (`api::ssh::fetch_ssh_host_fingerprint` is the *only* place a fingerprint is ever learned and
//!   requires an explicit operator confirmation before it is stored) — there is deliberately no path
//!   where a hook's first real execution is also the first time its target's host key is seen, which
//!   is what a TOFU-at-connect-time policy would mean in practice.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use russh::keys::{HashAlg, PrivateKeyWithHashAlg, PublicKeyOrCertificate, decode_secret_key};
use russh::{ChannelMsg, Disconnect, client};

use crate::crypto::SecretCipher;
use crate::entities::{execution::ExecutionStatus, ssh_credential, ssh_target};
use crate::error::AppError;
use crate::executor::{CommandPlan, ExecutionOutcome, elapsed_ms};

/// Wraps `s` in single quotes, escaping any embedded single quote as `'\''` (close the quote, an
/// escaped literal quote, reopen the quote) — the standard POSIX-shell-safe quoting idiom. The
/// result is inert to the remote shell no matter what `s` contains: no character inside a
/// single-quoted string is special to any POSIX-family shell, including another single quote (which
/// is exactly why it has to be closed-escaped-reopened rather than escaped in place).
pub fn shell_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Renders a [`CommandPlan`] as the single command line SSH's `exec` channel requires.
///
/// Always `env <KEY=VALUE...> <program> <args...>`, every token individually [`shell_quote`]d — see
/// this module's own doc comment for why `env`, and [`crate::executor::validate_remote_command`] for
/// the one invariant this construction depends on (`program` never looking like `NAME=VALUE`).
/// `plan.env`'s `BTreeMap` ordering also makes this output deterministic, which is incidental but
/// convenient for testing.
fn build_remote_command(plan: &CommandPlan) -> String {
    let mut parts = Vec::with_capacity(1 + plan.env.len() + 1 + plan.args.len());
    parts.push("env".to_owned());
    for (key, value) in &plan.env {
        parts.push(shell_quote(&format!("{key}={value}")));
    }
    parts.push(shell_quote(&plan.program));
    parts.extend(plan.args.iter().map(|a| shell_quote(a)));
    parts.join(" ")
}

/// Everything [`run_remote_process`] needs to open one SSH connection: fully decrypted, fully
/// resolved, and carrying no database handle — built by [`Self::from_target_and_credential`]
/// strictly before the network call it feeds, so no DB connection is ever held open across the SSH
/// handshake/execution window.
pub struct SshConnectionSpec {
    host: String,
    port: u16,
    username: String,
    host_key_fingerprint: String,
    auth: SshAuthMaterial,
}

/// Decrypted authentication material for one [`SshConnectionSpec`]. Never logged, never serialized,
/// dropped as soon as the connection attempt that consumes it finishes.
enum SshAuthMaterial {
    /// Private key material, and its passphrase if the key itself is encrypted.
    Key { private_key: String, passphrase: Option<String> },
    /// A plain login password.
    Password { password: String },
}

impl SshConnectionSpec {
    /// Builds a connection spec from a target and its credential, decrypting every secret field
    /// through `cipher` in the process.
    ///
    /// Every failure here is either a data-integrity problem (a `NULL` secret column that
    /// `auth_type` says should be populated, a port outside `u16`'s range — both should be
    /// unreachable given the write-time validation in `api::ssh`) or a decryption failure (the
    /// daemon's `SIGNING_SECRET_KEY` no longer matches what wrote the row), so both map to
    /// [`AppError::Internal`], mirroring `middleware::recover_hook_secret`'s identical judgment call
    /// for the same reason: neither is the caller's mistake to be told about as a `400`.
    pub fn from_target_and_credential(
        cipher: &SecretCipher,
        target: &ssh_target::Model,
        credential: &ssh_credential::Model,
    ) -> Result<Self, AppError> {
        let host_key_fingerprint = target.host_key_fingerprint.clone().ok_or_else(|| {
            AppError::InvalidInput(format!(
                "SSH target '{}' has no pinned host key fingerprint yet; fetch and confirm one \
                 (POST /api/ssh-targets/{{id}}/fetch-fingerprint) before executing hooks against it",
                target.name
            ))
        })?;

        let port = u16::try_from(target.port).map_err(|_| {
            tracing::error!(
                target = %target.name,
                port = target.port,
                "SSH target has an out-of-range port"
            );
            AppError::Internal
        })?;

        let open = |stored: &str, what: &str| -> Result<String, AppError> {
            cipher.open(stored).map_err(|e| {
                tracing::error!(
                    credential = %credential.name,
                    "Failed to decrypt an SSH credential's {what}: {e}"
                );
                AppError::Internal
            })
        };

        let auth = match credential.auth_type {
            ssh_credential::SshAuthType::Key => {
                let stored = credential.encrypted_private_key.as_deref().ok_or_else(|| {
                    tracing::error!(
                        credential = %credential.name,
                        "KEY credential has no private key stored"
                    );
                    AppError::Internal
                })?;
                let private_key = open(stored, "private key")?;
                let passphrase = match &credential.encrypted_passphrase {
                    Some(stored) => Some(open(stored, "passphrase")?),
                    None => None,
                };
                SshAuthMaterial::Key { private_key, passphrase }
            }
            ssh_credential::SshAuthType::Password => {
                let stored = credential.encrypted_password.as_deref().ok_or_else(|| {
                    tracing::error!(
                        credential = %credential.name,
                        "PASSWORD credential has no password stored"
                    );
                    AppError::Internal
                })?;
                SshAuthMaterial::Password { password: open(stored, "password")? }
            }
        };

        Ok(Self {
            host: target.host.clone(),
            port,
            username: target.username.clone(),
            host_key_fingerprint,
            auth,
        })
    }
}

/// A descriptive SSH connection/authentication failure.
///
/// Surfaced verbatim to whichever caller asked for a definite yes/no answer about reachability
/// (`POST /api/ssh-targets/{id}/test-connection`, `POST /api/ssh-targets/fetch-fingerprint`) — unlike
/// [`run_remote_process`], which is a hook's actual dispatch path and, matching
/// [`crate::executor::run_process`]'s own contract, is never allowed to fail outright; it turns every
/// failure mode this type would otherwise carry into a `FAILED` or `TIMEOUT`
/// [`ExecutionOutcome`] instead.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct SshRunError(String);

/// A [`client::Handler`] that accepts exactly one host key: the fingerprint pinned on the target row.
///
/// The default [`client::Handler::check_server_key`] rejects every key (fail-closed); this
/// implementation stays just as strict, narrowing "reject everything" to "reject everything except
/// this one fingerprint" rather than loosening it.
struct HostKeyPinning {
    expected_fingerprint: String,
}

impl client::Handler for HostKeyPinning {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let PublicKeyOrCertificate::PublicKey { key, .. } = server_public_key else {
            // A certificate-authenticated host has no bare-key fingerprint to compare against this
            // deployment's TOFU model (`ssh_targets.host_key_fingerprint`), so it is refused rather
            // than silently trusted on some other basis.
            return Ok(false);
        };
        Ok(key.fingerprint(HashAlg::Sha256).to_string() == self.expected_fingerprint)
    }
}

/// Connects to `spec`'s target, verifies its host key against the pinned fingerprint, and
/// authenticates. Used by both [`test_connection`] and [`run_remote_process`] — the one place either
/// of them can fail before anything remote has actually been asked to run.
async fn connect_authenticated(
    spec: &SshConnectionSpec,
) -> Result<client::Handle<HostKeyPinning>, SshRunError> {
    let config = Arc::new(client::Config::default());
    let handler = HostKeyPinning { expected_fingerprint: spec.host_key_fingerprint.clone() };

    let mut session =
        client::connect(config, (spec.host.as_str(), spec.port), handler).await.map_err(|e| {
            if matches!(e, russh::Error::UnknownKey) {
                SshRunError(format!(
                    "the host key offered by '{}:{}' does not match the pinned fingerprint '{}' for \
                     this target; refusing to connect (possible man-in-the-middle, or the host was \
                     rebuilt and needs its fingerprint re-pinned)",
                    spec.host, spec.port, spec.host_key_fingerprint
                ))
            } else {
                SshRunError(format!("could not connect to '{}:{}': {e}", spec.host, spec.port))
            }
        })?;

    let auth_result = match &spec.auth {
        SshAuthMaterial::Password { password } => {
            session.authenticate_password(spec.username.clone(), password.clone()).await
        }
        SshAuthMaterial::Key { private_key, passphrase } => {
            let key = decode_secret_key(private_key, passphrase.as_deref()).map_err(|e| {
                SshRunError(format!("the stored private key could not be parsed: {e}"))
            })?;
            // `Some(Sha256)` opts an RSA key into the modern `rsa-sha2-256` signature algorithm
            // instead of the legacy SHA-1 one `None` would select; every other key type ignores
            // this parameter entirely (`PrivateKeyWithHashAlg::new`'s own doc comment).
            let key_with_hash = PrivateKeyWithHashAlg::new(Arc::new(key), Some(HashAlg::Sha256));
            session.authenticate_publickey(spec.username.clone(), key_with_hash).await
        }
    };

    match auth_result {
        Ok(result) if result.success() => Ok(session),
        Ok(_) => Err(SshRunError(format!(
            "authentication as '{}' on '{}:{}' was rejected by the server",
            spec.username, spec.host, spec.port
        ))),
        Err(e) => Err(SshRunError(format!(
            "authentication as '{}' on '{}:{}' failed: {e}",
            spec.username, spec.host, spec.port
        ))),
    }
}

/// Verifies that `spec` is fully usable — reachable, host key pinned correctly, credential
/// accepted — without running anything. Backs `POST /api/ssh-targets/{id}/test-connection`.
pub async fn test_connection(spec: &SshConnectionSpec, timeout: Duration) -> Result<(), SshRunError> {
    let session = tokio::time::timeout(timeout, connect_authenticated(spec)).await.map_err(|_| {
        SshRunError(format!(
            "connecting to '{}:{}' as '{}' did not complete within {}s",
            spec.host,
            spec.port,
            spec.username,
            timeout.as_secs()
        ))
    })??;
    // Best-effort: the connection is about to be dropped either way, and nothing downstream reads
    // whether the server acknowledged a clean disconnect.
    let _ = session.disconnect(Disconnect::ByApplication, "", "en").await;
    Ok(())
}

/// A [`client::Handler`] that trusts every host key it is offered, recording its fingerprint into
/// `observed` for the caller to read back once the connection succeeds.
///
/// Deliberately the opposite policy from [`HostKeyPinning`] — used *only* by
/// [`fetch_host_key_fingerprint`], whose entire purpose is learning a key, not verifying one. This
/// handler can never be reached by a hook execution: [`run_remote_process`] always goes through
/// [`connect_authenticated`], which only ever constructs [`HostKeyPinning`].
///
/// `observed` is an `Arc<Mutex<_>>` rather than a plain field because the handler is moved by value
/// into `russh`'s background connection task at `connect()` time and is not reachable from the
/// caller afterward — the shared cell is the only way to read back what it saw. `russh` awaits the
/// completion of key exchange (during which `check_server_key` is called) before `connect()` itself
/// resolves, so by the time the caller observes `Ok(session)`, the write below has already happened.
#[derive(Clone)]
struct FingerprintLearner {
    observed: Arc<Mutex<Option<String>>>,
}

impl client::Handler for FingerprintLearner {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        if let PublicKeyOrCertificate::PublicKey { key, .. } = server_public_key {
            let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
            if let Ok(mut guard) = self.observed.lock() {
                *guard = Some(fingerprint);
            }
        }
        Ok(true)
    }
}

/// Connects to `host:port`, records the fingerprint of whatever host key it offers, and disconnects
/// without authenticating. Backs `POST /api/ssh-targets/fetch-fingerprint` — the one operator-facing
/// step in this deployment's TOFU model, explicitly separate from every hook execution path.
pub async fn fetch_host_key_fingerprint(
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<String, SshRunError> {
    let config = Arc::new(client::Config::default());
    let observed = Arc::new(Mutex::new(None));
    let handler = FingerprintLearner { observed: Arc::clone(&observed) };

    let session = tokio::time::timeout(timeout, client::connect(config, (host, port), handler))
        .await
        .map_err(|_| {
            SshRunError(format!(
                "connecting to '{host}:{port}' did not complete within {}s",
                timeout.as_secs()
            ))
        })?
        .map_err(|e| SshRunError(format!("could not connect to '{host}:{port}': {e}")))?;

    let fingerprint = observed.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone();
    let _ = session.disconnect(Disconnect::ByApplication, "", "en").await;

    fingerprint.ok_or_else(|| {
        SshRunError(format!(
            "'{host}:{port}' did not offer a plain public host key during key exchange \
             (certificate-based host authentication is not supported for fingerprint pinning)"
        ))
    })
}

/// A captured output stream plus whether it hit the size cap — [`run_remote_process`]'s sequential
/// counterpart to [`crate::executor`]'s `CapturedStream`. That one is shared across concurrent pipe
/// readers behind an `Arc<Mutex<_>>` because local execution drains two OS pipes concurrently; an SSH
/// channel multiplexes stdout (`ChannelMsg::Data`) and stderr (`ChannelMsg::ExtendedData`) through
/// the *same* ordered message queue, so one `channel.wait()` loop observes both without any
/// concurrency to synchronize — a plain, unshared struct is the whole mechanism needed here.
#[derive(Default)]
struct CapturedStream {
    bytes: Vec<u8>,
    truncated: bool,
}

impl CapturedStream {
    fn push(&mut self, data: &[u8], limit: usize) {
        let remaining = limit.saturating_sub(self.bytes.len());
        if remaining == 0 {
            self.truncated = true;
        } else if data.len() > remaining {
            self.bytes.extend_from_slice(&data[..remaining]);
            self.truncated = true;
        } else {
            self.bytes.extend_from_slice(data);
        }
    }

    fn finish(self) -> String {
        let mut text = String::from_utf8_lossy(&self.bytes).into_owned();
        if self.truncated {
            text.push_str("\n[output truncated: exceeded MAX_OUTPUT_BYTES]");
        }
        text
    }
}

/// The `128 + signum` form of a remote process killed by a signal, on the standard Linux/x86 (and
/// ARM) signal numbering — matching the convention
/// [`crate::executor::run_process`] reports for a locally `SIGKILL`ed hook. Best-effort: `Sig` covers
/// only a fixed, commonly-used subset of POSIX signals, and its `Custom` variant (an arbitrary name
/// the remote end chose to report) has no portable number to map to at all.
fn signal_exit_code(signal: &russh::Sig) -> Option<i32> {
    let number = match signal {
        russh::Sig::HUP => 1,
        russh::Sig::INT => 2,
        russh::Sig::QUIT => 3,
        russh::Sig::ILL => 4,
        russh::Sig::ABRT => 6,
        russh::Sig::FPE => 8,
        russh::Sig::KILL => 9,
        russh::Sig::USR1 => 10,
        russh::Sig::SEGV => 11,
        russh::Sig::PIPE => 13,
        russh::Sig::ALRM => 14,
        russh::Sig::TERM => 15,
        russh::Sig::Custom(_) => return None,
    };
    Some(128 + number)
}

/// Runs `plan` on the remote host described by `spec` over SSH.
///
/// Never returns an error, matching [`crate::executor::run_process`]'s own contract exactly: a
/// target that cannot be reached, a credential the server rejects, a command that cannot be started,
/// all become a `FAILED` (or, past `timeout`, `TIMEOUT`) [`ExecutionOutcome`] with the failure
/// captured in `stderr`, rather than a `500` — a remote dispatch failure belongs in the execution
/// history like any other failure, not out of band from it.
///
/// `timeout` bounds the *entire* operation — connecting, authenticating, opening the channel, and
/// running the command — not merely the command's own runtime, since none of those steps has a
/// separate budget of its own. Partial stdout/stderr already read before a mid-command timeout is
/// still recorded: only the network-level connect/auth/channel-open steps risk losing everything
/// they were doing to a timeout (there is nothing to have captured yet at that point).
///
/// One respect in which this cannot fully match local execution: there is no portable way to force
/// the remote command to stop the moment `timeout` elapses. [`crate::executor::run_process`] can
/// `SIGKILL` an entire local process group; here, exceeding the deadline drops the SSH connection
/// (ending this function's own wait), but a remote process that ignores its stdin/pipe closing and
/// keeps running independently of the session will do exactly that — a limitation of the SSH
/// protocol itself, not of this implementation.
pub async fn run_remote_process(
    spec: &SshConnectionSpec,
    plan: &CommandPlan,
    timeout: Duration,
    max_output_bytes: usize,
) -> ExecutionOutcome {
    let started = Instant::now();
    let deadline = started + timeout;
    let remaining = || deadline.saturating_duration_since(Instant::now());

    let failed = |detail: String| {
        tracing::warn!(host = %spec.host, port = spec.port, "SSH execution failed: {detail}");
        ExecutionOutcome {
            status: ExecutionStatus::Failed,
            exit_code: None,
            stdout: String::new(),
            stderr: format!("[ERROR] {detail}"),
            duration_ms: elapsed_ms(started),
        }
    };
    let timed_out = |doing: &str, stdout: String, stderr_so_far: String| {
        let mut stderr = stderr_so_far;
        if !stderr.is_empty() {
            stderr.push('\n');
        }
        stderr.push_str(&format!("[ERROR] {doing} exceeded its {}s timeout", timeout.as_secs()));
        ExecutionOutcome {
            status: ExecutionStatus::Timeout,
            exit_code: None,
            stdout,
            stderr,
            duration_ms: elapsed_ms(started),
        }
    };

    let session = match tokio::time::timeout(remaining(), connect_authenticated(spec)).await {
        Ok(Ok(session)) => session,
        Ok(Err(e)) => return failed(e.to_string()),
        Err(_) => {
            return timed_out(
                &format!("Connecting to '{}@{}:{}'", spec.username, spec.host, spec.port),
                String::new(),
                String::new(),
            );
        }
    };

    let mut channel = match tokio::time::timeout(remaining(), session.channel_open_session()).await {
        Ok(Ok(channel)) => channel,
        Ok(Err(e)) => return failed(format!("could not open an SSH session channel: {e}")),
        Err(_) => {
            return timed_out(
                &format!("Opening an SSH session channel to '{}:{}'", spec.host, spec.port),
                String::new(),
                String::new(),
            );
        }
    };

    let command = build_remote_command(plan);
    match tokio::time::timeout(remaining(), channel.exec(true, command.into_bytes())).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return failed(format!("could not start the remote command: {e}")),
        Err(_) => {
            return timed_out(
                &format!("Starting the remote command on '{}:{}'", spec.host, spec.port),
                String::new(),
                String::new(),
            );
        }
    }

    let mut stdout = CapturedStream::default();
    let mut stderr = CapturedStream::default();
    let mut exit_code: Option<i32> = None;

    loop {
        let msg = match tokio::time::timeout(remaining(), channel.wait()).await {
            Ok(msg) => msg,
            Err(_) => {
                return timed_out(
                    &format!("Executing the remote command on '{}:{}'", spec.host, spec.port),
                    stdout.finish(),
                    stderr.finish(),
                );
            }
        };
        match msg {
            // `1` is `SSH_EXTENDED_DATA_STDERR`, the only extended-data type RFC 4254 §5.2 defines;
            // anything else is silently dropped rather than misfiled into either stream.
            Some(ChannelMsg::Data { data }) => stdout.push(&data, max_output_bytes),
            Some(ChannelMsg::ExtendedData { data, ext: 1 }) => stderr.push(&data, max_output_bytes),
            Some(ChannelMsg::ExitStatus { exit_status }) => exit_code = Some(exit_status as i32),
            Some(ChannelMsg::ExitSignal { signal_name, error_message, .. }) => {
                exit_code = signal_exit_code(&signal_name);
                stderr.push(
                    format!(
                        "\n[remote process terminated by signal {signal_name:?}: {error_message}]\n"
                    )
                    .as_bytes(),
                    max_output_bytes,
                );
            }
            Some(ChannelMsg::Close) | None => break,
            Some(_) => {}
        }
    }

    // Best-effort: the loop above only exits once the channel itself is done, so the underlying
    // connection has nothing further to do either way.
    let _ = session.disconnect(Disconnect::ByApplication, "", "en").await;

    let stdout = stdout.finish();
    let mut stderr = stderr.finish();
    let status = match exit_code {
        Some(0) => ExecutionStatus::Success,
        Some(_) => ExecutionStatus::Failed,
        None => {
            if stderr.is_empty() {
                stderr.push_str(
                    "[ERROR] The SSH connection closed before the remote command reported an exit \
                     status",
                );
            }
            ExecutionStatus::Failed
        }
    };

    ExecutionOutcome { status, exit_code, stdout, stderr, duration_ms: elapsed_ms(started) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn plan(program: &str, args: &[&str], env: &[(&str, &str)]) -> CommandPlan {
        CommandPlan {
            program: program.to_owned(),
            args: args.iter().map(|s| (*s).to_owned()).collect(),
            env: env.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<BTreeMap<_, _>>(),
            run_as_user: None,
        }
    }

    #[test]
    fn quotes_plain_values_inertly() {
        assert_eq!(shell_quote("hello"), "'hello'");
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn escapes_embedded_single_quotes() {
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(shell_quote("''"), "''\\'''\\'''");
    }

    #[test]
    fn neutralizes_shell_metacharacters() {
        for hostile in ["$(rm -rf /)", "; rm -rf /", "`whoami`", "a && b", "a | b", "a\nb"] {
            let quoted = shell_quote(hostile);
            assert!(quoted.starts_with('\'') && quoted.ends_with('\''));
            // Every character of the original survives verbatim inside the quoting, just wrapped —
            // this is an inertness property (nothing escapes the quotes), not a content filter.
            assert!(quoted.contains(hostile) || hostile.contains('\''));
        }
    }

    #[test]
    fn builds_env_prefixed_command_line() {
        let plan = plan("/opt/hooks/deploy.sh", &["prod"], &[("HOOK_PARAM_TARGET", "prod")]);
        assert_eq!(
            build_remote_command(&plan),
            "env 'HOOK_PARAM_TARGET=prod' '/opt/hooks/deploy.sh' 'prod'"
        );
    }

    #[test]
    fn builds_command_line_with_no_env() {
        let plan = plan("/opt/hooks/noop.sh", &[], &[]);
        assert_eq!(build_remote_command(&plan), "env '/opt/hooks/noop.sh'");
    }

    #[test]
    fn quotes_hostile_argv_entries_inertly() {
        let plan = plan("/opt/hooks/deploy.sh", &["$(rm -rf /)"], &[]);
        let command = build_remote_command(&plan);
        assert_eq!(command, "env '/opt/hooks/deploy.sh' '$(rm -rf /)'");
    }

    #[test]
    fn maps_common_signals_to_128_plus_signum() {
        assert_eq!(signal_exit_code(&russh::Sig::KILL), Some(137));
        assert_eq!(signal_exit_code(&russh::Sig::TERM), Some(143));
        assert_eq!(signal_exit_code(&russh::Sig::Custom("WINCH".to_owned())), None);
    }

    #[test]
    fn captured_stream_truncates_at_limit() {
        let mut stream = CapturedStream::default();
        stream.push(b"hello", 3);
        assert_eq!(stream.finish(), "hel\n[output truncated: exceeded MAX_OUTPUT_BYTES]");
    }

    #[test]
    fn captured_stream_keeps_short_output_untouched() {
        let mut stream = CapturedStream::default();
        stream.push(b"hello", 100);
        assert_eq!(stream.finish(), "hello");
    }
}
