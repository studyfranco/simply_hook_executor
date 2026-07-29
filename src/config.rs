//! Runtime configuration, read once from the environment at startup.
//!
//! Every field has a safe default so the daemon runs with zero configuration; each is documented
//! with the environment variable that overrides it. Values are parsed leniently — a malformed
//! override logs a warning and falls back to the default rather than aborting startup, since a
//! typo in a unit file should never take the whole service down.

use std::sync::Arc;

/// Default environment variables inherited by hook sub-processes, per `AGENT.MD`.
const DEFAULT_ALLOWED_ENV_VARS: &str = "PATH,LANG,TERM,SYSTEMROOT";
/// Default retention window for `executions` rows, in days.
const DEFAULT_LOG_RETENTION_DAYS: i64 = 30;
/// Default interval between retention sweeps, in seconds (hourly).
const DEFAULT_RETENTION_SWEEP_SECONDS: u64 = 3600;
/// Default per-stream cap on captured output, in bytes (1 MiB).
const DEFAULT_MAX_OUTPUT_BYTES: usize = 1024 * 1024;
/// Fallback timeout applied when a hook stores a non-positive `default_timeout_seconds`.
const FALLBACK_TIMEOUT_SECONDS: u64 = 30;

/// Immutable runtime configuration shared by every handler and background worker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeConfig {
    /// Names of the host environment variables passed through to hook sub-processes after
    /// `env_clear()`. Overridden by `ALLOWED_ENV_VARS` (comma-separated).
    pub allowed_env_vars: Vec<String>,
    /// Age, in days, beyond which `executions` rows are purged. Overridden by
    /// `LOG_RETENTION_DAYS`. A value of `0` disables purging entirely.
    pub log_retention_days: i64,
    /// Seconds between retention sweeps. Overridden by `RETENTION_SWEEP_SECONDS`.
    pub retention_sweep_seconds: u64,
    /// Maximum bytes retained per captured stream (stdout and stderr each). Output beyond this is
    /// discarded — but still drained, so a chatty hook can never deadlock on a full pipe.
    /// Overridden by `MAX_OUTPUT_BYTES`.
    pub max_output_bytes: usize,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            allowed_env_vars: parse_env_var_list(DEFAULT_ALLOWED_ENV_VARS),
            log_retention_days: DEFAULT_LOG_RETENTION_DAYS,
            retention_sweep_seconds: DEFAULT_RETENTION_SWEEP_SECONDS,
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
        }
    }
}

impl RuntimeConfig {
    /// Builds the configuration from the process environment, falling back to defaults.
    pub fn from_env() -> Self {
        let defaults = Self::default();

        let allowed_env_vars = match std::env::var("ALLOWED_ENV_VARS") {
            Ok(raw) => {
                let parsed = parse_env_var_list(&raw);
                if parsed.is_empty() {
                    // An explicitly empty list is a legitimate choice (maximum isolation: hooks
                    // inherit nothing at all), so it is honored rather than silently replaced.
                    tracing::info!("ALLOWED_ENV_VARS is empty: hooks will inherit no host environment variables");
                }
                parsed
            }
            Err(_) => defaults.allowed_env_vars,
        };

        Self {
            allowed_env_vars,
            log_retention_days: parse_or_warn("LOG_RETENTION_DAYS", defaults.log_retention_days),
            retention_sweep_seconds: parse_or_warn("RETENTION_SWEEP_SECONDS", defaults.retention_sweep_seconds)
                .max(1),
            max_output_bytes: parse_or_warn("MAX_OUTPUT_BYTES", defaults.max_output_bytes),
        }
    }

    /// Wraps this configuration in an [`Arc`] for sharing across handlers and workers.
    pub fn shared(self) -> Arc<Self> {
        Arc::new(self)
    }

    /// Resolves a hook's stored timeout into a concrete [`std::time::Duration`], substituting the
    /// fallback for a non-positive stored value (which would otherwise mean "kill immediately").
    pub fn timeout_for(&self, hook_timeout_seconds: i32) -> std::time::Duration {
        let secs = if hook_timeout_seconds > 0 {
            hook_timeout_seconds as u64
        } else {
            FALLBACK_TIMEOUT_SECONDS
        };
        std::time::Duration::from_secs(secs)
    }
}

/// Splits a comma-separated variable list, trimming blanks and dropping empty entries.
fn parse_env_var_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_owned())
        .collect()
}

/// Reads and parses an environment variable, warning and falling back on a malformed value.
fn parse_or_warn<T: std::str::FromStr + std::fmt::Display>(name: &str, default: T) -> T {
    match std::env::var(name) {
        Ok(raw) => match raw.trim().parse::<T>() {
            Ok(v) => v,
            Err(_) => {
                tracing::warn!("Invalid value for {name}: {raw:?} — falling back to {default}");
                default
            }
        },
        Err(_) => default,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_trims_env_var_lists() {
        assert_eq!(parse_env_var_list(" PATH , LANG ,, TERM "), vec!["PATH", "LANG", "TERM"]);
        assert!(parse_env_var_list("  ,, ").is_empty());
    }

    #[test]
    fn substitutes_fallback_for_non_positive_timeouts() {
        let cfg = RuntimeConfig::default();
        assert_eq!(cfg.timeout_for(5), std::time::Duration::from_secs(5));
        assert_eq!(cfg.timeout_for(0), std::time::Duration::from_secs(FALLBACK_TIMEOUT_SECONDS));
        assert_eq!(cfg.timeout_for(-1), std::time::Duration::from_secs(FALLBACK_TIMEOUT_SECONDS));
    }

    #[test]
    fn default_passthrough_matches_agent_md() {
        assert_eq!(
            RuntimeConfig::default().allowed_env_vars,
            vec!["PATH", "LANG", "TERM", "SYSTEMROOT"]
        );
    }
}
