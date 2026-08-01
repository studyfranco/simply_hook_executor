//! Runtime configuration, read once from the environment at startup.
//!
//! Every field has a safe default so the daemon runs with zero configuration; each is documented
//! with the environment variable that overrides it. Values are parsed leniently — a malformed
//! override logs a warning and falls back to the default rather than aborting startup, since a
//! typo in a unit file should never take the whole service down.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use ipnetwork::IpNetwork;

/// Default environment variables inherited by hook sub-processes, per `AGENT.MD`.
const DEFAULT_ALLOWED_ENV_VARS: &str = "PATH,LANG,TERM,SYSTEMROOT";
/// Default listen address: every interface.
const DEFAULT_BIND_HOST: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
/// Default listen port.
const DEFAULT_BIND_PORT: u16 = 3000;
/// Default retention window for `executions` rows, in days.
const DEFAULT_LOG_RETENTION_DAYS: i64 = 30;
/// Default interval between retention sweeps, in seconds (hourly).
const DEFAULT_RETENTION_SWEEP_SECONDS: u64 = 3600;
/// Default per-stream cap on captured output, in bytes (1 MiB).
const DEFAULT_MAX_OUTPUT_BYTES: usize = 1024 * 1024;
/// Fallback timeout applied when a hook stores a non-positive `default_timeout_seconds`.
const FALLBACK_TIMEOUT_SECONDS: u64 = 30;
/// Default anti-replay window for signed requests, in seconds (5 minutes each way).
const DEFAULT_SIGNATURE_MAX_AGE_SECONDS: i64 = 300;

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
    /// How far a request's `X-Timestamp` may be from the server's clock, in seconds, before the
    /// signature is rejected as a replay. Overridden by `SIGNATURE_MAX_AGE_SECONDS`.
    ///
    /// Applied symmetrically — a timestamp too far in the *future* is refused as well, since a
    /// forward-dated request would otherwise stay replayable for as long as the skew allows.
    pub signature_max_age_seconds: i64,
    /// Whether every authenticated request must carry a valid signature, from
    /// `REQUIRE_SIGNED_REQUESTS`.
    ///
    /// Defaults to `false` so a bearer-only client keeps working after an upgrade. Turning it on
    /// makes the HMAC protocol mandatory across the whole API — the intended end state once every
    /// client signs.
    pub require_signed_requests: bool,
    /// Directories a hook's `script_path` must live under, from `ALLOWED_SCRIPT_ROOTS`
    /// (comma-separated absolute paths).
    ///
    /// Empty (the default) means "any absolute, non-traversing path", which preserves
    /// zero-configuration behavior. Setting it is defense in depth: it confines a caller holding
    /// `can_manage_hooks` to a directory an operator has vetted, so a stolen management key cannot
    /// turn the daemon into a generic "run any binary as `hookrunner`" service.
    pub allowed_script_roots: Vec<PathBuf>,
    /// Peers whose `X-Forwarded-For` / `X-Real-IP` headers are believed, from `TRUSTED_PROXIES`
    /// (comma-separated CIDRs or bare IPs, e.g. `127.0.0.1,10.0.0.0/8`).
    ///
    /// **Empty is the secure default and means "believe no forwarding header".** A forwarding
    /// header is a claim made by whoever sent the request; it is evidence only when the sender is
    /// a proxy the operator controls. Honouring it unconditionally — as this daemon previously did
    /// — lets any client choose its own apparent source address, which defeats the `bound_ips`
    /// CIDR allowlist outright and forges `audit_logs.client_ip` at the same time.
    ///
    /// Set this to the address of the reverse proxy actually sitting in front of the daemon, and
    /// nothing else. A range wider than the real proxy fleet re-opens the bypass for every host
    /// inside it.
    pub trusted_proxies: Vec<IpNetwork>,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            allowed_env_vars: parse_env_var_list(DEFAULT_ALLOWED_ENV_VARS),
            log_retention_days: DEFAULT_LOG_RETENTION_DAYS,
            retention_sweep_seconds: DEFAULT_RETENTION_SWEEP_SECONDS,
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            signature_max_age_seconds: DEFAULT_SIGNATURE_MAX_AGE_SECONDS,
            require_signed_requests: false,
            allowed_script_roots: Vec::new(),
            trusted_proxies: Vec::new(),
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

        let allowed_script_roots = parse_script_roots(
            std::env::var("ALLOWED_SCRIPT_ROOTS").ok().as_deref().unwrap_or(""),
        );
        if allowed_script_roots.is_empty() {
            tracing::info!(
                "ALLOWED_SCRIPT_ROOTS is unset: hooks may point at any absolute path. Set it to a \
                 comma-separated list of directories (e.g. /opt/hooks,/usr/local/bin) to confine \
                 script_path to vetted locations."
            );
        } else {
            tracing::info!(
                "Hook scripts are confined to: {}",
                allowed_script_roots.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", ")
            );
        }

        let trusted_proxies =
            parse_trusted_proxies(std::env::var("TRUSTED_PROXIES").ok().as_deref().unwrap_or(""));
        if trusted_proxies.is_empty() {
            tracing::info!(
                "TRUSTED_PROXIES is unset: X-Forwarded-For and X-Real-IP are ignored and bound_ips \
                 is evaluated against the direct TCP peer. If this daemon sits behind a reverse \
                 proxy, set it to that proxy's address or every key will appear to connect from it."
            );
        } else {
            tracing::info!(
                "Forwarding headers are honoured only from: {}",
                trusted_proxies.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(", ")
            );
        }

        Self {
            allowed_env_vars,
            trusted_proxies,
            log_retention_days: parse_or_warn("LOG_RETENTION_DAYS", defaults.log_retention_days),
            retention_sweep_seconds: parse_or_warn("RETENTION_SWEEP_SECONDS", defaults.retention_sweep_seconds)
                .max(1),
            max_output_bytes: parse_or_warn("MAX_OUTPUT_BYTES", defaults.max_output_bytes),
            // Clamped to at least 1s: a zero or negative window would reject every request,
            // including correctly-signed ones, which is a configuration foot-gun rather than a
            // security posture anyone intends.
            signature_max_age_seconds: parse_or_warn(
                "SIGNATURE_MAX_AGE_SECONDS",
                defaults.signature_max_age_seconds,
            )
            .max(1),
            require_signed_requests: parse_bool_or_warn(
                "REQUIRE_SIGNED_REQUESTS",
                defaults.require_signed_requests,
            ),
            allowed_script_roots,
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

/// Resolves the socket address the HTTP server binds to, from `BIND_HOST`/`HOST` and `PORT`.
///
/// Reads the environment and delegates to [`parse_bind_addr`], which holds the actual logic so it
/// can be unit-tested without mutating process-global state.
pub fn resolve_bind_addr() -> SocketAddr {
    // `BIND_HOST` wins over `HOST` because `HOST` is a widely-used variable that some environments
    // set to something entirely unrelated (a hostname, a build target triple); an operator who
    // sets the explicit name should not have it silently overridden by ambient configuration.
    let host = std::env::var("BIND_HOST").or_else(|_| std::env::var("HOST")).ok();
    let port = std::env::var("PORT").ok();
    parse_bind_addr(host.as_deref(), port.as_deref())
}

/// Builds a listen address from optional raw `host`/`port` strings.
///
/// Both are parsed leniently: an unparseable value logs a warning and falls back to the default
/// rather than aborting startup, matching how the rest of this module treats malformed overrides.
/// A host must be a literal IP address — resolving a hostname could yield several addresses with
/// no principled way to pick one, and binding the wrong interface is a security problem, not a
/// convenience one.
///
/// Port `0` is passed through deliberately: the OS then assigns an ephemeral free port, which is
/// exactly what a test harness or a socket-activated deployment wants.
pub fn parse_bind_addr(host: Option<&str>, port: Option<&str>) -> SocketAddr {
    let ip = match host.map(str::trim).filter(|h| !h.is_empty()) {
        Some(raw) => match raw.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => {
                tracing::warn!(
                    "Invalid bind host {raw:?} (expected a literal IP address such as 0.0.0.0, \
                     127.0.0.1, or ::) — falling back to {DEFAULT_BIND_HOST}"
                );
                DEFAULT_BIND_HOST
            }
        },
        None => DEFAULT_BIND_HOST,
    };

    let port = match port.map(str::trim).filter(|p| !p.is_empty()) {
        Some(raw) => match raw.parse::<u16>() {
            Ok(port) => port,
            Err(_) => {
                tracing::warn!(
                    "Invalid PORT {raw:?} — falling back to {DEFAULT_BIND_PORT}"
                );
                DEFAULT_BIND_PORT
            }
        },
        None => DEFAULT_BIND_PORT,
    };

    SocketAddr::new(ip, port)
}

/// Parses `ALLOWED_SCRIPT_ROOTS` into a list of confinement directories.
///
/// Relative entries are discarded with a warning rather than resolved against the daemon's
/// working directory: a containment boundary that moves with the cwd is not a boundary.
fn parse_script_roots(raw: &str) -> Vec<PathBuf> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|entry| {
            let path = PathBuf::from(entry);
            if path.is_absolute() {
                Some(path)
            } else {
                tracing::warn!("Ignoring relative ALLOWED_SCRIPT_ROOTS entry {entry:?}: roots must be absolute");
                None
            }
        })
        .collect()
}

/// Parses `TRUSTED_PROXIES` into the set of peers whose forwarding headers are believed.
///
/// Accepts both CIDR notation (`10.0.0.0/8`) and bare addresses (`127.0.0.1`, `::1`), because an
/// operator naming a single proxy should not have to remember to append `/32`. A bare address is
/// widened to a host route — `/32` for IPv4, `/128` for IPv6 — which matches exactly that one host.
///
/// A malformed entry is dropped with a warning rather than aborting startup, matching how the rest
/// of this module treats bad overrides. The failure mode is deliberately the safe one: a dropped
/// entry means a proxy is *not* trusted, so requests through it are evaluated against its own
/// address instead of silently accepting a header it forwarded.
fn parse_trusted_proxies(raw: &str) -> Vec<IpNetwork> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|entry| match entry.parse::<IpNetwork>() {
            Ok(network) => Some(network),
            // `IpNetwork`'s parser is the authority on CIDR text; this fallback only covers the
            // bare-address spelling, and does so by construction rather than by string surgery.
            Err(_) => match entry.parse::<IpAddr>() {
                Ok(addr) => Some(IpNetwork::from(addr)),
                Err(_) => {
                    tracing::warn!(
                        "Ignoring invalid TRUSTED_PROXIES entry {entry:?}: expected an IP address \
                         or CIDR range. Forwarding headers from that peer will NOT be trusted."
                    );
                    None
                }
            },
        })
        .collect()
}

/// Splits a comma-separated variable list, trimming blanks and dropping empty entries.
fn parse_env_var_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_owned())
        .collect()
}

/// Reads a boolean environment variable, accepting the usual spellings.
fn parse_bool_or_warn(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(raw) => match raw.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" => false,
            other => {
                tracing::warn!("Invalid boolean for {name}: {other:?} — falling back to {default}");
                default
            }
        },
        Err(_) => default,
    }
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

    #[test]
    fn parses_script_roots_and_drops_relative_entries() {
        assert_eq!(
            parse_script_roots("/opt/hooks, /usr/local/bin ,,"),
            vec![PathBuf::from("/opt/hooks"), PathBuf::from("/usr/local/bin")]
        );
        // A relative root would move with the daemon's working directory, so it is not a boundary.
        assert_eq!(parse_script_roots("hooks,../escape"), Vec::<PathBuf>::new());
        assert!(parse_script_roots("").is_empty());
    }

    #[test]
    fn parses_trusted_proxies_in_both_spellings() {
        // A bare address is widened to a host route, so an operator naming one proxy need not
        // remember the /32.
        let parsed = parse_trusted_proxies("127.0.0.1, 10.0.0.0/8 , ::1,2001:db8::/32");
        assert_eq!(parsed.len(), 4);
        assert!(parsed[0].contains("127.0.0.1".parse::<IpAddr>().expect("valid")));
        assert!(!parsed[0].contains("127.0.0.2".parse::<IpAddr>().expect("valid")));
        assert!(parsed[1].contains("10.1.2.3".parse::<IpAddr>().expect("valid")));
        assert!(parsed[2].contains("::1".parse::<IpAddr>().expect("valid")));
        assert!(parsed[3].contains("2001:db8::5".parse::<IpAddr>().expect("valid")));
    }

    #[test]
    fn trusted_proxies_defaults_to_empty_and_drops_malformed_entries() {
        // Empty is the secure default: no peer is trusted, so no forwarding header is believed.
        assert!(parse_trusted_proxies("").is_empty());
        assert!(parse_trusted_proxies("  ,, ").is_empty());
        assert!(RuntimeConfig::default().trusted_proxies.is_empty());

        // A malformed entry is dropped rather than aborting startup — and dropping it means "not
        // trusted", which is the safe direction to fail in.
        let parsed = parse_trusted_proxies("not-an-ip, 10.0.0.0/8, 999.1.1.1, 10.0.0.0/99");
        assert_eq!(parsed.len(), 1);
        assert!(parsed[0].contains("10.9.9.9".parse::<IpAddr>().expect("valid")));
    }

    #[test]
    fn bind_addr_defaults_to_all_interfaces_on_3000() {
        assert_eq!(parse_bind_addr(None, None).to_string(), "0.0.0.0:3000");
        // Empty strings are treated as "unset", so an unset variable in a unit file or compose
        // file behaves the same as an absent one.
        assert_eq!(parse_bind_addr(Some(""), Some("  ")).to_string(), "0.0.0.0:3000");
    }

    #[test]
    fn bind_addr_honors_host_and_port_overrides() {
        assert_eq!(parse_bind_addr(Some("127.0.0.1"), Some("8080")).to_string(), "127.0.0.1:8080");
        assert_eq!(parse_bind_addr(Some(" 127.0.0.1 "), Some(" 8080 ")).to_string(), "127.0.0.1:8080");
        // Port 0 is passed through so the OS can assign an ephemeral port.
        assert_eq!(parse_bind_addr(Some("127.0.0.1"), Some("0")).to_string(), "127.0.0.1:0");
    }

    #[test]
    fn bind_addr_supports_ipv6_literals() {
        let addr = parse_bind_addr(Some("::1"), Some("9000"));
        assert!(addr.is_ipv6());
        assert_eq!(addr.port(), 9000);
        assert_eq!(parse_bind_addr(Some("::"), None).ip(), "::".parse::<IpAddr>().expect("valid"));
    }

    #[test]
    fn bind_addr_falls_back_on_malformed_values() {
        // A hostname is not a literal IP and is rejected rather than resolved.
        assert_eq!(parse_bind_addr(Some("localhost"), Some("8080")).to_string(), "0.0.0.0:8080");
        assert_eq!(parse_bind_addr(Some("127.0.0.1"), Some("not-a-port")).to_string(), "127.0.0.1:3000");
        // Out of u16 range.
        assert_eq!(parse_bind_addr(Some("127.0.0.1"), Some("70000")).to_string(), "127.0.0.1:3000");
        assert_eq!(parse_bind_addr(Some("999.1.1.1"), Some("-1")).to_string(), "0.0.0.0:3000");
    }
}
