//! Runtime configuration, read once from the environment at startup.
//!
//! Every field has a safe default so the daemon runs with zero configuration; each is documented
//! with the environment variable that overrides it. Values are parsed leniently — a malformed
//! override logs a warning and falls back to the default rather than aborting startup, since a
//! typo in a unit file should never take the whole service down.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ipnetwork::IpNetwork;

/// How long a *successfully* resolved `TRUSTED_PROXIES` hostname is reused before being looked up
/// again.
///
/// Container addresses change on restart, so a name resolved once at startup and cached forever
/// would keep trusting an address the orchestrator has since handed to something else — a stale
/// entry here is a trusted-proxy grant pointing at an arbitrary container. Thirty seconds bounds
/// that window while keeping DNS out of the per-request path in the steady state.
const TRUSTED_PROXY_DNS_TTL: Duration = Duration::from_secs(30);

/// How long a *failed* lookup is remembered before the name is tried again.
///
/// This is the anti-storm control, and it is the reason failures are cached at all. Without a
/// negative cache, a single unresolvable entry turns every inbound request into a fresh DNS query:
/// the daemon's own request rate becomes its query rate against the resolver, which is a
/// self-inflicted amplification path that gets worse exactly when DNS is already unhealthy. Caching
/// the failure bounds it to one lookup per name per window no matter how much traffic arrives.
///
/// Deliberately much shorter than [`TRUSTED_PROXY_DNS_TTL`]. The two windows are asymmetric because
/// their costs are: over-trusting a stale address is a security problem, so success expires slowly
/// enough to be cheap but fast enough to track a moved container, while an unresolvable name is
/// merely *untrusted* — the safe direction — so it can be retried aggressively to shorten the
/// outage without ever widening trust.
const TRUSTED_PROXY_DNS_NEGATIVE_TTL: Duration = Duration::from_secs(5);

/// How long the daemon waits after a failed boot-time resolution before its one loud re-check.
///
/// A hostname that does not resolve at startup is almost always a service that has simply not
/// finished starting yet — the reverse proxy and this daemon come up together under Compose or
/// Kubernetes, in no guaranteed order. Aborting on that would turn an ordinary startup race into a
/// crash loop, and a crash loop is *worse* than serving: the entry is already fail-closed (an
/// unresolvable name is trusted by nobody), so the daemon that keeps running is strictly more
/// available than the one that keeps dying, and no less safe.
pub const TRUSTED_PROXY_BOOT_GRACE: Duration = Duration::from_secs(60);

/// One entry of `TRUSTED_PROXIES`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxySpec {
    /// A literal address or CIDR range. Matched arithmetically, with no name lookup.
    Network(IpNetwork),
    /// A DNS name (`traefik`, `proxy.internal`), resolved at match time.
    ///
    /// Exists for container platforms where the proxy's address is assigned by the orchestrator and
    /// changes on every restart, so it cannot be written into configuration ahead of time.
    Hostname(String),
}

impl std::fmt::Display for ProxySpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Network(network) => write!(f, "{network}"),
            Self::Hostname(name) => write!(f, "{name}"),
        }
    }
}

/// One hostname's most recent lookup outcome.
struct HostnameEntry {
    /// The host routes the name resolved to. Empty when the lookup failed, which is what makes a
    /// failed entry contribute nothing to the trusted set rather than falling back to something.
    networks: Vec<IpNetwork>,
    /// Whether the lookup itself succeeded.
    ///
    /// Tracked separately from `networks.is_empty()` because the two carry different TTLs, and a
    /// name that resolves to an empty answer is a failure for our purposes: it should be retried on
    /// the short negative window, not held for the full positive one.
    resolved: bool,
    /// When the lookup ran.
    at: Instant,
}

impl HostnameEntry {
    /// Whether this entry may still be served without re-querying DNS.
    fn is_fresh(&self, positive: Duration, negative: Duration) -> bool {
        let ttl = if self.resolved { positive } else { negative };
        self.at.elapsed() < ttl
    }
}

/// The per-hostname resolution cache, plus the flattened view the request path actually reads.
#[derive(Default)]
struct ResolvedProxies {
    /// Cache keyed by hostname, so each name expires on its own clock. One unresolvable entry
    /// therefore costs one lookup per negative window — it does not drag the healthy names into
    /// being re-resolved alongside it.
    hosts: HashMap<String, HostnameEntry>,
    /// Static networks merged with every cached hostname's addresses, precomputed so the hot path
    /// is an `Arc` clone rather than a walk over the map.
    merged: Arc<Vec<IpNetwork>>,
}

/// The set of peers whose forwarding headers are believed.
///
/// Holds the parsed `TRUSTED_PROXIES` specification plus a short-lived cache of resolved hostnames.
/// Cloning shares the cache, so every handler sees the same resolution rather than each maintaining
/// its own.
pub struct TrustedProxies {
    /// The configuration exactly as written, for logging and the settings endpoint.
    spec: Vec<ProxySpec>,
    /// Literal entries, precomputed. Also the complete answer when no hostnames are configured,
    /// which is the common case and costs nothing but an `Arc` clone to serve.
    networks: Arc<Vec<IpNetwork>>,
    /// Hostname entries awaiting resolution.
    hostnames: Vec<String>,
    /// Reuse window for a successful resolution.
    ttl: Duration,
    /// Reuse window for a failed one. See [`TRUSTED_PROXY_DNS_NEGATIVE_TTL`].
    negative_ttl: Duration,
    cache: Arc<tokio::sync::RwLock<ResolvedProxies>>,
}

impl Clone for TrustedProxies {
    fn clone(&self) -> Self {
        Self {
            spec: self.spec.clone(),
            networks: Arc::clone(&self.networks),
            hostnames: self.hostnames.clone(),
            ttl: self.ttl,
            negative_ttl: self.negative_ttl,
            cache: Arc::clone(&self.cache),
        }
    }
}

impl std::fmt::Debug for TrustedProxies {
    /// Renders the specification, not the cache: a `{:?}` of application state should say what the
    /// operator configured, not which addresses a name happened to resolve to a moment ago.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("TrustedProxies").field(&self.spec).finish()
    }
}

impl PartialEq for TrustedProxies {
    /// Compares the specification only. Two sets configured identically are equal even if their
    /// caches were refreshed at different moments.
    fn eq(&self, other: &Self) -> bool {
        self.spec == other.spec
    }
}

impl Eq for TrustedProxies {}

impl Default for TrustedProxies {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

impl TrustedProxies {
    /// Builds the set from a parsed specification.
    pub fn new(spec: Vec<ProxySpec>) -> Self {
        let networks: Vec<IpNetwork> = spec
            .iter()
            .filter_map(|entry| match entry {
                ProxySpec::Network(network) => Some(*network),
                ProxySpec::Hostname(_) => None,
            })
            .collect();
        let hostnames = spec
            .iter()
            .filter_map(|entry| match entry {
                ProxySpec::Hostname(name) => Some(name.clone()),
                ProxySpec::Network(_) => None,
            })
            .collect();

        let networks = Arc::new(networks);
        Self {
            spec,
            // The flattened view starts as the static entries alone. Until a hostname resolves it
            // contributes nothing, which is the fail-closed default the boot grace period relies
            // on: the daemon serves immediately, with unresolved names simply not trusted yet.
            cache: Arc::new(tokio::sync::RwLock::new(ResolvedProxies {
                hosts: HashMap::new(),
                merged: Arc::clone(&networks),
            })),
            networks,
            hostnames,
            ttl: TRUSTED_PROXY_DNS_TTL,
            negative_ttl: TRUSTED_PROXY_DNS_NEGATIVE_TTL,
        }
    }

    /// Parses a raw `TRUSTED_PROXIES` value.
    ///
    /// Fallible on purpose: a syntactically invalid entry is a misconfigured trust boundary, and
    /// [`parse_trusted_proxies`] explains why that is refused rather than dropped. An entry that is
    /// merely unresolvable still parses here — that failure belongs to DNS and is handled at
    /// resolution time.
    pub fn from_raw(raw: &str) -> Result<Self, TrustedProxyError> {
        Ok(Self::new(parse_trusted_proxies(raw)?))
    }

    /// Whether nothing at all is trusted — the secure default.
    pub fn is_empty(&self) -> bool {
        self.spec.is_empty()
    }

    /// The specification as configured, for display.
    pub fn spec(&self) -> &[ProxySpec] {
        &self.spec
    }

    /// Overrides the successful-resolution reuse window. Test-facing: a suite cannot wait 30
    /// seconds to observe that a re-resolution happened.
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Overrides the failed-resolution reuse window. Test-facing, for the same reason as
    /// [`TrustedProxies::with_ttl`] — and additionally so a test can assert that a failure is
    /// cached *at all*, by observing that a second call inside the window issues no lookup.
    pub fn with_negative_ttl(mut self, negative_ttl: Duration) -> Self {
        self.negative_ttl = negative_ttl;
        self
    }

    /// Whether every configured hostname currently has a usable cache entry.
    fn all_fresh(&self, cache: &ResolvedProxies) -> bool {
        self.hostnames.iter().all(|hostname| {
            cache
                .hosts
                .get(hostname)
                .is_some_and(|entry| entry.is_fresh(self.ttl, self.negative_ttl))
        })
    }

    /// Re-resolves the stale hostnames in place and rebuilds the flattened view.
    ///
    /// Returns the names that failed, which is what [`TrustedProxies::prime`] reports to the
    /// operator at startup.
    ///
    /// `force` bypasses the TTL check entirely. It exists for the boot re-check: after the grace
    /// period the answer to "is this name resolvable *now*" must come from DNS, not from whatever
    /// the cache happens to be holding.
    async fn refresh_stale(&self, cache: &mut ResolvedProxies, force: bool) -> Vec<String> {
        let mut failed = Vec::new();
        let mut changed = false;

        for hostname in &self.hostnames {
            let fresh = !force
                && cache
                    .hosts
                    .get(hostname)
                    .is_some_and(|entry| entry.is_fresh(self.ttl, self.negative_ttl));
            if fresh {
                // A cached failure counts as a current failure for reporting purposes: the name is
                // untrusted right now either way, and re-querying it here would defeat the negative
                // cache this whole path exists to honour.
                if cache.hosts.get(hostname).is_some_and(|entry| !entry.resolved) {
                    failed.push(hostname.clone());
                }
                continue;
            }

            let (networks, resolved) = resolve_hostname(hostname).await;
            if !resolved {
                failed.push(hostname.clone());
            }
            cache.hosts.insert(
                hostname.clone(),
                HostnameEntry { networks, resolved, at: Instant::now() },
            );
            changed = true;
        }

        if changed {
            let mut merged = (*self.networks).clone();
            for entry in cache.hosts.values() {
                merged.extend(entry.networks.iter().copied());
            }
            cache.merged = Arc::new(merged);
        }

        failed
    }

    /// The networks to match a request against right now, resolving hostnames whose cache entry is
    /// cold or expired.
    ///
    /// Returns an [`Arc`] rather than a fresh `Vec` so the steady-state cost is a refcount bump. The
    /// no-hostname case — every deployment that names its proxies by address — never touches the
    /// lock or the resolver at all.
    ///
    /// The write lock is held across the lookups on purpose. It is what collapses a burst of
    /// requests arriving on an expired entry into a *single* query: the rest queue, then find the
    /// entry fresh and return immediately. Combined with the negative TTL, that bounds DNS traffic
    /// to one query per name per window regardless of how much load the daemon is under.
    pub async fn resolved(&self) -> Arc<Vec<IpNetwork>> {
        if self.hostnames.is_empty() {
            return Arc::clone(&self.networks);
        }

        {
            let cache = self.cache.read().await;
            if self.all_fresh(&cache) {
                return Arc::clone(&cache.merged);
            }
        }

        let mut cache = self.cache.write().await;
        // Re-check under the write lock: several requests can queue behind one expiry, and only the
        // first should pay for the lookup.
        if self.all_fresh(&cache) {
            return Arc::clone(&cache.merged);
        }

        self.refresh_stale(&mut cache, false).await;
        Arc::clone(&cache.merged)
    }

    /// Resolves every configured hostname unconditionally, returning those that failed.
    ///
    /// Called once at startup so a misspelled or not-yet-running proxy is reported while an
    /// operator is still watching the log, rather than surfacing later as inexplicable `403`s — and
    /// called again after [`TRUSTED_PROXY_BOOT_GRACE`] to give a service that was merely slow to
    /// start a second chance. It never fails: an unresolvable name is a name nobody is trusted
    /// under, which is a safe state to serve traffic in.
    pub async fn prime(&self) -> Vec<String> {
        if self.hostnames.is_empty() {
            return Vec::new();
        }
        let mut cache = self.cache.write().await;
        self.refresh_stale(&mut cache, true).await
    }
}

/// Resolves one hostname to the host routes it currently names.
///
/// Returns the addresses and whether the lookup *succeeded*. The caller needs both: an empty answer
/// and a failed answer are equally untrusted right now, but they are cached on different clocks —
/// see [`HostnameEntry::is_fresh`].
///
/// A failure yields nothing rather than propagating: an unresolvable name means "this proxy is not
/// currently trusted", which is the safe direction to fail in. A DNS outage must never be able to
/// *widen* what the daemon believes, and a container that is down should stop being trusted rather
/// than keep a stale grant alive.
async fn resolve_hostname(hostname: &str) -> (Vec<IpNetwork>, bool) {
    // Port 0: `lookup_host` wants a socket address, but only the address half is used.
    match tokio::net::lookup_host((hostname, 0u16)).await {
        Ok(addrs) => {
            let networks: Vec<IpNetwork> =
                addrs.map(|addr| IpNetwork::from(normalize_ip(addr.ip()))).collect();
            if networks.is_empty() {
                tracing::warn!(
                    "TRUSTED_PROXIES hostname {hostname:?} resolved to no addresses; it is not \
                     trusted until it does."
                );
                return (networks, false);
            }
            tracing::debug!(
                "TRUSTED_PROXIES hostname {hostname:?} resolved to {}",
                networks.iter().map(|n| n.ip().to_string()).collect::<Vec<_>>().join(", ")
            );
            (networks, true)
        }
        Err(e) => {
            tracing::warn!(
                "Could not resolve TRUSTED_PROXIES hostname {hostname:?}: {e}. It is not trusted \
                 until resolution succeeds."
            );
            (Vec::new(), false)
        }
    }
}

/// Normalizes an IPv4-mapped IPv6 address (`::ffff:192.168.1.1`) down to its plain IPv4 form.
///
/// Dual-stack listeners and reverse proxies routinely surface IPv4 clients this way. Without this,
/// such a peer would fail to match an IPv4 CIDR in either `bound_ips` or `TRUSTED_PROXIES` — the
/// first causing a spurious `403`, the second silently downgrading a trusted proxy to an untrusted
/// one.
pub fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

/// Reports whether `ip` falls inside any of the `trusted` networks.
fn is_trusted(ip: IpAddr, trusted: &[IpNetwork]) -> bool {
    trusted.iter().any(|net| net.contains(ip))
}

/// Determines the client address to authorize `bound_ips` against, and to record in the audit trail.
///
/// **The forwarding headers are only consulted when `peer` — the immediate TCP peer, which cannot
/// be forged — is itself inside `trusted`.** Any other client gets its TCP address used verbatim, no
/// matter what it claims in `X-Forwarded-For`. That check is the whole control: `X-Forwarded-For` is
/// an ordinary request header, so honouring it from an arbitrary peer turns `bound_ips` from a
/// network restriction into a self-asserted one that any caller satisfies by typing an allowed
/// address into a header.
///
/// When the peer *is* trusted, the header is walked **right to left, skipping addresses that are
/// themselves trusted proxies**, and the first remaining address is the client. Rightmost-first is
/// what makes the suffix unforgeable: each proxy appends the address it actually saw, so entries to
/// the left of the last trusted hop are hearsay the client supplied. Skipping trusted entries is
/// what makes a *chain* work — with `client → P1 → P2 → us` the header reads `client, P1` and the
/// rightmost entry is `P1`, a proxy rather than the client.
///
/// `X-Real-IP` (single-valued, no chain) is consulted only when `X-Forwarded-For` is absent or
/// yields nothing, under exactly the same trust precondition.
///
/// Falls back to `peer` whenever the headers are absent, unparseable, or contain nothing but trusted
/// proxies — never to an unvalidated claim.
pub fn resolve_client_ip(
    peer: IpAddr,
    headers: &axum::http::HeaderMap,
    trusted: &[IpNetwork],
) -> IpAddr {
    let peer = normalize_ip(peer);

    // The load-bearing check. Everything below is unreachable for an untrusted caller.
    if !is_trusted(peer, trusted) {
        return peer;
    }

    if let Some(forwarded) = headers.get("X-Forwarded-For").and_then(|h| h.to_str().ok()) {
        let client = forwarded
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.parse::<IpAddr>().ok())
            .map(normalize_ip)
            .rev()
            .find(|ip| !is_trusted(*ip, trusted));

        if let Some(client) = client {
            return client;
        }
        // A header listing only trusted proxies (or nothing parseable) says nothing about the
        // client; fall through rather than inventing one.
    }

    if let Some(real_ip) = headers
        .get("X-Real-IP")
        .and_then(|h| h.to_str().ok())
        .map(str::trim)
        .and_then(|s| s.parse::<IpAddr>().ok())
    {
        return normalize_ip(real_ip);
    }

    peer
}

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
    /// Days a soft-deleted hook stays recoverable before the sweep drops it for good. Overridden by
    /// `DELETED_HOOK_RETENTION_DAYS`; `0` keeps the trash forever.
    ///
    /// Governed **separately** from [`RuntimeConfig::log_retention_days`] rather than sharing a
    /// window with it. The two answer different questions — "how much history do we keep?" versus
    /// "how long is a mistake reversible?" — and an operator shortening log retention to reclaim
    /// disk must not silently shrink the undo window for deleted automation as a side effect.
    pub deleted_hook_retention_days: i64,
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
    ///
    /// Entries may be addresses, CIDR ranges, or hostnames; see [`TrustedProxies`].
    pub trusted_proxies: TrustedProxies,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            allowed_env_vars: parse_env_var_list(DEFAULT_ALLOWED_ENV_VARS),
            log_retention_days: DEFAULT_LOG_RETENTION_DAYS,
            deleted_hook_retention_days: crate::retention::DEFAULT_DELETED_HOOK_RETENTION_DAYS,
            retention_sweep_seconds: DEFAULT_RETENTION_SWEEP_SECONDS,
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            signature_max_age_seconds: DEFAULT_SIGNATURE_MAX_AGE_SECONDS,
            require_signed_requests: false,
            allowed_script_roots: Vec::new(),
            trusted_proxies: TrustedProxies::default(),
        }
    }
}

impl RuntimeConfig {
    /// Builds the configuration from the process environment, falling back to defaults.
    ///
    /// Fails on exactly one class of input: a `TRUSTED_PROXIES` entry that is not syntactically an
    /// address, a CIDR range, or a hostname. Every other malformed override warns and falls back,
    /// because every other override *has* a safe substitute. See [`parse_trusted_proxies`].
    pub fn from_env() -> Result<Self, TrustedProxyError> {
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

        // The `?` is the abort. A typo here is not something to serve through: see
        // [`parse_trusted_proxies`] for why this one override is fatal where the rest are lenient.
        let trusted_proxies = TrustedProxies::from_raw(
            std::env::var("TRUSTED_PROXIES").ok().as_deref().unwrap_or(""),
        )?;
        if trusted_proxies.is_empty() {
            tracing::info!(
                "TRUSTED_PROXIES is unset: X-Forwarded-For and X-Real-IP are ignored and bound_ips \
                 is evaluated against the direct TCP peer. If this daemon sits behind a reverse \
                 proxy, set it to that proxy's address or every key will appear to connect from it."
            );
        } else {
            tracing::info!(
                "Forwarding headers are honoured only from: {}",
                trusted_proxies.spec().iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
            );
        }

        Ok(Self {
            allowed_env_vars,
            trusted_proxies,
            log_retention_days: parse_or_warn("LOG_RETENTION_DAYS", defaults.log_retention_days),
            // Clamped at zero rather than accepted verbatim: a negative window would read as
            // "purge everything trashed since the future", and the purge is the one query in the
            // system that destroys audit history. `0` already means "keep forever".
            deleted_hook_retention_days: parse_or_warn(
                "DELETED_HOOK_RETENTION_DAYS",
                defaults.deleted_hook_retention_days,
            )
            .max(0),
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
        })
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

/// Required width of `INITIAL_MASTER_KEY`, in hex characters.
///
/// Not an arbitrary number: [`crate::api::generate_random_key`] mints 32 random bytes and hex-encodes
/// them, so 64 hex characters is exactly the shape this service issues for every key it generates. A
/// bootstrap override that did not match that shape would be a credential of a different class
/// wearing the same name.
pub const INITIAL_MASTER_KEY_HEX_LEN: usize = 64;

/// Why an `INITIAL_MASTER_KEY` was refused.
///
/// Each variant renders an operator-facing message naming the actual defect. A single "invalid key"
/// error would be cheaper and worse: the three failures have three different fixes, and the operator
/// cannot see the value in the log to work out which one they hit.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum InitialMasterKeyError {
    /// The variable was set to an empty or whitespace-only value.
    #[error(
        "INITIAL_MASTER_KEY is set but empty. Either unset it entirely — the daemon then generates \
         a random master key and prints it once at startup — or set it to {INITIAL_MASTER_KEY_HEX_LEN} \
         hex characters (`openssl rand -hex 32`)."
    )]
    Empty,
    /// The value was the wrong width.
    #[error(
        "INITIAL_MASTER_KEY must be exactly {INITIAL_MASTER_KEY_HEX_LEN} hex characters (32 bytes); \
         got {0}. Generate one with `openssl rand -hex 32`."
    )]
    BadLength(usize),
    /// The value contained a character outside `[0-9a-fA-F]`.
    #[error(
        "INITIAL_MASTER_KEY must contain only hexadecimal characters (0-9, a-f, A-F); found {0:?} at \
         position {1}. Generate one with `openssl rand -hex 32`."
    )]
    NonHex(char, usize),
}

/// Validates the `INITIAL_MASTER_KEY` bootstrap override.
///
/// # What each input means
///
/// | Input | Result | Why |
/// | :--- | :--- | :--- |
/// | Unset (`None`) | `Ok(None)` | The documented zero-config path: the daemon mints a random master key and prints it once |
/// | Set, 64 hex chars | `Ok(Some(key))` | Accepted verbatim (after trimming surrounding whitespace) |
/// | Set, empty/whitespace | `Err(Empty)` | **Fatal.** Setting the variable is a statement of intent; setting it to nothing is a mistake, most often an unexpanded shell variable |
/// | Set, wrong width | `Err(BadLength)` | **Fatal** |
/// | Set, non-hex | `Err(NonHex)` | **Fatal** |
///
/// # Why an unset variable is *not* an error
///
/// Making absence fatal would mean this daemon cannot start without an operator-supplied master key,
/// which contradicts the bootstrap design in `src/main.rs`: `INITIAL_MASTER_KEY` exists for
/// deterministic test and CI bootstrap and is explicitly **not** a normal deployment option, because
/// a human-chosen secret defeats the point of a random 256-bit key. The zero-config path — generate,
/// print once, warn — is the documented default in `README.md`. Absence is therefore the *expected*
/// production state, and the strictness here applies to a value that was actually supplied.
///
/// An **empty** value is treated as a defect rather than as absence, and that distinction is the
/// point of having both cases: `INITIAL_MASTER_KEY=""` and `INITIAL_MASTER_KEY=$UNSET_VAR` are what a
/// broken deployment script produces, and silently generating a random key there would hand the
/// operator a daemon whose master credential is not the one their tooling believes it configured.
///
/// # Why the value is trimmed
///
/// `INITIAL_MASTER_KEY=$(cat key.txt)` and `... $(echo -n ... )` differ by a trailing newline, and
/// that footgun costs an hour to diagnose because the log cannot show it. Trimming cannot change the
/// meaning of a hex string, so it is safe here in a way it would not be for an arbitrary secret. The
/// trimmed value is what is returned and what becomes the key.
pub fn validate_initial_master_key(
    raw: Option<&str>,
) -> Result<Option<String>, InitialMasterKeyError> {
    let Some(raw) = raw else {
        return Ok(None);
    };

    let candidate = raw.trim();
    if candidate.is_empty() {
        return Err(InitialMasterKeyError::Empty);
    }

    // Character class before width: a 12-character value full of `z` should be told it is not hex,
    // which is the more useful of the two complaints, rather than being told only that it is short.
    if let Some((index, found)) = candidate
        .char_indices()
        .find(|(_, c)| !c.is_ascii_hexdigit())
    {
        return Err(InitialMasterKeyError::NonHex(found, index));
    }

    // `chars().count()` rather than `len()`: the two agree only for ASCII, and reporting a byte
    // count for a value that reached here as non-ASCII would be a misleading diagnostic. The hex
    // check above already guarantees ASCII, so this is defence against a future reordering.
    let width = candidate.chars().count();
    if width != INITIAL_MASTER_KEY_HEX_LEN {
        return Err(InitialMasterKeyError::BadLength(width));
    }

    Ok(Some(candidate.to_owned()))
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

/// Why a `TRUSTED_PROXIES` entry is not any of the three accepted spellings.
///
/// Returned rather than logged so the caller can abort startup with it. See
/// [`parse_trusted_proxies`] for why a syntax error is fatal while an unresolvable name is not.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "FATAL: TRUSTED_PROXIES entry '{entry}' is not a valid IP address, CIDR range, or hostname \
     ({reason}). Refusing to start with an ambiguous trust boundary."
)]
pub struct TrustedProxyError {
    /// The offending entry, exactly as it was written in the environment.
    pub entry: String,
    /// A specific diagnosis, so the operator does not have to guess which of the three spellings
    /// was nearly matched.
    pub reason: String,
}

/// Diagnoses why `candidate` is not shaped like a DNS name, or `None` if it is.
///
/// Deliberately strict. An entry reaching this point already failed to parse as an address or a
/// CIDR, and the two ways that happens are a typo and a hostname. Accepting anything at all as a
/// name would turn `10.0.0.0/8x` into a lookup that quietly never matches, so a would-be CIDR is
/// better reported as the mistake it is: entries containing `/` or `:` are refused outright, since
/// those characters only appear in prefix and IPv6 syntax.
///
/// The reason is returned rather than discarded because it is what makes the startup abort
/// actionable: `10.0.0.0/8x` and `bad!char` are both rejected, but for entirely different reasons,
/// and an operator reading the log at 3am should not have to work out which.
fn hostname_rejection(candidate: &str) -> Option<&'static str> {
    if candidate.is_empty() {
        return Some("it is empty");
    }
    if candidate.len() > 253 {
        return Some("it exceeds the 253-character DNS name limit");
    }
    if candidate.contains('/') {
        return Some(
            "it contains '/', so it was read as a CIDR range, but the address or prefix length is \
             not valid",
        );
    }
    if candidate.contains(':') {
        return Some(
            "it contains ':', so it was read as an IPv6 address, but it is not a valid one",
        );
    }
    // A leading or trailing separator is malformed rather than merely unusual.
    let bytes = candidate.as_bytes();
    let edges_are_alphanumeric = bytes
        .first()
        .zip(bytes.last())
        .is_some_and(|(f, l)| f.is_ascii_alphanumeric() && l.is_ascii_alphanumeric());
    if !edges_are_alphanumeric {
        return Some("a hostname must start and end with a letter or a digit");
    }
    // A name made only of digits and dots is a malformed IPv4 literal, not a hostname.
    if candidate.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return Some(
            "it contains only digits and dots, so it was read as an IPv4 address, but it is not a \
             valid one",
        );
    }
    if !candidate
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_')
    {
        return Some("a hostname may contain only letters, digits, '-', '.' and '_'");
    }
    None
}

/// Whether `candidate` is shaped like a DNS name. See [`hostname_rejection`] for the rules.
///
/// Test-only: the parser needs the *reason* a name was refused, not merely the verdict, because the
/// reason is what the startup abort prints. This keeps the plausibility check expressible as the
/// predicate it conceptually is, for the tests that enumerate both sides of it.
#[cfg(test)]
mod initial_master_key_tests {
    use super::*;

    /// A well-formed key is accepted and returned verbatim, in either hex case.
    #[test]
    fn a_64_character_hex_string_is_accepted() {
        for valid in [
            "0".repeat(64),
            "f".repeat(64),
            "F".repeat(64),
            "0123456789abcdef".repeat(4),
            "0123456789ABCDEF".repeat(4),
            // Mixed case: hex is case-insensitive and both spellings name the same 32 bytes.
            "0123456789aBcDeF".repeat(4),
        ] {
            assert_eq!(
                validate_initial_master_key(Some(&valid)),
                Ok(Some(valid.clone())),
                "{valid:?} is exactly 64 hex characters and must be accepted"
            );
        }
    }

    /// The width this service actually mints round-trips through the validator.
    ///
    /// Pinned against `generate_random_key` rather than against the literal 64, so that if the
    /// generator's width ever changed, this fails rather than silently accepting a key shape the
    /// service no longer issues.
    #[test]
    fn a_freshly_generated_key_satisfies_the_validator() {
        for _ in 0..16 {
            let generated = crate::api::generate_random_key();
            assert_eq!(
                validate_initial_master_key(Some(&generated)),
                Ok(Some(generated.clone())),
                "the daemon must accept a key of the shape it generates itself"
            );
        }
    }

    /// Absence is the documented zero-config path and is **not** an error.
    ///
    /// This is the case most at risk of being "tightened" later: making it fatal would mean the
    /// daemon cannot start without an operator-supplied master key, which contradicts the bootstrap
    /// design and `README.md`. The assertion is here so that change has to be deliberate.
    #[test]
    fn an_unset_variable_is_not_an_error_and_asks_for_a_generated_key() {
        assert_eq!(validate_initial_master_key(None), Ok(None));
    }

    /// A variable that is set but blank is a defect, not absence.
    ///
    /// `INITIAL_MASTER_KEY=""` and `INITIAL_MASTER_KEY=$UNSET_VAR` are what a broken deployment
    /// script produces. Falling back to a generated key there would hand the operator a daemon whose
    /// master credential is not the one their tooling believes it configured.
    #[test]
    fn a_set_but_empty_value_is_fatal_rather_than_treated_as_unset() {
        for blank in ["", " ", "\t", "\n", "   \t\n  "] {
            assert_eq!(
                validate_initial_master_key(Some(blank)),
                Err(InitialMasterKeyError::Empty),
                "{blank:?} must be refused, not silently replaced with a generated key"
            );
        }
    }

    /// Anything other than exactly 64 hex characters is refused, on width.
    #[test]
    fn a_key_of_the_wrong_width_is_refused() {
        for (value, width) in [
            ("a".repeat(63), 63),
            ("a".repeat(65), 65),
            ("a".repeat(32), 32),
            ("abcdef".to_owned(), 6),
            ("a".repeat(128), 128),
        ] {
            assert_eq!(
                validate_initial_master_key(Some(&value)),
                Err(InitialMasterKeyError::BadLength(width)),
                "a {width}-character key must be refused"
            );
        }
    }

    /// Non-hex characters are refused, and named.
    ///
    /// The reported position and character are asserted because the whole reason this error carries
    /// them is that an operator cannot see the value in the log — a bare "invalid" would leave them
    /// diffing the key by eye.
    #[test]
    fn non_hex_characters_are_refused_and_located() {
        // Right width, wrong alphabet — this is the case a length-only check would wave through.
        let mut sixty_four = "a".repeat(64);
        sixty_four.replace_range(10..11, "z");
        assert_eq!(
            validate_initial_master_key(Some(&sixty_four)),
            Err(InitialMasterKeyError::NonHex('z', 10)),
            "a full-width key containing 'z' must be refused on its alphabet, not accepted on width"
        );

        for (value, expected_char, expected_index) in [
            ("g".repeat(64), 'g', 0),
            ("-".repeat(64), '-', 0),
            (format!("{}!", "a".repeat(63)), '!', 63),
            (format!("{} {}", "a".repeat(31), "a".repeat(32)), ' ', 31),
        ] {
            assert_eq!(
                validate_initial_master_key(Some(&value)),
                Err(InitialMasterKeyError::NonHex(expected_char, expected_index))
            );
        }
    }

    /// The alphabet is checked before the width, so the more useful complaint wins.
    ///
    /// A short value full of `z` is told it is not hex rather than merely that it is short, because
    /// "not hex" is the defect the operator has to fix first — correcting the length of a value that
    /// was never hex would not help.
    #[test]
    fn the_alphabet_complaint_takes_precedence_over_the_width_complaint() {
        assert_eq!(
            validate_initial_master_key(Some("zzzz")),
            Err(InitialMasterKeyError::NonHex('z', 0))
        );
    }

    /// Surrounding whitespace is trimmed, because `$(cat key.txt)` carries a newline.
    ///
    /// Trimming cannot change the meaning of a hex string, which is what makes it safe here.
    #[test]
    fn surrounding_whitespace_is_trimmed_rather_than_rejected() {
        let key = "a".repeat(64);
        for padded in [
            format!("{key}\n"),
            format!("  {key}  "),
            format!("\t{key}\r\n"),
        ] {
            assert_eq!(
                validate_initial_master_key(Some(&padded)),
                Ok(Some(key.clone())),
                "a trailing newline from a shell substitution must not be a fatal misconfiguration"
            );
        }
    }

    /// Every rejection names the actual defect, so the log is actionable without the value.
    #[test]
    fn each_error_renders_an_actionable_message() {
        let empty = InitialMasterKeyError::Empty.to_string();
        assert!(empty.contains("empty"), "{empty}");
        assert!(empty.contains("unset it entirely"), "the zero-config escape must be offered");

        let short = InitialMasterKeyError::BadLength(12).to_string();
        assert!(short.contains("64"), "{short}");
        assert!(short.contains("got 12"), "{short}");

        let bad = InitialMasterKeyError::NonHex('z', 3).to_string();
        assert!(bad.contains("'z'"), "{bad}");
        assert!(bad.contains("position 3"), "{bad}");

        // All three point at the same remedy, so an operator never has to work out how to make one.
        for message in [empty, short, bad] {
            assert!(message.contains("openssl rand -hex 32"), "{message}");
        }
    }
}

#[cfg(test)]
fn is_hostname_like(candidate: &str) -> bool {
    hostname_rejection(candidate).is_none()
}

/// Parses `TRUSTED_PROXIES` into the set of peers whose forwarding headers are believed.
///
/// Three spellings are accepted, in this order:
///
/// - **CIDR** (`10.0.0.0/8`, `172.16.0.0/12`) — the Docker/Traefik bridge-network case.
/// - **Bare address** (`127.0.0.1`, `::1`), widened to a host route (`/32`, `/128`), because an
///   operator naming one proxy should not have to remember the prefix.
/// - **Hostname** (`traefik`, `proxy.internal`), resolved at match time — see
///   [`TrustedProxies::resolved`]. This is what makes the setting usable on a container platform,
///   where the proxy's address is assigned by the orchestrator and changes on every restart.
///
/// # Two failures that look alike and are not
///
/// A **syntax error** — an entry that is neither an address, nor a CIDR, nor even hostname-shaped —
/// is **fatal**, and this is the one place in this module that refuses to fall back to a default.
/// The rest of the module is lenient because a bad `LOG_RETENTION_DAYS` has an obviously correct
/// substitute; a bad `TRUSTED_PROXIES` entry does not. Dropping it silently leaves the operator
/// believing a proxy is trusted when it is not, and every request through that proxy is then
/// authorized against the *proxy's* address instead of the client's — `bound_ips` allowlists
/// quietly stop meaning what they say and `audit_logs.client_ip` records the wrong caller. That is
/// a security boundary configured one way and enforced another, which is worse than not starting.
///
/// An **unresolvable hostname** is a different thing entirely and stays non-fatal. `traefik` is
/// perfectly well-formed; it just names a container that has not finished starting. That is an
/// ordinary startup race, it is already fail-closed (an unresolved name is trusted by nobody), and
/// it corrects itself — so it is handled by the negative cache and the boot grace period in
/// [`TrustedProxies::prime`] rather than by refusing to run. The distinction is exactly
/// *typo versus timing*: one can only be fixed by a human editing configuration, the other fixes
/// itself in seconds.
fn parse_trusted_proxies(raw: &str) -> Result<Vec<ProxySpec>, TrustedProxyError> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|entry| match entry.parse::<IpNetwork>() {
            Ok(network) => Ok(ProxySpec::Network(network)),
            // `IpNetwork`'s parser is the authority on CIDR text; these fallbacks cover the
            // bare-address and hostname spellings by construction rather than by string surgery.
            Err(_) => match entry.parse::<IpAddr>() {
                Ok(addr) => Ok(ProxySpec::Network(IpNetwork::from(addr))),
                Err(_) => match hostname_rejection(entry) {
                    None => Ok(ProxySpec::Hostname(entry.to_owned())),
                    Some(reason) => Err(TrustedProxyError {
                        entry: entry.to_owned(),
                        reason: reason.to_owned(),
                    }),
                },
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

    /// Builds a header map from `(name, value)` pairs.
    fn headers(pairs: &[(&str, &str)]) -> axum::http::HeaderMap {
        let mut map = axum::http::HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).expect("valid header name"),
                value.parse().expect("valid header value"),
            );
        }
        map
    }

    fn ip(raw: &str) -> IpAddr {
        raw.parse().expect("valid IP literal")
    }

    /// Parses a `TRUSTED_PROXIES` fixture that is expected to be syntactically valid.
    ///
    /// The fallible-parse path has its own dedicated tests below; everything else in this module is
    /// about resolution and matching, and should not restate the syntax contract at every call.
    fn trusted(raw: &str) -> TrustedProxies {
        TrustedProxies::from_raw(raw).expect("test fixture is syntactically valid")
    }

    fn nets(raw: &str) -> Vec<IpNetwork> {
        parse_trusted_proxies(raw)
            .expect("test fixture is well-formed")
            .into_iter()
            .filter_map(|spec| match spec {
                ProxySpec::Network(network) => Some(network),
                ProxySpec::Hostname(_) => None,
            })
            .collect()
    }

    #[test]
    fn parses_addresses_cidrs_and_hostnames() {
        let parsed = parse_trusted_proxies("127.0.0.1, 10.0.0.0/8 , ::1, traefik, proxy.internal")
            .expect("every entry is well-formed");
        assert_eq!(
            parsed,
            vec![
                // A bare address is widened to a host route, so naming one proxy needs no /32.
                ProxySpec::Network("127.0.0.1/32".parse().expect("valid")),
                ProxySpec::Network("10.0.0.0/8".parse().expect("valid")),
                ProxySpec::Network("::1/128".parse().expect("valid")),
                ProxySpec::Hostname("traefik".to_owned()),
                ProxySpec::Hostname("proxy.internal".to_owned()),
            ]
        );
    }

    #[test]
    fn trusted_proxies_defaults_to_empty() {
        // Empty is the secure default: no peer is trusted, so no forwarding header is believed.
        // Note that empty is *not* an error — "trust nothing" is the intended production posture,
        // not a misconfiguration.
        assert!(parse_trusted_proxies("").expect("empty is valid").is_empty());
        assert!(parse_trusted_proxies("  ,, ").expect("blanks are skipped").is_empty());
        assert!(RuntimeConfig::default().trusted_proxies.is_empty());
    }

    /// The fatal half of the split. A syntactically invalid entry aborts startup instead of being
    /// dropped with a warning.
    ///
    /// Dropping it was the old behaviour and it was the wrong trade. A dropped entry means the
    /// operator believes a proxy is trusted while it is not, so every request arriving through that
    /// proxy is authorized against the *proxy's* address rather than the client's: `bound_ips`
    /// allowlists silently stop meaning what they say, and `audit_logs.client_ip` records the wrong
    /// caller. A security boundary configured one way and enforced another is worse than a daemon
    /// that refuses to start and says why.
    ///
    /// Critically, a botched CIDR must not be silently reinterpreted as a hostname that then never
    /// resolves — that would launder a syntax error into the *non*-fatal path this test exists to
    /// separate it from.
    #[test]
    fn a_syntactically_invalid_entry_is_fatal_rather_than_dropped() {
        for malformed in ["999.1.1.1", "10.0.0.0/99", "10.0.0.0/8x", "-leading-dash", "::ffff::x"] {
            let err = parse_trusted_proxies(malformed)
                .expect_err("{malformed:?} must abort startup, not be silently dropped");
            assert_eq!(err.entry, malformed);
            assert!(!err.reason.is_empty(), "the abort must say which spelling nearly matched");
        }

        // The message is the operator's entire diagnostic, so its wording is asserted verbatim
        // rather than merely checked for being an error.
        let err = parse_trusted_proxies("10.0.0.0/8x").expect_err("malformed CIDR");
        assert_eq!(
            err.to_string(),
            "FATAL: TRUSTED_PROXIES entry '10.0.0.0/8x' is not a valid IP address, CIDR range, or \
             hostname (it contains '/', so it was read as a CIDR range, but the address or prefix \
             length is not valid). Refusing to start with an ambiguous trust boundary."
        );

        // One bad entry condemns the whole list: a partially-applied trust boundary is precisely
        // the ambiguity being refused, so the valid entries alongside it are not silently kept.
        assert!(parse_trusted_proxies("10.0.0.0/8, 10.0.0.0/8x, traefik").is_err());
        assert!(TrustedProxies::from_raw("10.0.0.0/8x").is_err());
        assert!(RuntimeConfig::default().trusted_proxies.is_empty());
    }

    /// The non-fatal half of the same split, and the distinction the whole design turns on:
    /// **typo versus timing**.
    ///
    /// `no-such-host.invalid` is perfectly well-formed — it simply names something that is not
    /// answering yet, which under Compose or Kubernetes is the ordinary case of a sibling container
    /// still starting. It therefore parses cleanly, the daemon serves, the entry contributes
    /// nothing (fail-closed) until it resolves, and [`TrustedProxies::prime`] reports it so the boot
    /// grace period in `main` can re-check it. Aborting on this would turn a startup race into a
    /// crash loop.
    #[tokio::test]
    async fn a_valid_but_unresolvable_hostname_starts_and_is_left_to_the_grace_period() {
        let proxies = TrustedProxies::from_raw("no-such-host.invalid, 10.0.0.0/8")
            .expect("an unresolvable name is still syntactically valid");

        // Parsing succeeded, so startup continues — that is the whole difference from the test
        // above, where the same call returns Err.
        assert_eq!(
            proxies.spec(),
            &[
                ProxySpec::Hostname("no-such-host.invalid".to_owned()),
                ProxySpec::Network("10.0.0.0/8".parse().expect("valid")),
            ]
        );

        // Priming reports it rather than failing, which is what `main` turns into the 60s grace
        // period and the loud post-grace re-check.
        assert_eq!(proxies.prime().await, vec!["no-such-host.invalid".to_owned()]);

        // And the daemon is serving in the meantime, with that entry simply not trusted.
        let resolved = proxies.resolved().await;
        assert!(is_trusted(ip("10.1.2.3"), &resolved), "the literal entry still applies");
        assert_eq!(resolved.len(), 1, "the unresolvable name contributes nothing: {resolved:?}");
    }

    #[test]
    fn distinguishes_hostnames_from_malformed_addresses() {
        for name in ["traefik", "proxy.internal", "gw-1", "a", "svc_name", "x.y.z-9"] {
            assert!(is_hostname_like(name), "{name:?} should be accepted as a hostname");
        }
        for not_a_name in [
            "",
            "10.0.0.1",      // a well-formed address is handled before this is ever consulted
            "999.1.1.1",     // a malformed IPv4 literal, not a name
            "10.0.0.0/8",    // CIDR syntax
            "::1",           // IPv6 syntax
            "-leading",
            "trailing-",
            ".dotted",
            "has space",
            "bad!char",
        ] {
            assert!(!is_hostname_like(not_a_name), "{not_a_name:?} should not be a hostname");
        }
    }

    #[test]
    fn forwarding_headers_are_ignored_when_the_peer_is_not_trusted() {
        let peer = ip("203.0.113.5");
        let hdrs = headers(&[("X-Forwarded-For", "10.1.2.3"), ("X-Real-IP", "10.1.2.3")]);

        // Nothing trusted at all — the production default.
        assert_eq!(resolve_client_ip(peer, &hdrs, &[]), peer);
        // A trust list that simply does not include this peer behaves identically.
        assert_eq!(resolve_client_ip(peer, &hdrs, &nets("10.0.0.0/8")), peer);
    }

    #[test]
    fn a_trusted_peer_has_its_forwarded_client_believed() {
        let peer = ip("10.0.0.9");
        let trusted = nets("10.0.0.0/8");

        assert_eq!(
            resolve_client_ip(peer, &headers(&[("X-Forwarded-For", "192.168.4.4")]), &trusted),
            ip("192.168.4.4")
        );
        // X-Real-IP is consulted only when X-Forwarded-For yields nothing.
        assert_eq!(
            resolve_client_ip(peer, &headers(&[("X-Real-IP", "192.168.4.4")]), &trusted),
            ip("192.168.4.4")
        );
        // An IPv4-mapped hop is normalized so it can match an IPv4 CIDR.
        assert_eq!(
            resolve_client_ip(peer, &headers(&[("X-Real-IP", "::ffff:192.168.4.4")]), &trusted),
            ip("192.168.4.4")
        );
        // Garbage falls back to the peer rather than failing open.
        assert_eq!(
            resolve_client_ip(peer, &headers(&[("X-Forwarded-For", "not-an-ip")]), &trusted),
            peer
        );
        assert_eq!(resolve_client_ip(peer, &axum::http::HeaderMap::new(), &trusted), peer);
    }

    #[test]
    fn the_chain_is_walked_right_to_left_past_trusted_hops() {
        let peer = ip("10.0.0.2");
        let trusted = nets("10.0.0.0/8,172.16.0.0/12");

        // client → P1(172.16.0.9) → P2(10.0.0.2) → us. The header reads "client, P1"; the rightmost
        // entry is a proxy, so it must be skipped to reach the real client.
        assert_eq!(
            resolve_client_ip(
                peer,
                &headers(&[("X-Forwarded-For", "203.0.113.50, 172.16.0.9")]),
                &trusted
            ),
            ip("203.0.113.50")
        );

        // A client that prepends a lie gets it ignored: only the suffix each proxy appended counts.
        assert_eq!(
            resolve_client_ip(
                peer,
                &headers(&[("X-Forwarded-For", "8.8.8.8, 203.0.113.50, 172.16.0.9")]),
                &trusted
            ),
            ip("203.0.113.50")
        );

        // A header naming nothing but trusted proxies says nothing about the client, so the peer
        // stands rather than a proxy being reported as the caller.
        assert_eq!(
            resolve_client_ip(peer, &headers(&[("X-Forwarded-For", "10.0.0.3, 172.16.0.9")]), &trusted),
            peer
        );
    }

    #[test]
    fn a_trusted_peer_is_matched_after_ipv4_mapping_is_normalized() {
        // A dual-stack listener surfaces an IPv4 proxy as ::ffff:10.0.0.9; the trust check must
        // still recognize it, or a correct TRUSTED_PROXIES entry would silently stop applying.
        assert_eq!(
            resolve_client_ip(
                ip("::ffff:10.0.0.9"),
                &headers(&[("X-Forwarded-For", "192.168.4.4")]),
                &nets("10.0.0.0/8")
            ),
            ip("192.168.4.4")
        );
    }

    #[tokio::test]
    async fn resolution_is_a_no_op_when_only_addresses_are_configured() {
        let proxies = trusted("127.0.0.1,10.0.0.0/8");
        let resolved = proxies.resolved().await;
        assert_eq!(resolved.len(), 2);
        assert!(is_trusted(ip("10.1.2.3"), &resolved));
        // Same allocation each time: the no-hostname path must not rebuild or lock anything.
        assert!(Arc::ptr_eq(&resolved, &proxies.resolved().await));
    }

    #[tokio::test]
    async fn hostnames_resolve_to_their_addresses_and_are_cached() {
        // `localhost` is the one name guaranteed resolvable without network access.
        let proxies = trusted("localhost,192.0.2.0/24");
        let resolved = proxies.resolved().await;

        assert!(
            is_trusted(ip("127.0.0.1"), &resolved) || is_trusted(ip("::1"), &resolved),
            "localhost should resolve to a loopback address: {resolved:?}"
        );
        // The literal entry alongside it is preserved.
        assert!(is_trusted(ip("192.0.2.7"), &resolved));
        // A second call inside the TTL reuses the cached allocation rather than resolving again.
        assert!(Arc::ptr_eq(&resolved, &proxies.resolved().await));
    }

    /// The other half of the positive window, and the half the test above cannot reach: a cached
    /// *success* must eventually be re-queried, not held forever.
    ///
    /// This is the more security-relevant direction of the two. [`TRUSTED_PROXY_DNS_TTL`] is the
    /// window in which a container that has been recreated keeps its **old** address trusted — an
    /// address the orchestrator may well have already handed to something else. `AGENT.MD` accepts
    /// that window at 30s precisely because it expires; a positive entry that never lapsed would
    /// turn a moved proxy into a standing grant to whoever inherited its address, and would need a
    /// restart to clear. Asserting expiry is what keeps that from regressing into "cached forever".
    #[tokio::test]
    async fn a_successful_resolution_is_re_queried_once_its_positive_ttl_expires() {
        let proxies = trusted("localhost").with_ttl(Duration::ZERO);

        let first = proxies.resolved().await;
        assert!(
            is_trusted(ip("127.0.0.1"), &first) || is_trusted(ip("::1"), &first),
            "localhost should resolve to a loopback address: {first:?}"
        );

        // A fresh `Arc` is the observable signal that a lookup ran: the flattened view is rebuilt
        // only when at least one name was actually re-queried. This is the same signal the
        // negative-caching tests use, read in the opposite direction.
        assert!(
            !Arc::ptr_eq(&first, &proxies.resolved().await),
            "an expired positive entry must be re-resolved rather than trusted indefinitely"
        );
    }

    #[tokio::test]
    async fn an_unresolvable_hostname_is_simply_not_trusted() {
        // Failing closed matters: a DNS outage must never be able to *widen* what is trusted.
        let proxies = trusted("no-such-host.invalid,10.0.0.0/8");
        let resolved = proxies.resolved().await;

        assert!(is_trusted(ip("10.1.2.3"), &resolved), "the literal entry still applies");
        assert_eq!(resolved.len(), 1, "the unresolvable name contributes nothing: {resolved:?}");
    }

    /// Negative caching, and the reason it exists: without it the daemon's own request rate becomes
    /// its DNS query rate the moment a name stops resolving, which is a self-inflicted
    /// amplification path that bites hardest exactly when the resolver is already unhealthy.
    ///
    /// A fresh `Arc` is the observable signal that a lookup ran — the flattened view is only
    /// rebuilt when at least one name was actually re-queried — so pointer identity across calls is
    /// what proves no query was issued.
    #[tokio::test]
    async fn a_failed_resolution_is_cached_so_traffic_cannot_become_a_dns_storm() {
        let proxies = trusted("no-such-host.invalid")
            .with_negative_ttl(Duration::from_secs(30));

        let first = proxies.resolved().await;
        for attempt in 0..10 {
            assert!(
                Arc::ptr_eq(&first, &proxies.resolved().await),
                "request {attempt} re-queried DNS inside the negative window"
            );
        }
    }

    /// The other half of the same contract: the failure is cached, not permanent. A proxy that was
    /// merely slow to start must become trusted on its own, without a restart.
    #[tokio::test]
    async fn a_failed_resolution_is_retried_once_its_negative_ttl_expires() {
        let proxies =
            trusted("no-such-host.invalid").with_negative_ttl(Duration::ZERO);

        let first = proxies.resolved().await;
        assert!(
            !Arc::ptr_eq(&first, &proxies.resolved().await),
            "an expired negative entry must be re-resolved rather than held forever"
        );
    }

    /// Per-domain expiry: one unresolvable name must not drag a healthy one into being re-queried
    /// alongside it, and must not suppress the healthy name's addresses either.
    #[tokio::test]
    async fn one_failing_name_does_not_disturb_the_names_that_resolve() {
        let proxies = trusted("localhost,no-such-host.invalid,192.0.2.7")
            .with_negative_ttl(Duration::ZERO);

        for attempt in 0..3 {
            let resolved = proxies.resolved().await;
            assert!(
                is_trusted(ip("127.0.0.1"), &resolved) || is_trusted(ip("::1"), &resolved),
                "attempt {attempt}: the healthy name must stay trusted"
            );
            assert!(is_trusted(ip("192.0.2.7"), &resolved), "attempt {attempt}: literal preserved");
            assert!(
                !is_trusted(ip("203.0.113.9"), &resolved),
                "attempt {attempt}: the failing name must contribute nothing"
            );
        }
    }

    /// Boot priming reports the names that could not be resolved, which is what `main` turns into
    /// the startup error and the post-grace-period re-check. It must never fail or panic — a
    /// daemon that refuses to start over an unresolvable proxy is a crash loop, and the entry is
    /// already fail-closed without one.
    #[tokio::test]
    async fn priming_reports_unresolvable_names_without_failing() {
        let proxies = trusted("localhost,no-such-host.invalid,10.0.0.0/8");
        assert_eq!(proxies.prime().await, vec!["no-such-host.invalid".to_owned()]);

        // A configuration with nothing to look up is a no-op rather than a spurious success log.
        assert!(trusted("10.0.0.0/8").prime().await.is_empty());
        assert!(TrustedProxies::default().prime().await.is_empty());
    }

    #[tokio::test]
    async fn a_hostname_peer_is_trusted_end_to_end() {
        let proxies = trusted("localhost");
        let trusted = proxies.resolved().await;

        // The loopback peer is trusted because the *name* resolved to it, so its header is believed.
        let forwarded = resolve_client_ip(
            ip("127.0.0.1"),
            &headers(&[("X-Forwarded-For", "203.0.113.50")]),
            &trusted,
        );
        assert_eq!(forwarded, ip("203.0.113.50"));

        // An unrelated peer is still untrusted, so its identical header is ignored.
        assert_eq!(
            resolve_client_ip(
                ip("203.0.113.9"),
                &headers(&[("X-Forwarded-For", "203.0.113.50")]),
                &trusted
            ),
            ip("203.0.113.9")
        );
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
