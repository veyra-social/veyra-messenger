//! Proxy transport runtime (slice A: the HTTPS plane).
//!
//! One immutable snapshot of the active proxy is published here after unlock
//! and on every settings change; every HTTPS client in the app builds itself
//! through [`apply`], so there is exactly one place that decides whether a
//! request goes direct or through the proxy.
//!
//! Proxy mode is fail-closed by design (ratified 2026-07-25): there is no
//! silent direct fallback. When the proxy is on and broken, requests fail and
//! the app is honestly offline — nothing leaks around the proxy.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::errors::{AppError, AppResult};
use crate::models::proxy::{ProxyKind, ProxyStatus, ProxyTestResult};
use crate::storage::proxies::ProxyConfig;

/// Bounded phases so a dead proxy fails fast instead of stalling a worker.
/// Per candidate node — the check walks up to [`MAX_TEST_TARGETS`] of them, so
/// the worst case (everything unreachable) stays under ~20 s.
const PROXY_CONNECT_TIMEOUT: Duration = Duration::from_secs(4);
const PROXY_TEST_TIMEOUT: Duration = Duration::from_secs(6);
/// How many probe targets the check may try before giving up on the proxy.
pub const MAX_TEST_TARGETS: usize = 4;

/// What the check aims at.
///
/// Deliberately NOT our own bootstrap nodes: the question is «does this proxy
/// work», not «are our nodes up». A node can be down, blocked from the proxy's
/// network, or simply not added yet — none of that makes the proxy broken, and
/// the user may add their own nodes or receive them from contacts later
/// (ratified 2026-07-25 after the check condemned a healthy proxy over one
/// unroutable node).
///
/// Every entry is TCP/443 HTTPS, because that is the only thing a tunnel can
/// carry: NTP is UDP/123 and plain DNS is UDP/53 — neither survives SOCKS5
/// CONNECT or HTTP CONNECT — and CONNECT proxies routinely allow port 443
/// only. The list mixes global DoH resolvers with sites that stay reachable
/// inside Russia and China, so that a proxy in a censored network still finds
/// something to answer it. A successful TLS session to any one of them means
/// the tunnel carries real traffic.
const PROBE_TARGETS: &[&str] = &[
    "https://one.one.one.one/",     // Cloudflare DNS
    "https://1.1.1.1/",             // …by IP: no DNS needed at all
    "https://dns.google/",          // Google DNS
    "https://8.8.8.8/",             // …by IP
    "https://dns.quad9.net/",       // Quad9 (Switzerland)
    "https://9.9.9.9/",             // …by IP
    "https://dns.adguard-dns.com/", // AdGuard (Cyprus)
    "https://example.com/",         // IANA reference host
    "https://www.wikipedia.org/",   // Wikimedia
    "https://ya.ru/",               // reachable inside Russia
    "https://www.baidu.com/",       // reachable inside China
    "https://www.qq.com/",          // reachable inside China
];

/// The targets for one check: [`MAX_TEST_TARGETS`] entries starting at a
/// random offset. Rotating spreads the probes over the list instead of always
/// knocking on Cloudflare's door, and keeps the check from being a fixed,
/// recognisable pattern.
pub fn probe_targets() -> Vec<String> {
    let offset = (rand::random::<u32>() as usize) % PROBE_TARGETS.len();
    (0..MAX_TEST_TARGETS.min(PROBE_TARGETS.len()))
        .map(|index| PROBE_TARGETS[(offset + index) % PROBE_TARGETS.len()].to_string())
        .collect()
}
/// Two consecutive failures before the UI is told the proxy is down: a single
/// dropped request on mobile is not an outage.
const FAILURES_BEFORE_DOWN: u32 = 2;

/// …and they must be spread over at least this long. The mailbox HTTPS pool
/// runs several workers in parallel, so one bad moment produces several
/// failures within microseconds — the 2026-07-27 ASUS log has pairs 0.5 ms
/// apart, with a successful request one second later. Counting those as "two
/// consecutive failures" turned a single blip into an outage; "consecutive"
/// has to mean "over time", not "in flight together".
const MIN_FAILURE_SPAN: Duration = Duration::from_secs(20);

/// How long one outage stays the SAME outage. The UI shows one dialog per
/// outage id and then stays quiet, so minting a fresh id on every
/// down → up → down flap produced a stack of dialogs (five in four minutes in
/// the same field log). A proxy that recovers and stumbles again within this
/// window is still the outage the user has already been told about.
const OUTAGE_COOLDOWN: Duration = Duration::from_secs(15 * 60);

pub const ERR_UNREACHABLE: &str = "proxy_unreachable";
pub const ERR_AUTH_FAILED: &str = "proxy_auth_failed";
pub const ERR_CONNECT_DENIED: &str = "proxy_connect_denied";
pub const ERR_TIMEOUT: &str = "proxy_timeout";
pub const ERR_PROTOCOL: &str = "proxy_protocol_error";
pub const ERR_TARGET_TLS: &str = "target_tls_failed";
pub const ERR_NO_TARGET: &str = "no_test_target";

static ACTIVE: RwLock<Option<Arc<ProxyConfig>>> = RwLock::new(None);
static HEALTH: RwLock<Health> = RwLock::new(Health::new());
/// Incremented on every healthy → down transition. The UI shows its one
/// honest "proxy is down" dialog per outage id and then stays quiet.
static OUTAGE_ID: AtomicU64 = AtomicU64::new(0);
/// Bumped whenever the active configuration changes, so long-lived cached
/// HTTPS clients rebuild instead of holding a client bound to the old proxy.
static GENERATION: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthState {
    /// Proxy mode is off — everything goes direct, as before.
    Off,
    /// On, but no successful request yet in this generation.
    Checking,
    Online,
    Down,
}

impl HealthState {
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Checking => "checking",
            Self::Online => "online",
            Self::Down => "down",
        }
    }
}

struct Health {
    state: HealthState,
    consecutive_failures: u32,
    last_error_code: Option<String>,
    /// When the current run of failures started; cleared by any success.
    first_failure_at: Option<Instant>,
    /// A neutral probe is deciding whether the proxy or the target was at
    /// fault. Only one runs at a time.
    verifying: bool,
    /// Bumped by anything that invalidates an in-flight verdict (a success,
    /// a configuration change), so a late verifier discards its own result.
    epoch: u64,
    /// When the current outage id was minted.
    last_outage_at: Option<Instant>,
}

impl Health {
    const fn new() -> Self {
        Self {
            state: HealthState::Off,
            consecutive_failures: 0,
            last_error_code: None,
            first_failure_at: None,
            verifying: false,
            epoch: 0,
            last_outage_at: None,
        }
    }

    fn clear_failures(&mut self) {
        self.consecutive_failures = 0;
        self.first_failure_at = None;
        self.last_error_code = None;
        self.epoch = self.epoch.wrapping_add(1);
    }
}

/// Publishes the proxy the network layer must use. `None` = proxy mode off.
pub fn set_active(config: Option<Arc<ProxyConfig>>) {
    let enabled = config.is_some();
    if let Ok(mut guard) = ACTIVE.write() {
        *guard = config;
    }
    GENERATION.fetch_add(1, Ordering::Relaxed);
    if let Ok(mut health) = HEALTH.write() {
        health.state = if enabled {
            HealthState::Checking
        } else {
            HealthState::Off
        };
        health.clear_failures();
        health.verifying = false;
        health.last_outage_at = None;
    }
}

pub fn active() -> Option<Arc<ProxyConfig>> {
    ACTIVE.read().ok().and_then(|guard| guard.clone())
}

pub fn is_enabled() -> bool {
    active().is_some()
}

pub fn health() -> (HealthState, Option<String>, u64) {
    let guard = HEALTH.read().ok();
    let (state, code) = guard
        .as_ref()
        .map(|health| (health.state, health.last_error_code.clone()))
        .unwrap_or((HealthState::Off, None));
    (state, code, OUTAGE_ID.load(Ordering::Relaxed))
}

/// Proxy state for the UI. Built from the in-memory snapshot only — no
/// database access, so it is cheap enough for the polled app status.
pub fn status() -> ProxyStatus {
    let active = active();
    let (state, last_error_code, outage_id) = health();
    ProxyStatus {
        enabled: active.is_some(),
        active_id: active.as_ref().map(|config| config.id.clone()),
        active_label: active.as_ref().map(|config| config.label.clone()),
        health: state.as_wire().to_string(),
        last_error_code,
        outage_id,
    }
}

/// Records that a request through the proxy succeeded.
pub fn note_success() {
    if let Ok(mut health) = HEALTH.write() {
        if health.state == HealthState::Off {
            return;
        }
        health.state = HealthState::Online;
        health.clear_failures();
    }
}

/// Records a failed request.
///
/// A failed request is NOT evidence about the proxy. The signal that feeds
/// this is the mailbox poll to one of our own bootstrap nodes, and a node that
/// is down, slow or blocked says nothing about whether the tunnel carries
/// traffic — the same reasoning that keeps `PROBE_TARGETS` off our own nodes
/// (ratified 2026-07-25, after the manual check condemned a healthy proxy over
/// one unroutable node). The passive path kept blaming the proxy anyway: in the
/// 2026-07-27 ASUS log 117 such failures sat next to 876 successes and would
/// have raised 18 "proxy is down" dialogs.
///
/// So a run of failures now only opens a QUESTION. When it has lasted long
/// enough to not be one blip ([`FAILURES_BEFORE_DOWN`] spread over
/// [`MIN_FAILURE_SPAN`]), a neutral probe answers it: if the probe gets
/// through, the proxy works and the node was the problem.
pub fn note_failure(code: &str) {
    let start_verification = {
        let Ok(mut health) = HEALTH.write() else {
            return;
        };
        if health.state == HealthState::Off {
            return;
        }
        health.consecutive_failures = health.consecutive_failures.saturating_add(1);
        health.last_error_code = Some(code.to_string());
        let first = *health.first_failure_at.get_or_insert_with(Instant::now);
        let sustained = failure_run_is_sustained(health.consecutive_failures, first.elapsed());
        if sustained && health.state != HealthState::Down && !health.verifying {
            health.verifying = true;
            Some(health.epoch)
        } else {
            None
        }
    };
    if let Some(epoch) = start_verification {
        spawn_health_verification(epoch);
    }
}

/// Whether a run of failures is long enough to be worth a probe: enough of
/// them AND spread over real time. Split out so the parallel-worker case —
/// several failures at the same instant — is testable without waiting.
fn failure_run_is_sustained(consecutive: u32, since_first: Duration) -> bool {
    consecutive >= FAILURES_BEFORE_DOWN && since_first >= MIN_FAILURE_SPAN
}

/// Whether a confirmed outage is a NEW one the user has not been told about,
/// or the same one still flapping.
fn outage_is_new(since_last_outage: Option<Duration>) -> bool {
    match since_last_outage {
        None => true,
        Some(elapsed) => elapsed >= OUTAGE_COOLDOWN,
    }
}

/// Asks the neutral probe targets whether the tunnel carries traffic at all,
/// and turns the answer into the verdict the UI sees. Runs on its own thread:
/// the callers are HTTPS worker threads in the middle of a request.
fn spawn_health_verification(epoch: u64) {
    let Some(config) = active() else {
        finish_verification(epoch, None);
        return;
    };
    let spawned = std::thread::Builder::new()
        .name("veyra-proxy-health".to_string())
        .spawn(move || {
            let result = test_config(&config, &probe_targets());
            let verdict = if result.ok {
                None
            } else {
                Some(
                    result
                        .error_code
                        .unwrap_or_else(|| ERR_UNREACHABLE.to_string()),
                )
            };
            finish_verification(epoch, verdict);
        });
    if spawned.is_err() {
        finish_verification(epoch, None);
    }
}

/// Applies a verification verdict. `None` means the probe got through — the
/// proxy is fine and the failures belonged to whatever we were talking to.
fn finish_verification(epoch: u64, verdict: Option<String>) {
    let Ok(mut health) = HEALTH.write() else {
        return;
    };
    health.verifying = false;
    // A success (or a settings change) landed while the probe was in flight:
    // its answer is about a state we have already left.
    if health.epoch != epoch || health.state == HealthState::Off {
        return;
    }
    match verdict {
        None => {
            tracing::debug!("proxy health probe got through; failures were not the proxy");
            health.state = HealthState::Online;
            health.clear_failures();
        }
        Some(code) => {
            health.last_error_code = Some(code);
            mark_down(&mut health);
        }
    }
}

/// Moves the health state to `Down`, minting a new outage id only when the
/// previous one is old enough to be a genuinely new outage.
fn mark_down(health: &mut Health) {
    let is_new = outage_is_new(health.last_outage_at.map(|at| at.elapsed()));
    health.state = HealthState::Down;
    if is_new {
        OUTAGE_ID.fetch_add(1, Ordering::Relaxed);
        health.last_outage_at = Some(Instant::now());
    }
}

/// The single place that decides direct vs proxied for HTTPS clients.
///
/// `off`: an explicit `no_proxy()` so an OS/environment proxy can never change
/// Veyra's behaviour behind the user's back. `on`: every request goes through
/// the configured proxy, with no direct client as a fallback.
pub fn apply(
    builder: reqwest::blocking::ClientBuilder,
) -> AppResult<reqwest::blocking::ClientBuilder> {
    match active() {
        None => Ok(builder.no_proxy()),
        Some(config) => {
            let proxy = reqwest::Proxy::all(proxy_url(&config))
                .map_err(|_| AppError::InvalidProxySettings)?;
            Ok(builder.proxy(proxy))
        }
    }
}

/// Builds the proxy URL for reqwest. `socks5h` keeps DNS resolution on the
/// proxy side — the target hostname must never be resolved locally.
///
/// The returned string contains credentials: never log it, never put it in an
/// error message.
fn proxy_url(config: &ProxyConfig) -> String {
    let scheme = match config.kind {
        ProxyKind::Socks5 => "socks5h",
        ProxyKind::HttpConnect => "http",
    };
    let host = if config.host.contains(':') {
        format!("[{}]", config.host)
    } else {
        config.host.clone()
    };
    match (config.username.as_deref(), config.password.as_deref()) {
        (Some(user), password) => format!(
            "{scheme}://{}:{}@{host}:{}",
            encode_credential(user),
            encode_credential(password.unwrap_or_default()),
            config.port
        ),
        (None, _) => format!("{scheme}://{host}:{}", config.port),
    }
}

fn encode_credential(value: &str) -> String {
    percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC).to_string()
}

/// Records the outcome of a deliberate probe. Unlike a single background
/// request — which can fail for a hundred reasons on mobile — a probe is
/// authoritative: it aimed at several always-on endpoints and none answered.
/// The indicator goes red at once instead of lingering on "checking".
pub fn note_probe_failure(code: &str) {
    if let Ok(mut health) = HEALTH.write() {
        if health.state == HealthState::Off {
            return;
        }
        health.consecutive_failures = health.consecutive_failures.saturating_add(1);
        health.last_error_code = Some(code.to_string());
        if health.state != HealthState::Down {
            mark_down(&mut health);
        }
    }
}

/// Records the outcome of a real request for the health indicator. HTTP status
/// errors are deliberately ignored: a 500 from a node says nothing about the
/// route, and marking the proxy down for it would be a lie.
pub fn note_reqwest_error(error: &reqwest::Error) {
    if error.is_status() || error.is_decode() || error.is_body() {
        return;
    }
    note_failure(classify_error(error));
}

/// A `reqwest` client that is rebuilt whenever the proxy configuration
/// changes. Used for the long-lived clients (mailbox polling) that would
/// otherwise stay bound to a proxy the user has already switched away from.
pub struct CachedClient {
    inner: RwLock<Option<(u64, reqwest::blocking::Client)>>,
}

impl CachedClient {
    pub const fn new() -> Self {
        Self {
            inner: RwLock::new(None),
        }
    }

    pub fn get_or_build<F>(&self, configure: F) -> AppResult<reqwest::blocking::Client>
    where
        F: FnOnce(reqwest::blocking::ClientBuilder) -> reqwest::blocking::ClientBuilder,
    {
        let generation = GENERATION.load(Ordering::Relaxed);
        if let Ok(guard) = self.inner.read() {
            if let Some((cached_generation, client)) = guard.as_ref() {
                if *cached_generation == generation {
                    return Ok(client.clone());
                }
            }
        }
        let client = apply(configure(reqwest::blocking::Client::builder()))?
            .build()
            .map_err(|err| AppError::Internal(err.to_string()))?;
        if let Ok(mut guard) = self.inner.write() {
            *guard = Some((generation, client.clone()));
        }
        Ok(client)
    }
}

impl Default for CachedClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Maps a transport failure to one normalized code. Credentials can never
/// reach this function's output: only fixed strings are returned.
pub fn classify_error(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        return ERR_TIMEOUT;
    }
    if error.status().map(|status| status.as_u16()) == Some(407) {
        return ERR_AUTH_FAILED;
    }
    if !error.is_connect() {
        return ERR_PROTOCOL;
    }
    // reqwest folds SOCKS/CONNECT handshake failures into connect errors and
    // keeps the actual reason in the source chain — the top-level message is
    // always the generic "error sending request for url". Verified against a
    // live microsocks/squid pair on 2026-07-25; the observed chains are the
    // cases covered in `classify_chain_text`.
    let mut chain = String::new();
    let mut current: Option<&dyn std::error::Error> = Some(error);
    while let Some(error) = current {
        chain.push_str(&error.to_string());
        chain.push('\n');
        current = error.source();
    }
    classify_chain_text(&chain)
}

/// The string matching of [`classify_error`], split out so it can be tested
/// against the exact wording real proxies produce (a `reqwest::Error` cannot
/// be constructed by hand).
fn classify_chain_text(chain: &str) -> &'static str {
    let text = chain.to_ascii_lowercase();
    // "credentials not accepted" (SOCKS5), "proxy authorization required"
    // (HTTP CONNECT / 407).
    if text.contains("credentials not accepted")
        || text.contains("authorization required")
        || text.contains("authentication")
        || text.contains("407")
    {
        return ERR_AUTH_FAILED;
    }
    // The proxy answered but refused to open the tunnel to this target.
    if text.contains("denied") || text.contains("forbidden") || text.contains("not allowed") {
        return ERR_CONNECT_DENIED;
    }
    // A tunnel error that is neither of the above still means the proxy
    // itself was reachable and talked to us.
    if text.contains("tunnel error") {
        return ERR_CONNECT_DENIED;
    }
    ERR_UNREACHABLE
}

/// One proxy check: reach the proxy, then tunnel to one of [`PROBE_TARGETS`]
/// and complete TLS. Nothing of ours is sent — no messages, contacts, key
/// material or identifiers; the probe is an anonymous HEAD that any browser
/// could have made, and it originates from the proxy, not from the user.
///
/// Never returns `Err` for a network problem: a failed check is information
/// for the user, expressed as an `error_code`.
pub fn test_config(config: &ProxyConfig, targets: &[String]) -> ProxyTestResult {
    if targets.is_empty() {
        return ProxyTestResult {
            ok: false,
            proxy_reached: false,
            target_reached: false,
            latency_ms: None,
            error_code: Some(ERR_NO_TARGET.to_string()),
        };
    }
    let mut last = None;
    for target in targets {
        let result = test_one_target(config, target);
        // A verdict about the proxy itself is final — another target would
        // not change it. Anything else may be about that one target (blocked
        // in this country, momentarily down), so the next candidate gets a
        // turn. The proxy is called broken only when nothing answers.
        if result.ok
            || matches!(
                result.error_code.as_deref(),
                Some(ERR_AUTH_FAILED) | Some(ERR_UNREACHABLE)
            )
        {
            return result;
        }
        last = Some(result);
    }
    last.expect("targets is not empty")
}

fn test_one_target(config: &ProxyConfig, target_url: &str) -> ProxyTestResult {
    let started = Instant::now();
    let client = match reqwest::Proxy::all(proxy_url(config))
        .map_err(|_| AppError::InvalidProxySettings)
        .and_then(|proxy| {
            reqwest::blocking::Client::builder()
                .proxy(proxy)
                .connect_timeout(PROXY_CONNECT_TIMEOUT)
                .timeout(PROXY_TEST_TIMEOUT)
                .pool_max_idle_per_host(0)
                .build()
                .map_err(|err| AppError::Internal(err.to_string()))
        }) {
        Ok(client) => client,
        Err(_) => {
            return ProxyTestResult {
                ok: false,
                proxy_reached: false,
                target_reached: false,
                latency_ms: None,
                error_code: Some(ERR_PROTOCOL.to_string()),
            }
        }
    };
    // HEAD carries no body: the check proves the tunnel and TLS, and any HTTP
    // status counts as success — a 404 from the endpoint still means the
    // proxy delivered us to the real host over a verified TLS session.
    match client.head(target_url).send() {
        Ok(_) => ProxyTestResult {
            ok: true,
            proxy_reached: true,
            target_reached: true,
            latency_ms: Some(started.elapsed().as_millis() as u64),
            error_code: None,
        },
        Err(err) => {
            let code = if err.is_request() && !err.is_connect() && !err.is_timeout() {
                ERR_TARGET_TLS
            } else {
                classify_error(&err)
            };
            ProxyTestResult {
                ok: false,
                // Everything except "we could not reach the proxy at all"
                // means the proxy answered and then something went wrong
                // further along — worth telling apart in the UI.
                proxy_reached: code != ERR_UNREACHABLE,
                target_reached: false,
                latency_ms: None,
                error_code: Some(code.to_string()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(username: Option<&str>, password: Option<&str>) -> ProxyConfig {
        ProxyConfig {
            id: "id".to_string(),
            label: "Дом".to_string(),
            kind: ProxyKind::Socks5,
            host: "10.8.0.1".to_string(),
            port: 1080,
            username: username.map(str::to_string),
            password: password.map(str::to_string),
        }
    }

    #[test]
    fn socks5_uses_remote_dns_scheme() {
        assert!(proxy_url(&config(None, None)).starts_with("socks5h://"));
        let mut http = config(None, None);
        http.kind = ProxyKind::HttpConnect;
        assert!(proxy_url(&http).starts_with("http://"));
    }

    #[test]
    fn credentials_are_percent_encoded_in_the_proxy_url() {
        let url = proxy_url(&config(Some("us er"), Some("p@ss:/")));
        assert!(url.contains("us%20er"));
        assert!(url.contains("p%40ss%3A%2F"));
        // The raw password must not survive anywhere in the URL.
        assert!(!url.contains("p@ss"));
    }

    #[test]
    fn ipv6_host_is_bracketed() {
        let mut ipv6 = config(None, None);
        ipv6.host = "::1".to_string();
        assert_eq!(proxy_url(&ipv6), "socks5h://[::1]:1080");
    }

    /// Live checks against a real proxy. Ignored by default (they need a
    /// reachable proxy and the internet); run them by hand against a test host:
    ///
    /// ```text
    /// VEYRA_TEST_PROXY_HOST=… VEYRA_TEST_PROXY_USER=… VEYRA_TEST_PROXY_PASSWORD=… \
    ///   cargo test --lib live_proxy -- --ignored --nocapture
    /// ```
    ///
    /// This is what proves the SOCKS5/CONNECT handshakes and the error
    /// classification against reality rather than against our assumptions.
    mod live {
        use super::*;

        const TARGET: &str = "https://retired.example/mailbox";
        /// A node this test proxy provably cannot route to — the check must
        /// fall through to a working one instead of blaming the proxy.
        const BLOCKED_TARGET: &str = "https://beta.example/mailbox";

        fn live_config(kind: ProxyKind, port: u16, password: Option<&str>) -> Option<ProxyConfig> {
            let host = std::env::var("VEYRA_TEST_PROXY_HOST").ok()?;
            let username = std::env::var("VEYRA_TEST_PROXY_USER").ok();
            let stored = std::env::var("VEYRA_TEST_PROXY_PASSWORD").ok();
            Some(ProxyConfig {
                id: "live".to_string(),
                label: "live".to_string(),
                kind,
                host,
                port,
                username,
                password: password.map(str::to_string).or(stored),
            })
        }

        #[test]
        #[ignore = "needs a live proxy: see the module docs"]
        fn socks5_and_connect_reach_a_real_node() {
            for (kind, port) in [(ProxyKind::Socks5, 41080), (ProxyKind::HttpConnect, 43128)] {
                let Some(config) = live_config(kind, port, None) else {
                    eprintln!("VEYRA_TEST_PROXY_HOST unset — skipping");
                    return;
                };
                let result = test_config(&config, &[TARGET.to_string()]);
                eprintln!("{:?} -> {result:?}", kind.as_wire());
                assert!(
                    result.ok,
                    "{} must reach the node: {result:?}",
                    kind.as_wire()
                );
                assert!(result.proxy_reached && result.target_reached);
            }
        }

        /// The 2026-07-25 field bug: the check aimed at one node the proxy
        /// had no route to and reported «прокси не ответил вовремя» for a
        /// perfectly working proxy.
        #[test]
        #[ignore = "needs a live proxy: see the module docs"]
        fn an_unroutable_target_does_not_condemn_a_working_proxy() {
            let Some(config) = live_config(ProxyKind::Socks5, 41080, None) else {
                eprintln!("VEYRA_TEST_PROXY_HOST unset — skipping");
                return;
            };
            let targets = vec![BLOCKED_TARGET.to_string(), TARGET.to_string()];
            let result = test_config(&config, &targets);
            eprintln!("blocked-then-working -> {result:?}");
            assert!(
                result.ok,
                "one unroutable target must not fail the whole check: {result:?}"
            );
        }

        /// What the app actually does now: probe the real internet, never our
        /// own nodes. Must pass even when every Veyra node is unreachable.
        #[test]
        #[ignore = "needs a live proxy: see the module docs"]
        fn real_probe_targets_answer_through_the_proxy() {
            for (kind, port) in [(ProxyKind::Socks5, 41080), (ProxyKind::HttpConnect, 43128)] {
                let Some(config) = live_config(kind, port, None) else {
                    eprintln!("VEYRA_TEST_PROXY_HOST unset — skipping");
                    return;
                };
                let result = test_config(&config, &probe_targets());
                eprintln!("{} probe -> {result:?}", kind.as_wire());
                assert!(result.ok, "{} probe failed: {result:?}", kind.as_wire());
            }
        }

        #[test]
        #[ignore = "needs a live proxy: see the module docs"]
        fn wrong_password_and_dead_port_are_classified() {
            for (kind, port) in [(ProxyKind::Socks5, 41080), (ProxyKind::HttpConnect, 43128)] {
                let Some(config) = live_config(kind, port, Some("definitely-wrong")) else {
                    eprintln!("VEYRA_TEST_PROXY_HOST unset — skipping");
                    return;
                };
                let result = test_config(&config, &[TARGET.to_string()]);
                eprintln!("{} wrong password -> {result:?}", kind.as_wire());
                assert!(!result.ok);
                assert_eq!(
                    result.error_code.as_deref(),
                    Some(ERR_AUTH_FAILED),
                    "a wrong password must not read as «check the address»"
                );
                assert!(
                    result.proxy_reached,
                    "the proxy did answer — it rejected us"
                );
            }
            let Some(dead) = live_config(ProxyKind::Socks5, 1, None) else {
                return;
            };
            let result = test_config(&dead, &[TARGET.to_string()]);
            eprintln!("dead port -> {result:?}");
            assert!(!result.ok);
            assert!(!result.proxy_reached);
            assert_eq!(result.error_code.as_deref(), Some(ERR_UNREACHABLE));
        }
    }

    #[test]
    fn probe_targets_are_https_443_and_rotate() {
        // Everything a tunnel can carry: no UDP (NTP/plain DNS) and no odd
        // ports, because CONNECT proxies routinely allow 443 only.
        for target in PROBE_TARGETS {
            assert!(target.starts_with("https://"), "{target} must be HTTPS");
            let authority = target.trim_start_matches("https://").trim_end_matches('/');
            assert!(
                !authority.contains(':'),
                "{target} must use the default 443"
            );
        }
        assert!(PROBE_TARGETS.len() >= 10, "keep a wide spread of fallbacks");

        let batch = probe_targets();
        assert_eq!(batch.len(), MAX_TEST_TARGETS);
        // No repeats inside one batch — four attempts, four different hosts.
        for index in 1..batch.len() {
            assert!(
                !batch[..index].contains(&batch[index]),
                "duplicate: {batch:?}"
            );
        }
        // Rotation actually rotates: over many batches more than one host
        // takes the first slot.
        let first: std::collections::HashSet<String> =
            (0..40).map(|_| probe_targets()[0].clone()).collect();
        assert!(first.len() > 1, "the probe always starts at the same host");
    }

    /// The exact `source()` chains a live microsocks (SOCKS5) and squid
    /// (HTTP CONNECT) produced on 2026-07-25. Before this, everything fell
    /// through to «прокси не отвечает, проверьте адрес и порт» — telling
    /// someone with a wrong password to check the address.
    #[test]
    fn real_proxy_error_chains_are_classified() {
        let cases = [
            (
                "error sending request for url (https://retired.example/mailbox)\n\
                 client error (Connect)\nerror connecting to socks proxy\n\
                 SOCKS error: credentials not accepted\n",
                ERR_AUTH_FAILED,
            ),
            (
                "error sending request for url (https://retired.example/mailbox)\n\
                 client error (Connect)\ntunnel error: proxy authorization required\n",
                ERR_AUTH_FAILED,
            ),
            (
                "error sending request for url (https://retired.example/mailbox)\n\
                 client error (Connect)\nerror connecting to socks proxy\n\
                 SOCKS error: failed to create underlying connection\n",
                ERR_UNREACHABLE,
            ),
            (
                "client error (Connect)\ntunnel error: unsuccessful tunnel (403)\n",
                ERR_CONNECT_DENIED,
            ),
        ];
        for (chain, expected) in cases {
            assert_eq!(classify_chain_text(chain), expected, "chain: {chain}");
        }
    }

    // Rewritten 2026-07-27 from the field log. The old contract — two
    // `note_failure` calls, no matter how close together, means "down" — was
    // exactly the defect: the mailbox HTTPS pool fails in parallel, so one bad
    // moment arrived as two failures microseconds apart and raised a dialog
    // while the proxy was carrying traffic (117 failures against 876 successes
    // in that log, 18 dialogs).
    #[test]
    fn health_needs_a_sustained_run_a_probe_and_a_fresh_outage() {
        // A run only counts when it is spread over real time.
        assert!(!failure_run_is_sustained(1, MIN_FAILURE_SPAN));
        assert!(!failure_run_is_sustained(
            FAILURES_BEFORE_DOWN,
            Duration::from_millis(1)
        ));
        assert!(failure_run_is_sustained(
            FAILURES_BEFORE_DOWN,
            MIN_FAILURE_SPAN
        ));

        // One outage, one dialog: a flap inside the cooldown is the same one.
        assert!(outage_is_new(None));
        assert!(!outage_is_new(Some(Duration::from_secs(1))));
        assert!(outage_is_new(Some(OUTAGE_COOLDOWN)));

        set_active(Some(Arc::new(config(None, None))));
        assert_eq!(health().0, HealthState::Checking);
        let outage_before = health().2;

        // The parallel-failure burst from the field log: same instant, no
        // verdict, nothing shown.
        note_failure(ERR_TIMEOUT);
        note_failure(ERR_TIMEOUT);
        assert_eq!(health().0, HealthState::Checking);
        assert_eq!(health().2, outage_before);

        // A sustained run asks the probe; the probe getting through means the
        // failures belonged to the node we were talking to, not the proxy.
        let epoch = begin_verification_for_test();
        finish_verification(epoch, None);
        assert_eq!(health().0, HealthState::Online);
        assert_eq!(health().1, None);
        assert_eq!(health().2, outage_before);

        // The probe failing is the only thing that condemns the proxy.
        let epoch = begin_verification_for_test();
        finish_verification(epoch, Some(ERR_UNREACHABLE.to_string()));
        assert_eq!(health().0, HealthState::Down);
        assert_eq!(health().1.as_deref(), Some(ERR_UNREACHABLE));
        assert_eq!(health().2, outage_before + 1);

        // Recovery, then a second confirmed failure inside the cooldown: still
        // the same outage id, so the dialog the user dismissed stays dismissed.
        note_success();
        assert_eq!(health().0, HealthState::Online);
        let epoch = begin_verification_for_test();
        finish_verification(epoch, Some(ERR_TIMEOUT.to_string()));
        assert_eq!(health().0, HealthState::Down);
        assert_eq!(health().2, outage_before + 1);

        // A verdict that lands after a success describes a state we have left.
        note_success();
        finish_verification(epoch, Some(ERR_TIMEOUT.to_string()));
        assert_eq!(health().0, HealthState::Online);

        set_active(None);
        assert_eq!(health().0, HealthState::Off);
        // With proxy mode off, failures of direct requests never flip state.
        note_failure(ERR_TIMEOUT);
        assert_eq!(health().0, HealthState::Off);
    }

    /// Puts the health tracker in the state `note_failure` reaches after a
    /// sustained run, without waiting `MIN_FAILURE_SPAN` for real.
    fn begin_verification_for_test() -> u64 {
        let mut health = HEALTH.write().unwrap();
        health.consecutive_failures = FAILURES_BEFORE_DOWN;
        health.first_failure_at = Some(Instant::now() - MIN_FAILURE_SPAN);
        health.verifying = true;
        health.epoch
    }
}
