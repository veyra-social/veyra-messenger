use serde::{Deserialize, Serialize};

/// Supported proxy protocols. SOCKS5 always resolves the target hostname on
/// the proxy side (no local DNS lookup); HTTP CONNECT gets the original
/// hostname in the request line for the same reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyKind {
    Socks5,
    HttpConnect,
}

impl ProxyKind {
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::Socks5 => "socks5",
            Self::HttpConnect => "http_connect",
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "socks5" => Some(Self::Socks5),
            "http_connect" => Some(Self::HttpConnect),
            _ => None,
        }
    }
}

/// A saved proxy as shown in the UI. The password is never part of this view —
/// only whether one is stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyView {
    pub id: String,
    pub label: String,
    pub kind: String,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub has_password: bool,
    /// True for the proxy selected as active (used when proxy mode is on).
    pub is_active: bool,
    pub created_at: String,
    pub updated_at: String,
    pub last_test_at: Option<String>,
    pub last_test_ok: Option<bool>,
    pub last_error_code: Option<String>,
}

/// What the "add" / "edit" form sends. `password` semantics on edit:
/// `None` keeps the stored secret, `Some("")` clears it, `Some(value)`
/// replaces it. On add, `None`/`Some("")` both mean "no password".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyInput {
    pub label: String,
    pub kind: String,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// Outcome of one proxy check. Never an error path: the UI shows a plain
/// sentence per `error_code`, so a failed check reads as information rather
/// than as a crash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyTestResult {
    pub ok: bool,
    /// The proxy itself answered the SOCKS/CONNECT handshake.
    pub proxy_reached: bool,
    /// The tunnel to the target endpoint was established (TLS included).
    pub target_reached: bool,
    pub latency_ms: Option<u64>,
    pub error_code: Option<String>,
}

/// Proxy mode state for the UI: whether it is on, which proxy is active and
/// how the last real network attempt went.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyStatus {
    pub enabled: bool,
    pub active_id: Option<String>,
    pub active_label: Option<String>,
    /// "off" | "checking" | "online" | "down"
    pub health: String,
    pub last_error_code: Option<String>,
    /// Incremented once per outage. The UI shows its single honest "the proxy
    /// is down" dialog per id and then keeps quiet — no repeated pop-ups.
    pub outage_id: u64,
}

/// What the UI gets back when it turns proxy mode on or switches proxies: the
/// check that was run, and the resulting state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyActivation {
    pub test: ProxyTestResult,
    pub status: ProxyStatus,
}
