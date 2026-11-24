//! Proxy CONNECT dialer (proxy transport, slice B).
//!
//! Opens a TCP tunnel to `host:port` through the configured proxy and hands
//! back the raw stream. Everything above it — TLS/WSS, Noise, Yamux — is
//! unchanged and runs inside the tunnel exactly as it does on a direct
//! connection.
//!
//! Both handshakes are written out by hand rather than pulled from a crate:
//! they are short, fully specified (RFC 1928 / 1929 for SOCKS5, one request
//! line for HTTP CONNECT), and doing it here keeps the target hostname in our
//! own control — it must reach the proxy as a *name*, never as an address we
//! resolved locally, or proxy mode would leak DNS.

use std::io;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::models::proxy::ProxyKind;
use crate::p2p::proxy::{
    ERR_AUTH_FAILED, ERR_CONNECT_DENIED, ERR_PROTOCOL, ERR_TIMEOUT, ERR_UNREACHABLE,
};
use crate::storage::proxies::ProxyConfig;

/// The proxy answered but refused; or never answered at all. Carries one of
/// the normalized `proxy::ERR_*` codes so the UI wording stays identical to
/// the HTTPS plane's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyDialError {
    pub code: &'static str,
}

impl ProxyDialError {
    fn new(code: &'static str) -> Self {
        Self { code }
    }
}

impl std::fmt::Display for ProxyDialError {
    /// Only the code — never the host, never credentials.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.code)
    }
}

impl std::error::Error for ProxyDialError {}

impl From<ProxyDialError> for io::Error {
    fn from(error: ProxyDialError) -> Self {
        io::Error::other(error)
    }
}

/// Longest CONNECT response we will read before giving up — a proxy that
/// wants to stream us a body is not a proxy we tunnel through.
const MAX_CONNECT_RESPONSE: usize = 8 * 1024;

/// Dials `host:port` through `config`. `host` is passed to the proxy as
/// given: a hostname stays a hostname (remote DNS), an IP literal stays an IP.
pub async fn dial_through_proxy(
    config: &ProxyConfig,
    host: &str,
    port: u16,
) -> Result<TcpStream, ProxyDialError> {
    // The proxy address is the only name this side is allowed to resolve.
    let stream = TcpStream::connect((config.host.as_str(), config.port))
        .await
        .map_err(|error| {
            ProxyDialError::new(match error.kind() {
                io::ErrorKind::TimedOut => ERR_TIMEOUT,
                _ => ERR_UNREACHABLE,
            })
        })?;
    // Interactive protocol on top: Nagle would sit on our small handshake
    // writes waiting for more data.
    let _ = stream.set_nodelay(true);
    match config.kind {
        ProxyKind::Socks5 => socks5_connect(stream, config, host, port).await,
        ProxyKind::HttpConnect => http_connect(stream, config, host, port).await,
    }
}

fn io_failed(error: io::Error) -> ProxyDialError {
    ProxyDialError::new(match error.kind() {
        io::ErrorKind::TimedOut => ERR_TIMEOUT,
        io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset => ERR_PROTOCOL,
        _ => ERR_PROTOCOL,
    })
}

/// RFC 1928 CONNECT, with RFC 1929 username/password when configured.
async fn socks5_connect(
    mut stream: TcpStream,
    config: &ProxyConfig,
    host: &str,
    port: u16,
) -> Result<TcpStream, ProxyDialError> {
    const VERSION: u8 = 0x05;
    const METHOD_NONE: u8 = 0x00;
    const METHOD_USER_PASS: u8 = 0x02;
    const METHOD_UNACCEPTABLE: u8 = 0xFF;

    let has_auth = config.username.is_some();
    let greeting: Vec<u8> = if has_auth {
        vec![VERSION, 2, METHOD_NONE, METHOD_USER_PASS]
    } else {
        vec![VERSION, 1, METHOD_NONE]
    };
    stream.write_all(&greeting).await.map_err(io_failed)?;

    let mut choice = [0u8; 2];
    stream.read_exact(&mut choice).await.map_err(io_failed)?;
    if choice[0] != VERSION {
        return Err(ProxyDialError::new(ERR_PROTOCOL));
    }
    match choice[1] {
        METHOD_NONE => {}
        METHOD_USER_PASS => {
            let (Some(username), password) =
                (config.username.as_deref(), config.password.as_deref())
            else {
                // The proxy demands credentials we do not have.
                return Err(ProxyDialError::new(ERR_AUTH_FAILED));
            };
            socks5_authenticate(&mut stream, username, password.unwrap_or_default()).await?;
        }
        METHOD_UNACCEPTABLE => return Err(ProxyDialError::new(ERR_AUTH_FAILED)),
        _ => return Err(ProxyDialError::new(ERR_PROTOCOL)),
    }

    let mut request = vec![VERSION, 0x01, 0x00];
    request.extend_from_slice(&socks5_target(host)?);
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await.map_err(io_failed)?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.map_err(io_failed)?;
    if head[0] != VERSION {
        return Err(ProxyDialError::new(ERR_PROTOCOL));
    }
    if head[1] != 0x00 {
        return Err(ProxyDialError::new(socks5_reply_code(head[1])));
    }
    // Drain the bound address so the stream starts exactly at the tunnel.
    let bound_len = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.map_err(io_failed)?;
            usize::from(len[0])
        }
        _ => return Err(ProxyDialError::new(ERR_PROTOCOL)),
    };
    let mut bound = vec![0u8; bound_len + 2];
    stream.read_exact(&mut bound).await.map_err(io_failed)?;
    Ok(stream)
}

async fn socks5_authenticate(
    stream: &mut TcpStream,
    username: &str,
    password: &str,
) -> Result<(), ProxyDialError> {
    if username.len() > 255 || password.len() > 255 {
        return Err(ProxyDialError::new(ERR_AUTH_FAILED));
    }
    let mut request = vec![0x01, username.len() as u8];
    request.extend_from_slice(username.as_bytes());
    request.push(password.len() as u8);
    request.extend_from_slice(password.as_bytes());
    stream.write_all(&request).await.map_err(io_failed)?;

    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await.map_err(io_failed)?;
    // Sub-negotiation version is 1, and status 0 is the only success.
    if reply[1] != 0x00 {
        return Err(ProxyDialError::new(ERR_AUTH_FAILED));
    }
    Ok(())
}

/// Address block of a SOCKS5 request. A hostname is sent as ATYP=3 so the
/// proxy resolves it — the whole point of `socks5h`.
fn socks5_target(host: &str) -> Result<Vec<u8>, ProxyDialError> {
    if let Ok(address) = host.parse::<std::net::Ipv4Addr>() {
        let mut out = vec![0x01];
        out.extend_from_slice(&address.octets());
        return Ok(out);
    }
    if let Ok(address) = host.parse::<std::net::Ipv6Addr>() {
        let mut out = vec![0x04];
        out.extend_from_slice(&address.octets());
        return Ok(out);
    }
    if host.is_empty() || host.len() > 255 {
        return Err(ProxyDialError::new(ERR_PROTOCOL));
    }
    let mut out = vec![0x03, host.len() as u8];
    out.extend_from_slice(host.as_bytes());
    Ok(out)
}

/// RFC 1928 §6 reply codes, mapped to the wording the user already sees for
/// the HTTPS plane.
fn socks5_reply_code(reply: u8) -> &'static str {
    match reply {
        0x02 => ERR_CONNECT_DENIED, // connection not allowed by ruleset
        0x03 | 0x04 | 0x05 => ERR_UNREACHABLE, // network/host unreachable, refused
        0x06 => ERR_TIMEOUT,        // TTL expired
        0x07 | 0x08 => ERR_PROTOCOL, // command / address type not supported
        _ => ERR_PROTOCOL,
    }
}

/// HTTP CONNECT with optional Basic auth.
async fn http_connect(
    mut stream: TcpStream,
    config: &ProxyConfig,
    host: &str,
    port: u16,
) -> Result<TcpStream, ProxyDialError> {
    // Bracket IPv6 literals in the request line, as the URI grammar requires.
    let authority = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some(username) = config.username.as_deref() {
        let token = B64.encode(format!(
            "{username}:{}",
            config.password.as_deref().unwrap_or_default()
        ));
        request.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    request.push_str("Proxy-Connection: keep-alive\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(io_failed)?;

    // Read exactly up to the end of the header block: whatever follows is
    // already tunnel payload and must stay in the stream.
    let mut buffer = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        let read = stream.read(&mut byte).await.map_err(io_failed)?;
        if read == 0 {
            return Err(ProxyDialError::new(ERR_PROTOCOL));
        }
        buffer.push(byte[0]);
        if buffer.ends_with(b"\r\n\r\n") {
            break;
        }
        if buffer.len() > MAX_CONNECT_RESPONSE {
            return Err(ProxyDialError::new(ERR_PROTOCOL));
        }
    }
    match connect_status(&buffer) {
        Some(200) => Ok(stream),
        Some(407) => Err(ProxyDialError::new(ERR_AUTH_FAILED)),
        Some(403) | Some(405) => Err(ProxyDialError::new(ERR_CONNECT_DENIED)),
        Some(502..=504) => Err(ProxyDialError::new(ERR_UNREACHABLE)),
        Some(_) => Err(ProxyDialError::new(ERR_CONNECT_DENIED)),
        None => Err(ProxyDialError::new(ERR_PROTOCOL)),
    }
}

/// Status code of `HTTP/1.x NNN …`. Anything else is not a proxy talking.
fn connect_status(response: &[u8]) -> Option<u16> {
    let head = response.split(|byte| *byte == b'\n').next()?;
    let head = std::str::from_utf8(head).ok()?;
    let mut parts = head.split_whitespace();
    let version = parts.next()?;
    if !version.starts_with("HTTP/1.") {
        return None;
    }
    parts.next()?.parse::<u16>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostnames_are_sent_for_remote_resolution() {
        // ATYP=3 + length + bytes: the proxy resolves it, we never do.
        let target = socks5_target("retired.example").expect("hostname");
        assert_eq!(target[0], 0x03);
        assert_eq!(usize::from(target[1]), "retired.example".len());
        assert_eq!(&target[2..], b"retired.example");
    }

    #[test]
    fn ip_literals_keep_their_native_address_types() {
        let v4 = socks5_target("10.8.0.1").expect("ipv4");
        assert_eq!(v4, vec![0x01, 10, 8, 0, 1]);
        let v6 = socks5_target("::1").expect("ipv6");
        assert_eq!(v6[0], 0x04);
        assert_eq!(v6.len(), 17);
        assert!(socks5_target("").is_err());
        assert!(socks5_target(&"a".repeat(256)).is_err());
    }

    #[test]
    fn socks5_replies_map_to_user_facing_codes() {
        assert_eq!(socks5_reply_code(0x02), ERR_CONNECT_DENIED);
        assert_eq!(socks5_reply_code(0x03), ERR_UNREACHABLE);
        assert_eq!(socks5_reply_code(0x06), ERR_TIMEOUT);
        assert_eq!(socks5_reply_code(0x07), ERR_PROTOCOL);
    }

    #[test]
    fn connect_status_parsing() {
        assert_eq!(
            connect_status(b"HTTP/1.1 200 Connection established\r\n\r\n"),
            Some(200)
        );
        assert_eq!(
            connect_status(b"HTTP/1.0 407 Proxy Authentication Required\r\n\r\n"),
            Some(407)
        );
        assert_eq!(connect_status(b"gibberish\r\n\r\n"), None);
        assert_eq!(connect_status(b""), None);
    }

    /// Live handshakes against a real proxy pair. Same env vars and the same
    /// `-- --ignored` invocation as `p2p::proxy::tests::live`.
    mod live {
        use super::*;
        use crate::models::proxy::ProxyKind;
        use crate::storage::proxies::ProxyConfig;

        fn live_config(kind: ProxyKind, port: u16, password: Option<&str>) -> Option<ProxyConfig> {
            let host = std::env::var("VEYRA_TEST_PROXY_HOST").ok()?;
            Some(ProxyConfig {
                id: "live".to_string(),
                label: "live".to_string(),
                kind,
                host,
                port,
                username: std::env::var("VEYRA_TEST_PROXY_USER").ok(),
                password: password
                    .map(str::to_string)
                    .or_else(|| std::env::var("VEYRA_TEST_PROXY_PASSWORD").ok()),
            })
        }

        #[tokio::test]
        #[ignore = "needs a live proxy: see p2p::proxy::tests::live"]
        async fn socks5_and_connect_open_a_real_tunnel() {
            for (kind, port) in [(ProxyKind::Socks5, 41080), (ProxyKind::HttpConnect, 43128)] {
                let Some(config) = live_config(kind, port, None) else {
                    eprintln!("VEYRA_TEST_PROXY_HOST unset — skipping");
                    return;
                };
                // Getting here means the proxy accepted our greeting, our
                // credentials and a CONNECT to a remotely resolved hostname,
                // and handed the tunnel over.
                dial_through_proxy(&config, "example.com", 443)
                    .await
                    .unwrap_or_else(|error| panic!("{} tunnel failed: {error}", kind.as_wire()));
                eprintln!("{} tunnel to example.com:443 open", kind.as_wire());
            }
        }

        /// Bytes actually flow — a completed handshake is not by itself proof
        /// that the stream is wired to the target. Plain HTTP on :80 so the
        /// answer is readable without TLS; squid is restricted to :443, so
        /// this one runs over SOCKS5.
        #[tokio::test]
        #[ignore = "needs a live proxy: see p2p::proxy::tests::live"]
        async fn the_socks5_tunnel_carries_real_traffic() {
            let Some(config) = live_config(ProxyKind::Socks5, 41080, None) else {
                return;
            };
            let mut stream = dial_through_proxy(&config, "example.com", 80)
                .await
                .expect("tunnel to example.com:80");
            stream
                .write_all(
                    b"HEAD / HTTP/1.1
Host: example.com
Connection: close

",
                )
                .await
                .expect("write through the tunnel");
            let mut buffer = [0u8; 12];
            stream
                .read_exact(&mut buffer)
                .await
                .expect("read through the tunnel");
            let head = String::from_utf8_lossy(&buffer);
            eprintln!("tunnel answered: {head}");
            assert!(head.starts_with("HTTP/1."), "unexpected answer: {head}");
        }

        #[tokio::test]
        #[ignore = "needs a live proxy: see p2p::proxy::tests::live"]
        async fn wrong_password_is_rejected_by_both_protocols() {
            for (kind, port) in [(ProxyKind::Socks5, 41080), (ProxyKind::HttpConnect, 43128)] {
                let Some(config) = live_config(kind, port, Some("definitely-wrong")) else {
                    return;
                };
                let error = dial_through_proxy(&config, "example.com", 443)
                    .await
                    .expect_err("a wrong password must not open a tunnel");
                eprintln!("{} wrong password -> {error}", kind.as_wire());
                assert_eq!(error.code, ERR_AUTH_FAILED);
            }
        }

        #[tokio::test]
        #[ignore = "needs a live proxy: see p2p::proxy::tests::live"]
        async fn a_forbidden_port_is_reported_as_denied_not_as_a_dead_proxy() {
            // squid allows CONNECT to 443 only — the honest answer is «the
            // proxy refused this target», not «the proxy is down».
            let Some(config) = live_config(ProxyKind::HttpConnect, 43128, None) else {
                return;
            };
            let error = dial_through_proxy(&config, "example.com", 8080)
                .await
                .expect_err("squid must refuse a non-443 CONNECT");
            eprintln!("forbidden port -> {error}");
            assert_eq!(error.code, ERR_CONNECT_DENIED);
        }
    }

    #[test]
    fn dial_errors_never_render_host_or_credentials() {
        let error = ProxyDialError::new(ERR_AUTH_FAILED);
        assert_eq!(error.to_string(), "proxy_auth_failed");
        assert_eq!(
            format!("{error:?}"),
            "ProxyDialError { code: \"proxy_auth_failed\" }"
        );
    }
}
