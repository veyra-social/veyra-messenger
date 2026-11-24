//! libp2p transport that dials through the configured proxy (slice B).
//!
//! Dial-only by design: a proxied client has no inbound path, so `listen_on`
//! is refused rather than faked. Everything the swarm layers on top — TLS/WSS,
//! Noise, Yamux — is untouched and runs inside the tunnel, which is what keeps
//! PeerId verification, the certificate check against the node's own domain
//! and the wire formats exactly as they are on a direct connection.

use std::pin::Pin;
use std::task::{Context, Poll};

use futures::future::BoxFuture;
use futures::FutureExt;
use libp2p::core::transport::{DialOpts, ListenerId, TransportError, TransportEvent};
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, Transport};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};

use crate::p2p::proxy_dial::{dial_through_proxy, ProxyDialError};
use crate::storage::proxies::ProxyConfig;

/// `host:port` extracted from a TCP-carrying multiaddr, in the form the proxy
/// needs: a `/dns*` address stays a name so the proxy resolves it.
fn target_of(address: &Multiaddr) -> Option<(String, u16)> {
    let mut host = None;
    let mut port = None;
    for protocol in address.iter() {
        match protocol {
            Protocol::Dns(name) | Protocol::Dns4(name) | Protocol::Dns6(name) => {
                host = Some(name.to_string());
            }
            Protocol::Ip4(addr) => host = Some(addr.to_string()),
            Protocol::Ip6(addr) => host = Some(addr.to_string()),
            Protocol::Tcp(value) => port = Some(value),
            // A tunnel carries TCP only: QUIC and anything else UDP-based
            // cannot cross SOCKS5 CONNECT or HTTP CONNECT.
            Protocol::Udp(_) | Protocol::QuicV1 | Protocol::Quic => return None,
            _ => {}
        }
    }
    Some((host?, port?))
}

/// True for addresses this transport dials itself: plain TCP, no circuit hop,
/// and no WebSocket layer.
///
/// WSS is *not* handled here even though it rides on TCP: `WsConfig` wraps
/// this transport and needs to see those addresses itself, so that TLS is
/// negotiated with the node's own domain inside the tunnel. Dialing them raw
/// would open a TCP tunnel and then speak the wrong protocol into it.
pub fn is_proxyable(address: &Multiaddr) -> bool {
    if address.iter().any(|protocol| {
        matches!(
            protocol,
            Protocol::P2pCircuit | Protocol::Ws(_) | Protocol::Wss(_) | Protocol::Tls
        )
    }) {
        return false;
    }
    target_of(address).is_some()
}

/// Is this address on a network we can reach without leaving the building?
///
/// Used to keep same-network peers working while proxy mode is on: LAN
/// traffic never reaches the ISP or the proxy operator, so cutting it would
/// only break «Работать локально» without buying any privacy. Everything that
/// is not provably local goes through the tunnel or does not go at all.
///
/// Carrier-grade NAT space (100.64/10) is deliberately *not* local: those
/// addresses live in the operator's network, not on your Wi-Fi.
pub fn is_lan_address(address: &Multiaddr) -> bool {
    for protocol in address.iter() {
        match protocol {
            Protocol::Ip4(addr) => {
                return addr.is_private() || addr.is_link_local() || addr.is_loopback();
            }
            Protocol::Ip6(addr) => {
                let segments = addr.segments();
                let link_local = segments[0] & 0xffc0 == 0xfe80;
                let unique_local = segments[0] & 0xfe00 == 0xfc00;
                return link_local || unique_local || addr.is_loopback();
            }
            // mDNS hands out `.local` names; anything else resolvable is not
            // something we can prove is on this network.
            Protocol::Dns(name) | Protocol::Dns4(name) | Protocol::Dns6(name) => {
                return name.ends_with(".local") || name.as_ref() == "localhost";
            }
            _ => {}
        }
    }
    false
}

/// Wraps the direct TCP transport so that, with proxy mode on, it dials only
/// addresses on this network. Anything else is refused with
/// `MultiaddrNotSupported`, which makes `OrTransport` fall through to the
/// proxied branch — that is the whole of "fail-closed" in one place: there is
/// no direct path to the internet left to fall back on.
#[derive(Clone)]
pub struct LanOnly<T> {
    inner: T,
}

impl<T> LanOnly<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T> Transport for LanOnly<T>
where
    T: Transport + Unpin,
{
    type Output = T::Output;
    type Error = T::Error;
    type ListenerUpgrade = T::ListenerUpgrade;
    type Dial = T::Dial;

    fn listen_on(
        &mut self,
        id: ListenerId,
        address: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        self.inner.listen_on(id, address)
    }

    fn remove_listener(&mut self, id: ListenerId) -> bool {
        self.inner.remove_listener(id)
    }

    fn dial(
        &mut self,
        address: Multiaddr,
        opts: DialOpts,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        if !is_lan_address(&address) {
            return Err(TransportError::MultiaddrNotSupported(address));
        }
        self.inner.dial(address, opts)
    }

    /// Also the gate for what the swarm is allowed to *know* about itself.
    ///
    /// A listener bound to `0.0.0.0` reports every interface address, and
    /// `identify` then hands that list to every peer we talk to — including
    /// the ones we reached through the tunnel, which would tell them our real
    /// address and undo the whole point of proxy mode. Non-LAN listen
    /// addresses are therefore swallowed here: the swarm never learns them,
    /// so nothing can advertise them.
    ///
    /// Inbound connections from outside the LAN are dropped for the matching
    /// reason: accepting one would carry our traffic on a direct path that
    /// never touched the proxy.
    fn poll(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        let inner = &mut self.get_mut().inner;
        loop {
            let event = match Pin::new(&mut *inner).poll(cx) {
                Poll::Ready(event) => event,
                Poll::Pending => return Poll::Pending,
            };
            match &event {
                TransportEvent::NewAddress { listen_addr, .. }
                | TransportEvent::AddressExpired { listen_addr, .. } => {
                    if !is_lan_address(listen_addr) {
                        tracing::debug!(
                            address = %listen_addr,
                            "listen address hidden: proxy mode advertises LAN only"
                        );
                        continue;
                    }
                }
                TransportEvent::Incoming { send_back_addr, .. } => {
                    if !is_lan_address(send_back_addr) {
                        tracing::debug!("inbound connection refused: proxy mode accepts LAN only");
                        continue;
                    }
                }
                _ => {}
            }
            return Poll::Ready(event);
        }
    }
}

#[derive(Clone)]
pub struct ProxyTransport {
    config: std::sync::Arc<ProxyConfig>,
}

impl ProxyTransport {
    pub fn new(config: std::sync::Arc<ProxyConfig>) -> Self {
        Self { config }
    }
}

impl Transport for ProxyTransport {
    type Output = Compat<tokio::net::TcpStream>;
    type Error = ProxyDialError;
    type ListenerUpgrade = BoxFuture<'static, Result<Self::Output, Self::Error>>;
    type Dial = BoxFuture<'static, Result<Self::Output, Self::Error>>;

    /// A proxied client never listens: the tunnel is outbound only, and
    /// pretending otherwise would advertise addresses nobody can reach.
    fn listen_on(
        &mut self,
        _id: ListenerId,
        address: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        Err(TransportError::MultiaddrNotSupported(address))
    }

    fn remove_listener(&mut self, _id: ListenerId) -> bool {
        false
    }

    fn dial(
        &mut self,
        address: Multiaddr,
        _opts: DialOpts,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        if !is_proxyable(&address) {
            return Err(TransportError::MultiaddrNotSupported(address));
        }
        let Some((host, port)) = target_of(&address) else {
            return Err(TransportError::MultiaddrNotSupported(address));
        };
        let config = self.config.clone();
        Ok(async move {
            let stream = dial_through_proxy(&config, &host, port).await?;
            Ok(stream.compat())
        }
        .boxed())
    }

    fn poll(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        // No listeners, so there is never anything to report.
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(value: &str) -> Multiaddr {
        value.parse().expect("valid multiaddr")
    }

    #[test]
    fn tcp_and_wss_addresses_are_dialable_names_or_ips() {
        let (host, port) = target_of(&addr("/dns4/retired.example/tcp/443/tls/ws")).unwrap();
        // A name must stay a name: resolving it here would leak DNS.
        assert_eq!((host.as_str(), port), ("retired.example", 443));

        let (host, port) = target_of(&addr("/ip4/10.8.0.1/tcp/4001")).unwrap();
        assert_eq!((host.as_str(), port), ("10.8.0.1", 4001));

        let (host, port) = target_of(&addr("/ip6/::1/tcp/4001")).unwrap();
        assert_eq!((host.as_str(), port), ("::1", 4001));
    }

    #[test]
    fn udp_based_and_relayed_addresses_are_refused() {
        // QUIC cannot cross a CONNECT tunnel.
        assert!(!is_proxyable(&addr("/ip4/1.2.3.4/udp/4001/quic-v1")));
        assert!(!is_proxyable(&addr(
            "/dns4/retired.example/udp/443/quic-v1"
        )));
        // Circuit addresses belong to the relay client; its own uplink is the
        // connection that gets proxied.
        assert!(!is_proxyable(&addr(
            "/dns4/retired.example/tcp/443/p2p/12D3KooWD4v6SrzipGLX4d7xyYmfvMe6fJ3TQRJKykbqxNRrTVSm/p2p-circuit"
        )));
        // No port, nothing to dial.
        assert!(!is_proxyable(&addr("/dns4/retired.example")));
    }

    #[test]
    fn websocket_addresses_are_left_to_the_websocket_layer() {
        // Dialing these raw would open a tunnel and then speak plain libp2p
        // into a socket the far side expects TLS on.
        assert!(!is_proxyable(&addr(
            "/dns4/retired.example/tcp/443/tls/ws"
        )));
        assert!(!is_proxyable(&addr("/dns4/retired.example/tcp/443/wss")));
        // Plain TCP is ours.
        assert!(is_proxyable(&addr("/dns4/retired.example/tcp/4001")));
    }

    #[test]
    fn lan_detection_covers_the_private_ranges_and_nothing_else() {
        for local in [
            "/ip4/192.168.1.10/tcp/4001",
            "/ip4/10.8.0.1/tcp/4001",
            "/ip4/172.16.0.5/tcp/4001",
            "/ip4/169.254.3.4/tcp/4001", // link-local
            "/ip4/127.0.0.1/tcp/4001",
            "/ip6/fe80::1/tcp/4001", // link-local
            "/ip6/fd00::1/tcp/4001", // unique local
            "/ip6/::1/tcp/4001",     // loopback
            "/dns4/asus.local/tcp/4001",
        ] {
            assert!(is_lan_address(&addr(local)), "must be LAN: {local}");
        }
        for remote in [
            "/ip4/198.51.100.180/tcp/443",
            "/ip4/8.8.8.8/tcp/443",
            // Carrier-grade NAT is the operator's network, not ours.
            "/ip4/100.64.0.1/tcp/4001",
            "/ip6/2a01:4f9::1/tcp/4001",
            "/dns4/retired.example/tcp/443",
        ] {
            assert!(!is_lan_address(&addr(remote)), "must not be LAN: {remote}");
        }
    }
}
