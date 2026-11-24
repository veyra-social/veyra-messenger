//! Android interface watcher (Veyra vendored backend).
//!
//! Netlink route sockets are unusable inside an Android app process:
//! AOSP bans RTM_GETLINK (`nlmsg_readpriv`) for apps targeting SDK >= 30,
//! and vendor SELinux policies (field-verified on ASUS ZS590KS and
//! Samsung S938B, 2026-07-08) deny even `socket`/`bind`, which also kills
//! bionic `getifaddrs` — so both the upstream netlink backend and the
//! upstream getifaddrs fallback fail with EACCES here.
//!
//! Instead of enumerating interfaces, this backend resolves the device's
//! active source addresses with connected UDP sockets: `connect()` on a
//! UDP socket transmits nothing and only runs a kernel route lookup, and
//! `getsockname()` then exposes the source address the kernel picked
//! (Wi-Fi LAN address when Wi-Fi carries the default route). That needs
//! no permission beyond INTERNET and no SELinux exemptions. Loopback is
//! always reported, so consumers see at least one interface even with no
//! connectivity and address changes surface as `Up`/`Down` diffs on a
//! 10-second local re-probe (three syscalls; no traffic, no radio).
use crate::IfEvent;
use async_io::Timer;
use futures::stream::{FusedStream, Stream};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::collections::{HashSet, VecDeque};
use std::io::Result;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

#[cfg(feature = "tokio")]
pub mod tokio {
    //! An interface watcher.
    //! **On this platform there is no difference between `tokio` and `smol` features,**
    //! **this was done to maintain the api compatible with other platforms**.

    /// Watches for interface changes.
    pub type IfWatcher = super::IfWatcher;
}

#[cfg(feature = "smol")]
pub mod smol {
    //! An interface watcher.
    //! **On this platform there is no difference between `tokio` and `smol` features,**
    //! **this was done to maintain the api compatible with other platforms**.

    /// Watches for interface changes.
    pub type IfWatcher = super::IfWatcher;
}

/// An address set/watcher
#[derive(Debug)]
pub struct IfWatcher {
    addrs: HashSet<IpNet>,
    queue: VecDeque<IfEvent>,
    ticker: Timer,
}

impl IfWatcher {
    /// Create a watcher.
    pub fn new() -> Result<Self> {
        Ok(Self {
            addrs: Default::default(),
            queue: Default::default(),
            ticker: Timer::interval_at(Instant::now(), Duration::from_secs(10)),
        })
    }

    fn resync(&mut self) {
        let current = current_addrs();
        for old_addr in self.addrs.clone() {
            if !current.contains(&old_addr) {
                self.addrs.remove(&old_addr);
                self.queue.push_back(IfEvent::Down(old_addr));
            }
        }
        for new_addr in current {
            if self.addrs.insert(new_addr) {
                self.queue.push_back(IfEvent::Up(new_addr));
            }
        }
    }

    /// Iterate over current networks.
    pub fn iter(&self) -> impl Iterator<Item = &IpNet> {
        self.addrs.iter()
    }

    /// Poll for an address change event.
    pub fn poll_if_event(&mut self, cx: &mut Context) -> Poll<Result<IfEvent>> {
        loop {
            if let Some(event) = self.queue.pop_front() {
                return Poll::Ready(Ok(event));
            }
            if Pin::new(&mut self.ticker).poll_next(cx).is_pending() {
                return Poll::Pending;
            }
            self.resync();
        }
    }
}

impl Stream for IfWatcher {
    type Item = Result<IfEvent>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::into_inner(self).poll_if_event(cx).map(Some)
    }
}

impl FusedStream for IfWatcher {
    fn is_terminated(&self) -> bool {
        false
    }
}

fn current_addrs() -> HashSet<IpNet> {
    let mut addrs = HashSet::new();
    addrs.insert(IpNet::V4(
        Ipv4Net::new(Ipv4Addr::LOCALHOST, 8).expect("loopback prefix is valid"),
    ));
    if let Some(ip) = default_route_source_v4() {
        addrs.insert(IpNet::V4(
            Ipv4Net::new(ip, 32).expect("/32 is a valid IPv4 prefix"),
        ));
    }
    if let Some(ip) = default_route_source_v6() {
        addrs.insert(IpNet::V6(
            Ipv6Net::new(ip, 128).expect("/128 is a valid IPv6 prefix"),
        ));
    }
    addrs
}

/// Source address the kernel picks for outbound IPv4. Connected UDP
/// sockets never transmit; `connect()` only resolves a route. The second
/// target covers LAN-only networks without a default route: the mDNS
/// multicast group still resolves through the LAN interface.
fn default_route_source_v4() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    for target in [
        (Ipv4Addr::new(8, 8, 8, 8), 53u16),
        (Ipv4Addr::new(224, 0, 0, 251), 5353u16),
    ] {
        if socket.connect(target).is_err() {
            continue;
        }
        if let Ok(SocketAddr::V4(local)) = socket.local_addr() {
            let ip = *local.ip();
            if !ip.is_unspecified() && !ip.is_loopback() {
                return Some(ip);
            }
        }
    }
    None
}

/// Source address the kernel picks for outbound IPv6, if any.
fn default_route_source_v6() -> Option<Ipv6Addr> {
    let socket = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)).ok()?;
    socket
        .connect((Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888), 53))
        .ok()?;
    match socket.local_addr() {
        Ok(SocketAddr::V6(local)) => {
            let ip = *local.ip();
            (!ip.is_unspecified() && !ip.is_loopback()).then_some(ip)
        }
        _ => None,
    }
}
