//! The `Listener` core: owns a tun fd and an encrypted `Session`, and runs
//! the two firewall-gated forwarding tasks (tun→mesh, mesh→tun).

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Arc;

use ipnet::IpNet;
use nebula_firewall::{Firewall, FirewallOptions, RuleSet};
use nebula_protocol::session::Session;
use tokio::io::unix::AsyncFd;

use crate::{identity, packet};

/// Everything a `Listener` needs beyond its already-built `Session` and tun.
pub struct ListenerConfig {
    pub firewall_rules: RuleSet,
    pub firewall_options: FirewallOptions,
    /// This node's own assigned VPN addresses (full prefixes, as in the cert).
    pub assigned_networks: Vec<IpNet>,
    pub unsafe_networks: Vec<IpNet>,
    /// Fills `PeerIdentity.ca_name` for every peer (rules may scope on it).
    pub ca_name: String,
    /// Fills `PeerIdentity.ca_sha` for every peer.
    pub ca_sha: String,
}

struct Shared {
    session: Session,
    firewall: Firewall,
    ca_name: String,
    ca_sha: String,
    tun: AsyncFd<OwnedFd>,
}

pub struct Listener {
    shared: Arc<Shared>,
}

impl Listener {
    pub fn new(config: ListenerConfig, session: Session, tun: OwnedFd) -> io::Result<Self> {
        let firewall = Firewall::new(
            config.firewall_rules,
            config.firewall_options,
            config.assigned_networks,
            config.unsafe_networks,
        );
        // `AsyncFd` requires the wrapped fd to already be in non-blocking
        // mode (a raw blocking `read`/`write` on it would otherwise stall
        // this crate's single reactor thread forever once no data is
        // ready). The injected fd's *netns* is fixed at creation, but its
        // blocking mode isn't load-bearing for that, so the Listener sets
        // it here rather than pushing the requirement onto every caller.
        set_nonblocking(&tun)?;
        let tun = AsyncFd::new(tun)?;
        Ok(Self {
            shared: Arc::new(Shared {
                session,
                firewall,
                ca_name: config.ca_name,
                ca_sha: config.ca_sha,
                tun,
            }),
        })
    }

    /// Runs both forwarding directions until one of them errors. The tasks
    /// share the same `Arc<Shared>`; the tun fd is read by one and written
    /// by the other.
    pub async fn run(self) -> io::Result<()> {
        let up = tokio::spawn(tun_to_mesh(self.shared.clone()));
        let down = tokio::spawn(mesh_to_tun(self.shared.clone()));

        // If this future is dropped/aborted (e.g. its task is cancelled),
        // the spawned loops must not outlive it — they hold the tun fd and
        // Session via `Shared`, and callers rely on drop-based teardown.
        struct AbortOnDrop(tokio::task::AbortHandle);
        impl Drop for AbortOnDrop {
            fn drop(&mut self) {
                self.0.abort();
            }
        }
        let _up_guard = AbortOnDrop(up.abort_handle());
        let _down_guard = AbortOnDrop(down.abort_handle());

        tokio::select! {
            r = up => r.map_err(io::Error::other)?,
            r = down => r.map_err(io::Error::other)?,
        }
    }
}

fn set_nonblocking(fd: &OwnedFd) -> io::Result<()> {
    let raw = fd.as_raw_fd();
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

async fn read_fd(afd: &AsyncFd<OwnedFd>, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        let mut guard = afd.readable().await?;
        match guard.try_io(|inner| {
            let fd = inner.get_ref().as_raw_fd();
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }) {
            Ok(result) => return result,
            Err(_would_block) => continue,
        }
    }
}

async fn write_fd(afd: &AsyncFd<OwnedFd>, buf: &[u8]) -> io::Result<usize> {
    loop {
        let mut guard = afd.writable().await?;
        match guard.try_io(|inner| {
            let fd = inner.get_ref().as_raw_fd();
            let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }) {
            Ok(result) => return result,
            Err(_would_block) => continue,
        }
    }
}

/// tun → mesh: read an IP packet from the tun, firewall it outbound, and
/// send it to the destination peer over the encrypted tunnel.
async fn tun_to_mesh(shared: Arc<Shared>) -> io::Result<()> {
    let mut buf = vec![0u8; 65535];
    loop {
        let n = read_fd(&shared.tun, &mut buf).await?;
        let raw = &buf[..n];
        let Some(fw_pkt) = packet::parse(raw, false) else {
            continue;
        };
        let dst = fw_pkt.remote_addr; // outbound: remote == destination vpn addr

        // Ensure a tunnel exists before we can look the peer up. Multicast
        // destinations (IPv6 router solicitation, mDNS, ...) are kernel
        // housekeeping traffic a real tun interface emits on its own and
        // never have a mesh peer — skip them rather than paying `connect`'s
        // multi-second handshake timeout, which would otherwise stall this
        // single sequential loop and head-of-line-block real traffic.
        if shared.session.peer_info(dst).await.is_none() {
            if dst.is_multicast() {
                continue;
            }
            if shared.session.connect(dst).await.is_err() {
                continue;
            }
        }
        let Some(info) = shared.session.peer_info(dst).await else {
            continue;
        };
        let peer = identity::peer_identity(&info, &shared.ca_name, &shared.ca_sha);
        if shared.firewall.evaluate(fw_pkt, false, &peer).is_ok() {
            let _ = shared.session.send(dst, raw).await;
        }
    }
}

/// mesh → tun: decrypt an IP packet from a peer, firewall it inbound, and
/// write it to the tun so the local kernel handles it.
async fn mesh_to_tun(shared: Arc<Shared>) -> io::Result<()> {
    loop {
        let Ok((src, bytes)) = shared.session.recv().await else {
            return Ok(()); // session closed
        };
        let Some(fw_pkt) = packet::parse(&bytes, true) else {
            continue;
        };
        let Some(info) = shared.session.peer_info(src).await else {
            continue;
        };
        let peer = identity::peer_identity(&info, &shared.ca_name, &shared.ca_sha);
        if shared.firewall.evaluate(fw_pkt, true, &peer).is_ok() {
            let _ = write_fd(&shared.tun, &bytes).await;
        }
    }
}
