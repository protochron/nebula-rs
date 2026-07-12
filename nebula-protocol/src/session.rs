//! Ties `cert`, `handshake`, `transport`, and `lighthouse` together
//! behind an async `Session` API. A test harness, a tun device, or
//! (eventually) a smoltcp stack can all drive `send`/`recv` without
//! knowing protocol internals.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use prost::Message;
use snow::HandshakeState;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::time::timeout;

use crate::cert::der::{Certificate, Curve, Network};
use crate::cert::verify::verify_host_cert;
use crate::error::Error;
use crate::handshake::{self, Cipher};
use crate::header::{self, Header};
use crate::lighthouse;
use crate::transport::Transport;
use crate::wire::nebula_meta::MessageType as LighthouseMessageType;
use crate::wire::NebulaMeta;

pub struct SessionConfig {
    pub ca_cert_pem: Vec<u8>,
    pub host_cert_pem: Vec<u8>,
    pub host_key_pem: Vec<u8>,
    pub cipher: Cipher,
    pub bind_addr: SocketAddr,
    pub lighthouses: Vec<SocketAddr>,
    pub static_hosts: Vec<(IpAddr, SocketAddr)>,
}

enum PeerState {
    Handshaking(HandshakeState),
    Established {
        transport: Transport,
        remote: SocketAddr,
        vpn_addr: IpAddr,
        /// The peer's verified certificate, kept so the listener can build
        /// a firewall `PeerIdentity` for it (name/groups/networks).
        cert: Certificate,
        /// The *peer's* local index, stamped on the `remote_index` header
        /// field of every data packet we send them (nebula's
        /// `hostinfo.remoteIndexId`). Distinct from the key this session is
        /// stored under in `peers_by_index`, which is *our* local index.
        remote_index: u32,
    },
}

struct Inner {
    socket: Arc<UdpSocket>,
    ca_cert: Certificate,
    host_cert: Certificate,
    host_private_key: [u8; 32],
    cipher: Cipher,
    vpn_addr: IpAddr,
    lighthouses: Vec<SocketAddr>,
    known_addrs: HashMap<IpAddr, SocketAddr>,
    peers_by_index: HashMap<u32, PeerState>,
    index_by_vpn_addr: HashMap<IpAddr, u32>,
    connected: HashMap<IpAddr, oneshot::Sender<()>>,
    lighthouse_waiters: HashMap<IpAddr, oneshot::Sender<Vec<SocketAddr>>>,
    inbox_tx: mpsc::UnboundedSender<(IpAddr, Vec<u8>)>,
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_secs() as i64
}

fn rand_index() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    // A cryptographically-strong index isn't required (it's a
    // connection-identifier, not key material) — nebula itself just calls
    // `rand.Read` for this; a coarse time-seeded value keeps this crate's
    // dependency list smaller.
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos();
    nanos ^ 0x9E37_79B9
}

fn allocate_index(inner: &mut Inner) -> u32 {
    loop {
        let candidate = rand_index();
        if candidate != 0 && !inner.peers_by_index.contains_key(&candidate) {
            return candidate;
        }
    }
}

async fn send_lighthouse_packet(socket: &UdpSocket, to: SocketAddr, payload: &[u8]) -> Result<(), Error> {
    let mut header_bytes = [0u8; header::LEN];
    Header {
        version: header::VERSION,
        type_: header::message_type::LIGHTHOUSE,
        subtype: 0,
        remote_index: 0,
        message_counter: 0,
    }
    .encode(&mut header_bytes);
    let mut packet = header_bytes.to_vec();
    packet.extend_from_slice(payload);
    socket.send_to(&packet, to).await?;
    Ok(())
}

async fn handle_handshake(inner: &mut Inner, hdr: &Header, body: &[u8], from: SocketAddr) {
    if hdr.remote_index == 0 {
        // Fresh stage-0 from an initiator (matches nebula's convention:
        // stage-0 is always sent with remote_index unset). Allocate our own
        // local index up front so it can be embedded as `responder_index` in
        // the stage-2 reply — the initiator stamps it on every data packet it
        // sends us, and we key this session by it below.
        let index = allocate_index(inner);
        let cert_bytes = inner.host_cert.encode_for_handshake();
        let Ok((their_details, reply, keys)) =
            handshake::respond(inner.cipher, &inner.host_private_key, cert_bytes, index, body)
        else {
            return;
        };
        let Ok(their_cert) = Certificate::recombine(&their_details.cert, &keys.remote_static, Curve::Curve25519)
        else {
            return;
        };
        if verify_host_cert(&their_cert, &inner.ca_cert, now_unix()).is_err() {
            return;
        }
        let Some(vpn_addr) = their_cert.details.networks.first().map(|n| n.addr) else { return };

        let mut header_bytes = [0u8; header::LEN];
        Header {
            version: header::VERSION,
            type_: header::message_type::HANDSHAKE,
            subtype: header::handshake_subtype::IX_PSK0,
            remote_index: their_details.initiator_index,
            message_counter: 2,
        }
        .encode(&mut header_bytes);
        let mut packet = header_bytes.to_vec();
        packet.extend_from_slice(&reply);
        let _ = inner.socket.send_to(&packet, from).await;

        inner.peers_by_index.insert(
            index,
            PeerState::Established {
                transport: Transport::new(inner.cipher, keys.send_key, keys.recv_key),
                remote: from,
                vpn_addr,
                cert: their_cert,
                // The initiator's index — where our outbound data packets go.
                remote_index: their_details.initiator_index,
            },
        );
        inner.index_by_vpn_addr.insert(vpn_addr, index);
    } else {
        // We are the initiator; hdr.remote_index is our own local index
        // for this in-progress handshake.
        let Some(PeerState::Handshaking(_)) = inner.peers_by_index.get(&hdr.remote_index) else { return };
        let Some(PeerState::Handshaking(hs)) = inner.peers_by_index.remove(&hdr.remote_index) else { return };
        let Ok((their_details, keys)) = handshake::finish_initiator(hs, body) else { return };
        let Ok(their_cert) = Certificate::recombine(&their_details.cert, &keys.remote_static, Curve::Curve25519)
        else {
            return;
        };
        if verify_host_cert(&their_cert, &inner.ca_cert, now_unix()).is_err() {
            return;
        }
        let Some(vpn_addr) = their_cert.details.networks.first().map(|n| n.addr) else { return };
        inner.peers_by_index.insert(
            hdr.remote_index,
            PeerState::Established {
                transport: Transport::new(inner.cipher, keys.send_key, keys.recv_key),
                remote: from,
                vpn_addr,
                cert: their_cert,
                // The responder's index, learned from the stage-2 reply — where
                // our outbound data packets go.
                remote_index: their_details.responder_index,
            },
        );
        inner.index_by_vpn_addr.insert(vpn_addr, hdr.remote_index);
        if let Some(tx) = inner.connected.remove(&vpn_addr) {
            let _ = tx.send(());
        }
    }
}

fn handle_message(inner: &mut Inner, hdr: &Header, header_bytes: &[u8], body: &[u8]) {
    let Some(PeerState::Established { transport, vpn_addr, .. }) = inner.peers_by_index.get_mut(&hdr.remote_index)
    else {
        return;
    };
    let mut out = vec![0u8; body.len()];
    // The raw wire header bytes are the AEAD associated data (nebula
    // authenticates the header alongside the payload) — see the
    // module-level comment in `transport`.
    let Ok(len) = transport.decrypt(hdr.message_counter, header_bytes, body, &mut out) else { return };
    out.truncate(len);
    let _ = inner.inbox_tx.send((*vpn_addr, out[..len].to_vec()));
}

fn handle_lighthouse(inner: &mut Inner, body: &[u8]) {
    let Ok(meta) = NebulaMeta::decode(body) else { return };
    if meta.r#type == LighthouseMessageType::HostQueryReply as i32
        || meta.r#type == LighthouseMessageType::HostUpdateNotification as i32
    {
        let addrs = lighthouse::candidate_addrs(&meta);
        if addrs.is_empty() {
            return;
        }
        if let Some(vpn_addr) = meta.details.as_ref().and_then(|d| d.vpn_addr.as_ref()).map(lighthouse::addr_to_ip) {
            inner.known_addrs.insert(vpn_addr, addrs[0]);
            if let Some(tx) = inner.lighthouse_waiters.remove(&vpn_addr) {
                let _ = tx.send(addrs);
            }
        }
    }
}

fn spawn_recv_loop(socket: Arc<UdpSocket>, inner: Arc<Mutex<Inner>>) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let Ok((n, from)) = socket.recv_from(&mut buf).await else { continue };
            let Ok(hdr) = Header::parse(&buf[..n]) else { continue };
            let header_bytes = buf[..header::LEN].to_vec();
            let body = buf[header::LEN..n].to_vec();
            let mut inner_guard = inner.lock().await;
            match hdr.type_ {
                t if t == header::message_type::HANDSHAKE => {
                    handle_handshake(&mut inner_guard, &hdr, &body, from).await;
                }
                t if t == header::message_type::MESSAGE => {
                    handle_message(&mut inner_guard, &hdr, &header_bytes, &body);
                }
                t if t == header::message_type::LIGHTHOUSE => {
                    handle_lighthouse(&mut inner_guard, &body);
                }
                _ => {}
            }
        }
    });
}

pub struct Session {
    inner: Arc<Mutex<Inner>>,
    inbox_rx: Mutex<mpsc::UnboundedReceiver<(IpAddr, Vec<u8>)>>,
    local_addr: SocketAddr,
}

/// The verified certificate identity of an established peer, in the plain
/// shape nebula-listener converts into a `nebula_firewall::PeerIdentity`.
/// Uses the cert crate's own `Network` type so `ipnet` stays out of
/// nebula-protocol's dependency list — the listener does the conversion.
#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub name: String,
    pub groups: Vec<String>,
    pub networks: Vec<Network>,
    pub unsafe_networks: Vec<Network>,
}

impl Session {
    pub async fn new(config: SessionConfig) -> Result<Self, Error> {
        let socket = UdpSocket::bind(config.bind_addr).await?;
        Self::build(config, socket).await
    }

    /// Builds a `Session` around an already-bound `std::net::UdpSocket`.
    ///
    /// The socket's network namespace is fixed at the point its fd was
    /// created; this constructor registers that fd with the *Session's*
    /// tokio runtime via `from_std`, so the runtime never has to be in the
    /// socket's netns. `config.bind_addr` is unused on this path.
    pub async fn from_socket(config: SessionConfig, sock: std::net::UdpSocket) -> Result<Self, Error> {
        sock.set_nonblocking(true)?;
        let socket = UdpSocket::from_std(sock)?;
        Self::build(config, socket).await
    }

    async fn build(config: SessionConfig, socket: UdpSocket) -> Result<Self, Error> {
        let ca_der = crate::cert::pem::decode(&config.ca_cert_pem, crate::cert::pem::CERTIFICATE_V2_BANNER)?;
        let ca_cert = Certificate::decode(&ca_der)?;
        let host_der = crate::cert::pem::decode(&config.host_cert_pem, crate::cert::pem::CERTIFICATE_V2_BANNER)?;
        let host_cert = Certificate::decode(&host_der)?;
        let key_bytes = crate::cert::pem::decode(&config.host_key_pem, crate::cert::pem::X25519_PRIVATE_KEY_BANNER)?;
        let host_private_key: [u8; 32] =
            key_bytes.as_slice().try_into().map_err(|_| Error::Pem("host private key is not 32 bytes".into()))?;
        let vpn_addr = host_cert.details.networks.first().ok_or(Error::CertNoNetworks)?.addr;

        let socket = Arc::new(socket);
        let local_addr = socket.local_addr()?;
        let (inbox_tx, inbox_rx) = mpsc::unbounded_channel();

        let inner = Arc::new(Mutex::new(Inner {
            socket: socket.clone(),
            ca_cert,
            host_cert,
            host_private_key,
            cipher: config.cipher,
            vpn_addr,
            lighthouses: config.lighthouses.clone(),
            known_addrs: config.static_hosts.into_iter().collect(),
            peers_by_index: HashMap::new(),
            index_by_vpn_addr: HashMap::new(),
            connected: HashMap::new(),
            lighthouse_waiters: HashMap::new(),
            inbox_tx,
        }));

        spawn_recv_loop(socket, inner.clone());

        let session = Session { inner, inbox_rx: Mutex::new(inbox_rx), local_addr };
        session.register_with_lighthouses().await?;
        Ok(session)
    }

    pub fn local_addr(&self) -> Result<SocketAddr, Error> {
        Ok(self.local_addr)
    }

    /// Returns the verified certificate identity of the established peer
    /// reachable at `vpn_addr`, or `None` if no handshake has completed for
    /// it yet.
    pub async fn peer_info(&self, vpn_addr: IpAddr) -> Option<PeerInfo> {
        let inner = self.inner.lock().await;
        let index = *inner.index_by_vpn_addr.get(&vpn_addr)?;
        let PeerState::Established { cert, .. } = inner.peers_by_index.get(&index)? else {
            return None;
        };
        Some(PeerInfo {
            name: cert.details.name.clone(),
            groups: cert.details.groups.clone(),
            networks: cert.details.networks.clone(),
            unsafe_networks: cert.details.unsafe_networks.clone(),
        })
    }

    async fn register_with_lighthouses(&self) -> Result<(), Error> {
        let inner = self.inner.lock().await;
        if inner.lighthouses.is_empty() {
            return Ok(());
        }
        let meta = lighthouse::host_update_notification(inner.vpn_addr, &[self.local_addr]);
        let payload = meta.encode_to_vec();
        for lh in &inner.lighthouses {
            send_lighthouse_packet(&inner.socket, *lh, &payload).await?;
        }
        Ok(())
    }

    async fn resolve(&self, vpn_addr: IpAddr) -> Result<SocketAddr, Error> {
        {
            let inner = self.inner.lock().await;
            if let Some(addr) = inner.known_addrs.get(&vpn_addr) {
                return Ok(*addr);
            }
        }
        let rx = {
            let mut inner = self.inner.lock().await;
            let (tx, rx) = oneshot::channel();
            inner.lighthouse_waiters.insert(vpn_addr, tx);
            let meta = lighthouse::host_query(vpn_addr);
            let payload = meta.encode_to_vec();
            for lh in inner.lighthouses.clone() {
                let socket = inner.socket.clone();
                let payload = payload.clone();
                tokio::spawn(async move {
                    let _ = send_lighthouse_packet(&socket, lh, &payload).await;
                });
            }
            rx
        };
        let addrs =
            timeout(Duration::from_secs(5), rx).await.map_err(|_| Error::PeerUnreachable(vpn_addr))?.map_err(|_| Error::PeerUnreachable(vpn_addr))?;
        addrs.first().copied().ok_or(Error::PeerUnreachable(vpn_addr))
    }

    pub async fn connect(&self, vpn_addr: IpAddr) -> Result<(), Error> {
        let remote = self.resolve(vpn_addr).await?;
        let rx = {
            let mut inner = self.inner.lock().await;
            let (tx, rx) = oneshot::channel();
            inner.connected.insert(vpn_addr, tx);

            let index = allocate_index(&mut inner);
            let cert_bytes = inner.host_cert.encode_for_handshake();
            let (hs, msg) = handshake::stage0(inner.cipher, &inner.host_private_key, cert_bytes, index)?;
            inner.peers_by_index.insert(index, PeerState::Handshaking(hs));

            let mut header_bytes = [0u8; header::LEN];
            Header {
                version: header::VERSION,
                type_: header::message_type::HANDSHAKE,
                subtype: header::handshake_subtype::IX_PSK0,
                remote_index: 0,
                message_counter: 1,
            }
            .encode(&mut header_bytes);
            let mut packet = header_bytes.to_vec();
            packet.extend_from_slice(&msg);
            let socket = inner.socket.clone();
            tokio::spawn(async move {
                let _ = socket.send_to(&packet, remote).await;
            });
            rx
        };
        timeout(Duration::from_secs(5), rx)
            .await
            .map_err(|_| Error::Timeout("handshake"))?
            .map_err(|_| Error::HandshakeFailed("cancelled".into()))
    }

    pub async fn send(&self, vpn_addr: IpAddr, payload: &[u8]) -> Result<(), Error> {
        let (packet, remote, socket) = {
            let mut inner = self.inner.lock().await;
            // Our own local index — how we find the session.
            let index = *inner.index_by_vpn_addr.get(&vpn_addr).ok_or(Error::PeerUnreachable(vpn_addr))?;
            let socket = inner.socket.clone();
            let Some(PeerState::Established { transport, remote, remote_index, .. }) =
                inner.peers_by_index.get_mut(&index)
            else {
                return Err(Error::PeerUnreachable(vpn_addr));
            };
            // Data packets carry the *peer's* index in the header so the peer
            // can look the tunnel up by its own local index (inside.go:359).
            let peer_index = *remote_index;
            // The header must be built *before* encryption: it's the AEAD
            // associated data (nebula authenticates the header alongside
            // the payload — see the module-level comment in `transport`),
            // so the counter it embeds has to already be chosen.
            let counter = transport.next_counter();
            let mut header_bytes = [0u8; header::LEN];
            Header {
                version: header::VERSION,
                type_: header::message_type::MESSAGE,
                subtype: 0,
                remote_index: peer_index,
                message_counter: counter,
            }
            .encode(&mut header_bytes);

            let mut ciphertext = vec![0u8; payload.len() + 32];
            let len = transport.encrypt(counter, &header_bytes, payload, &mut ciphertext)?;
            ciphertext.truncate(len);

            let mut packet = header_bytes.to_vec();
            packet.extend_from_slice(&ciphertext);
            (packet, *remote, socket)
        };
        socket.send_to(&packet, remote).await?;
        Ok(())
    }

    pub async fn recv(&self) -> Result<(IpAddr, Vec<u8>), Error> {
        self.inbox_rx.lock().await.recv().await.ok_or(Error::Timeout("session closed"))
    }
}
