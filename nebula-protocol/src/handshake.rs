//! Noise_IX handshake wrapper, matching slackhq/nebula v1.10.3's
//! `ixHandshakeStage0`/`ixHandshakeStage1`/`ixHandshakeStage2`
//! (handshake_ix.go). Curve25519 only; AES-256-GCM or ChaChaPoly per
//! `Cipher`, matching `NewConnectionState`'s cipher-suite selection in
//! connection_state.go.

use prost::Message;
use snow::{Builder, HandshakeState};

use crate::error::Error;
use crate::wire::{NebulaHandshake, NebulaHandshakeDetails};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    AesGcm,
    ChaChaPoly,
}

impl Cipher {
    fn noise_params(self) -> snow::params::NoiseParams {
        let s = match self {
            Cipher::AesGcm => "Noise_IX_25519_AESGCM_SHA256",
            Cipher::ChaChaPoly => "Noise_IX_25519_ChaChaPoly_SHA256",
        };
        s.parse().expect("static noise params string is always valid")
    }
}

/// The raw Noise-split transport keys plus the peer's static public key,
/// pulled directly off a completed `HandshakeState` rather than snow's
/// `StatelessTransportState` — see the module-level comment in `transport`
/// for why: nebula authenticates the packet header as AEAD associated
/// data, which `StatelessTransportState::write_message`/`read_message`
/// have no way to do, so `transport::Transport` implements the AEAD calls
/// itself using these raw keys.
pub struct SplitKeys {
    pub remote_static: Vec<u8>,
    pub send_key: [u8; 32],
    pub recv_key: [u8; 32],
}

/// By Noise `Split()` convention, the initiator sends with the first split
/// key and receives with the second; the responder is the mirror image
/// (matches how `snow`'s own `StatelessTransportState` picks
/// `cipherstates.0` vs `.1` based on `is_initiator`).
fn split_keys(hs: &mut HandshakeState) -> Result<SplitKeys, Error> {
    let remote_static = hs
        .get_remote_static()
        .map(|s| s.to_vec())
        .ok_or_else(|| Error::HandshakeFailed("handshake completed with no remote static key".into()))?;
    let (k1, k2) = hs.dangerously_get_raw_split();
    let (send_key, recv_key) = if hs.is_initiator() { (k1, k2) } else { (k2, k1) };
    Ok(SplitKeys { remote_static, send_key, recv_key })
}

fn unix_nanos_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_nanos() as u64
}

/// Builds the stage-0 (initiator) handshake message. Returns the raw
/// Noise ciphertext to place after the 16-byte header, plus the
/// in-progress `HandshakeState` to feed the responder's stage-2 reply
/// into via `finish_initiator`.
pub fn stage0(
    cipher: Cipher,
    local_private_key: &[u8; 32],
    my_cert_handshake_bytes: Vec<u8>,
    initiator_index: u32,
) -> Result<(HandshakeState, Vec<u8>), Error> {
    let builder = Builder::new(cipher.noise_params());
    let mut hs = builder.local_private_key(local_private_key)?.build_initiator()?;

    let payload = NebulaHandshake {
        details: Some(NebulaHandshakeDetails {
            cert: my_cert_handshake_bytes,
            initiator_index,
            responder_index: 0,
            cookie: 0,
            time: unix_nanos_now(),
            cert_version: 2,
        }),
        hmac: vec![],
    };
    let payload_bytes = payload.encode_to_vec();

    let mut msg = vec![0u8; 65535];
    let len = hs.write_message(&payload_bytes, &mut msg)?;
    msg.truncate(len);
    Ok((hs, msg))
}

/// Responds to an initiator's stage-0 message: reads their cert bytes and
/// index, and builds our own stage-2 reply. `responder_index` is *our* local
/// index for this tunnel — it's embedded as `responder_index` in the reply so
/// the initiator learns which index to stamp on its outbound data packets
/// (matches `hs.Details.ResponderIndex = myIndex` in handshake_ix.go). Returns
/// the transport state immediately, since the responder's handshake is
/// complete as soon as it sends stage 2 (matches `ixHandshakeStage1`
/// completing the connection on the responder side).
pub fn respond(
    cipher: Cipher,
    local_private_key: &[u8; 32],
    my_cert_handshake_bytes: Vec<u8>,
    responder_index: u32,
    stage0_noise_payload: &[u8],
) -> Result<(NebulaHandshakeDetails, Vec<u8>, SplitKeys), Error> {
    let builder = Builder::new(cipher.noise_params());
    let mut hs = builder.local_private_key(local_private_key)?.build_responder()?;

    let mut payload = vec![0u8; 65535];
    let len = hs.read_message(stage0_noise_payload, &mut payload)?;
    payload.truncate(len);
    let stage0 = NebulaHandshake::decode(payload.as_slice())?;
    let their_details = stage0
        .details
        .ok_or_else(|| Error::HandshakeFailed("stage 0 message had no details".into()))?;

    let reply = NebulaHandshake {
        details: Some(NebulaHandshakeDetails {
            cert: my_cert_handshake_bytes,
            initiator_index: their_details.initiator_index,
            responder_index,
            cookie: 0,
            time: unix_nanos_now(),
            cert_version: 2,
        }),
        hmac: vec![],
    };
    let reply_bytes = reply.encode_to_vec();
    let mut msg = vec![0u8; 65535];
    let len = hs.write_message(&reply_bytes, &mut msg)?;
    msg.truncate(len);

    let keys = split_keys(&mut hs)?;
    Ok((their_details, msg, keys))
}

/// Consumes the responder's stage-2 reply, completing the initiator side
/// of the handshake. Returns the peer's cert bytes (still to be verified
/// by the caller against the configured CA — see `cert::verify`) and the
/// transport state for steady-state encryption.
pub fn finish_initiator(
    mut hs: HandshakeState,
    stage2_noise_payload: &[u8],
) -> Result<(NebulaHandshakeDetails, SplitKeys), Error> {
    let mut payload = vec![0u8; 65535];
    let len = hs.read_message(stage2_noise_payload, &mut payload)?;
    payload.truncate(len);

    let handshake = NebulaHandshake::decode(payload.as_slice())?;
    let details = handshake
        .details
        .ok_or_else(|| Error::HandshakeFailed("stage 2 message had no details".into()))?;

    let keys = split_keys(&mut hs)?;
    Ok((details, keys))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> ([u8; 32], Vec<u8>) {
        let params: snow::params::NoiseParams = "Noise_IX_25519_AESGCM_SHA256".parse().unwrap();
        let kp = snow::Builder::new(params).generate_keypair().unwrap();
        (kp.private.try_into().unwrap(), kp.public)
    }

    #[test]
    fn full_ix_handshake_completes_between_two_local_parties() {
        let (initiator_key, _initiator_pub) = keypair();
        let (responder_key, _responder_pub) = keypair();

        // Stand-in "cert" bytes — this test only exercises the Noise
        // handshake mechanics and payload plumbing, not real cert
        // verification (that's Task 11's job, against real certs).
        let initiator_cert_bytes = b"initiator-cert-bytes".to_vec();
        let responder_cert_bytes = b"responder-cert-bytes".to_vec();

        let (hs, stage0_msg) =
            stage0(Cipher::AesGcm, &initiator_key, initiator_cert_bytes.clone(), 42).unwrap();

        let (their_details_at_responder, stage2_msg, responder_keys) =
            respond(Cipher::AesGcm, &responder_key, responder_cert_bytes.clone(), 99, &stage0_msg).unwrap();
        assert_eq!(their_details_at_responder.cert, initiator_cert_bytes);
        assert_eq!(their_details_at_responder.initiator_index, 42);

        let (their_details_at_initiator, initiator_keys) = finish_initiator(hs, &stage2_msg).unwrap();
        assert_eq!(their_details_at_initiator.cert, responder_cert_bytes);
        // The responder's own index must round-trip back to the initiator, so
        // the initiator knows which index to stamp on its outbound data packets.
        assert_eq!(their_details_at_initiator.responder_index, 99);

        // Both sides should now share working transport keys.
        let mut initiator_transport =
            crate::transport::Transport::new(Cipher::AesGcm, initiator_keys.send_key, initiator_keys.recv_key);
        let mut responder_transport =
            crate::transport::Transport::new(Cipher::AesGcm, responder_keys.send_key, responder_keys.recv_key);

        let aad = b"fake-16-byte-hdr";
        let mut ciphertext = vec![0u8; 128];
        let counter = initiator_transport.next_counter();
        let len = initiator_transport.encrypt(counter, aad, b"hello", &mut ciphertext).unwrap();
        let mut plaintext = vec![0u8; 128];
        let plen = responder_transport.decrypt(counter, aad, &ciphertext[..len], &mut plaintext).unwrap();
        assert_eq!(&plaintext[..plen], b"hello");
    }

    #[test]
    fn full_ix_handshake_completes_with_chachapoly() {
        let (initiator_key, _) = keypair();
        let (responder_key, _) = keypair();
        let (hs, stage0_msg) = stage0(Cipher::ChaChaPoly, &initiator_key, b"a".to_vec(), 7).unwrap();
        let (_, stage2_msg, _) = respond(Cipher::ChaChaPoly, &responder_key, b"b".to_vec(), 55, &stage0_msg).unwrap();
        let (details, _) = finish_initiator(hs, &stage2_msg).unwrap();
        assert_eq!(details.cert, b"b".to_vec());
    }
}
