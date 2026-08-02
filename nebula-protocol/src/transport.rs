//! Steady-state packet encryption, matching slackhq/nebula v1.10.3's
//! `NebulaCipherState` (noise.go) byte-for-byte — including two details
//! that `snow`'s high-level transport API cannot express and that a real
//! nebula peer will reject a packet over if they're wrong:
//!
//! - **The 16-byte packet header is AEAD associated data**, not just a
//!   plaintext prefix. `noise.go`'s `EncryptDanger(out, out, p, c, nb)` /
//!   `outside.go`'s `DecryptDanger(out, packet[:header.Len], ...)` both
//!   authenticate the header bytes alongside the payload. `snow`'s
//!   `StatelessTransportState::write_message`/`read_message` always use
//!   empty AAD with no way to override it, so this module talks to the
//!   `aes-gcm`/`chacha20poly1305` crates directly instead — the same
//!   crates `snow` itself uses internally, just with nebula's AAD
//!   convention layered on top. This mirrors nebula's own architecture:
//!   nebula only uses its Noise library for the handshake and does its own
//!   `Seal`/`Open` for steady-state packets too (see `NewNebulaCipherState`
//!   wrapping the raw split cipher in noise.go).
//! - **Nonce byte order depends on the cipher**: AES-256-GCM uses a
//!   big-endian counter, ChaChaPoly uses little-endian (`noiseEndianness`
//!   in noise.go, set per-cipher in pki.go). Both are 4 zero bytes followed
//!   by the 8-byte counter.

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;

use crate::error::Error;
use crate::handshake::Cipher;

const WINDOW_SIZE: u64 = 1024;

/// A 1024-entry sliding replay window, matching nebula's `ReplayWindow`
/// constant (connection_state.go) and `Bits` implementation (bits.go):
/// tracks which of the last 1024 message counters have already been seen,
/// rejecting duplicates and counters too far behind the current
/// high-water mark.
pub struct ReplayWindow {
    current: u64,
    seen: [u64; 16], // 1024 bits = 16 u64 words
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self {
            current: 0,
            seen: [0; 16],
        }
    }

    /// Returns `true` and marks `counter` as seen if it's new; `false` if
    /// it's a duplicate or too old to track.
    pub fn check_and_update(&mut self, counter: u64) -> bool {
        if counter > self.current {
            let shift = counter - self.current;
            if shift >= WINDOW_SIZE {
                self.seen = [0; 16];
            } else {
                self.shift_left(shift);
            }
            self.current = counter;
            self.mark(0);
            true
        } else {
            let diff = self.current - counter;
            if diff >= WINDOW_SIZE || self.is_marked(diff) {
                return false;
            }
            self.mark(diff);
            true
        }
    }

    fn word_bit(offset: u64) -> (usize, u32) {
        ((offset / 64) as usize, (offset % 64) as u32)
    }

    fn mark(&mut self, offset: u64) {
        let (word, bit) = Self::word_bit(offset);
        self.seen[word] |= 1 << bit;
    }

    fn is_marked(&self, offset: u64) -> bool {
        let (word, bit) = Self::word_bit(offset);
        self.seen[word] & (1 << bit) != 0
    }

    fn shift_left(&mut self, n: u64) {
        for _ in 0..n {
            let mut carry = 0u64;
            for word in self.seen.iter_mut() {
                let new_carry = *word >> 63;
                *word = (*word << 1) | carry;
                carry = new_carry;
            }
        }
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

enum CipherImpl {
    AesGcm(Box<Aes256Gcm>),
    ChaChaPoly(Box<ChaCha20Poly1305>),
}

impl CipherImpl {
    fn new(cipher: Cipher, key: &[u8; 32]) -> Self {
        match cipher {
            Cipher::AesGcm => CipherImpl::AesGcm(Box::new(Aes256Gcm::new(key.into()))),
            Cipher::ChaChaPoly => {
                CipherImpl::ChaChaPoly(Box::new(ChaCha20Poly1305::new(key.into())))
            }
        }
    }

    /// 4 zero bytes + an 8-byte counter, big-endian for AES-GCM and
    /// little-endian for ChaChaPoly — matches nebula's `noiseEndianness`.
    fn nonce(&self, counter: u64) -> [u8; 12] {
        let mut nb = [0u8; 12];
        match self {
            CipherImpl::AesGcm(_) => nb[4..].copy_from_slice(&counter.to_be_bytes()),
            CipherImpl::ChaChaPoly(_) => nb[4..].copy_from_slice(&counter.to_le_bytes()),
        }
        nb
    }

    fn encrypt(&self, counter: u64, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = self.nonce(counter);
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        match self {
            CipherImpl::AesGcm(c) => c.encrypt(&nonce.into(), payload),
            CipherImpl::ChaChaPoly(c) => c.encrypt(&nonce.into(), payload),
        }
        .map_err(|_| Error::DecryptFailed)
    }

    fn decrypt(&self, counter: u64, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = self.nonce(counter);
        let payload = Payload {
            msg: ciphertext,
            aad,
        };
        match self {
            CipherImpl::AesGcm(c) => c.decrypt(&nonce.into(), payload),
            CipherImpl::ChaChaPoly(c) => c.decrypt(&nonce.into(), payload),
        }
        .map_err(|_| Error::DecryptFailed)
    }
}

pub struct Transport {
    send_cipher: CipherImpl,
    recv_cipher: CipherImpl,
    send_counter: u64,
    pub replay: ReplayWindow,
}

impl Transport {
    /// `send_key`/`recv_key` are the raw Noise-split cipher keys — by Noise
    /// convention (and matching how `snow`'s own `StatelessTransportState`
    /// picks `cipherstates.0` vs `.1` based on `is_initiator`), the
    /// initiator's send key is the responder's recv key and vice versa.
    /// The caller (`handshake` module) is responsible for handing in the
    /// correctly-assigned pair for its role.
    pub fn new(cipher: Cipher, send_key: [u8; 32], recv_key: [u8; 32]) -> Self {
        Self {
            send_cipher: CipherImpl::new(cipher, &send_key),
            recv_cipher: CipherImpl::new(cipher, &recv_key),
            // Initialize to 2, matching `ConnectionState.messageCounter`'s `Add(2)`
            // in connection_state.go: the two handshake messages consume counters 1
            // and 2, and `next_counter` increments *before* use (mirroring nebula's
            // `messageCounter.Add(1)` in inside.go), so the first data packet is 3.
            // The absolute value isn't load-bearing for interop — the counter is
            // the AEAD nonce, echoed verbatim in the packet header, so the receiver
            // decrypts with whatever value it's handed — but matching nebula's
            // sequence exactly removes any ambiguity.
            send_counter: 2,
            replay: ReplayWindow::new(),
        }
    }

    /// Allocates the next outbound message counter. Call this *before*
    /// building the packet header: the header embeds this counter and is
    /// itself the AEAD associated data passed to `encrypt`, so the header
    /// must exist first (mirrors nebula's own ordering in `inside.go`:
    /// `c := ci.messageCounter.Add(1); out = header.Encode(out, ..., c);
    /// out, err = ci.eKey.EncryptDanger(out, out, p, c, nb)`).
    pub fn next_counter(&mut self) -> u64 {
        self.send_counter += 1;
        self.send_counter
    }

    /// `aad` must be the exact 16-byte wire header (with `counter` already
    /// embedded in its `message_counter` field).
    pub fn encrypt(
        &self,
        counter: u64,
        aad: &[u8],
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let ciphertext = self.send_cipher.encrypt(counter, aad, plaintext)?;
        out[..ciphertext.len()].copy_from_slice(&ciphertext);
        Ok(ciphertext.len())
    }

    /// `aad` must be the exact 16 raw header bytes as received on the
    /// wire, not a re-encoding of a parsed `Header` — nebula authenticates
    /// the literal bytes.
    pub fn decrypt(
        &mut self,
        counter: u64,
        aad: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        if !self.replay.check_and_update(counter) {
            return Err(Error::ReplayedPacket);
        }
        let plaintext = self.recv_cipher.decrypt(counter, aad, ciphertext)?;
        out[..plaintext.len()].copy_from_slice(&plaintext);
        Ok(plaintext.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_strictly_increasing_counters() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_update(1));
        assert!(w.check_and_update(2));
        assert!(w.check_and_update(3));
    }

    #[test]
    fn rejects_exact_duplicate() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_update(5));
        assert!(!w.check_and_update(5));
    }

    #[test]
    fn accepts_reordered_packet_within_window() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_update(10));
        assert!(w.check_and_update(8)); // arrived late, but within the last 1024
        assert!(!w.check_and_update(8)); // now a duplicate
    }

    #[test]
    fn rejects_packet_older_than_the_window() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_update(2000));
        assert!(!w.check_and_update(1)); // 1999 behind the high-water mark, window is 1024
    }

    #[test]
    fn end_to_end_encrypt_decrypt_via_transport() {
        let a_key = [0x11u8; 32];
        let b_key = [0x22u8; 32];
        // a sends with a_key/receives with b_key; b is the mirror image,
        // matching how the two ends of a real Noise split share keys.
        let mut a_transport = Transport::new(Cipher::AesGcm, a_key, b_key);
        let mut b_transport = Transport::new(Cipher::AesGcm, b_key, a_key);

        let aad = b"fake-16-byte-hdr";
        let counter = a_transport.next_counter();
        let mut ciphertext = vec![0u8; 128];
        let len = a_transport
            .encrypt(counter, aad, b"hello world", &mut ciphertext)
            .unwrap();
        let mut plaintext = vec![0u8; 128];
        let plen = b_transport
            .decrypt(counter, aad, &ciphertext[..len], &mut plaintext)
            .unwrap();
        assert_eq!(&plaintext[..plen], b"hello world");

        // A replay of the same counter must be rejected.
        assert!(
            b_transport
                .decrypt(counter, aad, &ciphertext[..len], &mut plaintext)
                .is_err()
        );
    }

    #[test]
    fn mismatched_aad_is_rejected() {
        let a_key = [0x33u8; 32];
        let b_key = [0x44u8; 32];
        let a_transport = Transport::new(Cipher::ChaChaPoly, a_key, b_key);
        let mut b_transport = Transport::new(Cipher::ChaChaPoly, b_key, a_key);

        let mut ciphertext = vec![0u8; 128];
        let len = a_transport
            .encrypt(3, b"correct-header-x", b"payload", &mut ciphertext)
            .unwrap();
        let mut plaintext = vec![0u8; 128];
        assert!(
            b_transport
                .decrypt(3, b"wrong-header-byte", &ciphertext[..len], &mut plaintext)
                .is_err()
        );
    }
}
