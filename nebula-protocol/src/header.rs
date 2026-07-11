//! The fixed 16-byte Nebula packet header, matching slackhq/nebula
//! v1.10.3's `header` package exactly:
//! ```text
//! | Version:4 | Type:4 | Subtype:8 | Reserved:16 | RemoteIndex:32 | MessageCounter:64 |
//! ```

use crate::error::Error;

pub const LEN: usize = 16;
pub const VERSION: u8 = 1;

pub mod message_type {
    pub const HANDSHAKE: u8 = 0;
    pub const MESSAGE: u8 = 1;
    pub const RECV_ERROR: u8 = 2;
    pub const LIGHTHOUSE: u8 = 3;
    pub const TEST: u8 = 4;
    pub const CLOSE_TUNNEL: u8 = 5;
    pub const CONTROL: u8 = 6;
}

pub mod handshake_subtype {
    pub const IX_PSK0: u8 = 0;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub type_: u8,
    pub subtype: u8,
    pub remote_index: u32,
    pub message_counter: u64,
}

impl Header {
    pub fn encode(&self, out: &mut [u8; LEN]) {
        out[0] = (self.version << 4) | (self.type_ & 0x0f);
        out[1] = self.subtype;
        out[2..4].copy_from_slice(&0u16.to_be_bytes());
        out[4..8].copy_from_slice(&self.remote_index.to_be_bytes());
        out[8..16].copy_from_slice(&self.message_counter.to_be_bytes());
    }

    pub fn parse(b: &[u8]) -> Result<Self, Error> {
        if b.len() < LEN {
            return Err(Error::HeaderTooShort { need: LEN, got: b.len() });
        }
        Ok(Self {
            version: (b[0] >> 4) & 0x0f,
            type_: b[0] & 0x0f,
            subtype: b[1],
            remote_index: u32::from_be_bytes(b[4..8].try_into().unwrap()),
            message_counter: u64::from_be_bytes(b[8..16].try_into().unwrap()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_matches_real_nebula_stage0_bytes() {
        // Reproduces the exact bytes handshake_ix.go's ixHandshakeStage0 sends:
        // header.Encode(buf, header.Version, header.Handshake, header.HandshakeIXPSK0, 0, 1)
        let h = Header {
            version: VERSION,
            type_: message_type::HANDSHAKE,
            subtype: handshake_subtype::IX_PSK0,
            remote_index: 0,
            message_counter: 1,
        };
        let mut out = [0u8; LEN];
        h.encode(&mut out);
        assert_eq!(
            out,
            [0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
        );
    }

    #[test]
    fn parse_round_trips_encode() {
        let h = Header {
            version: VERSION,
            type_: message_type::MESSAGE,
            subtype: 0,
            remote_index: 0xdeadbeef,
            message_counter: 0x0102030405060708,
        };
        let mut buf = [0u8; LEN];
        h.encode(&mut buf);
        let parsed = Header::parse(&buf).unwrap();
        assert_eq!(parsed, h);
    }

    #[test]
    fn parse_rejects_short_buffer() {
        let err = Header::parse(&[0u8; 15]).unwrap_err();
        assert!(matches!(err, crate::Error::HeaderTooShort { need: LEN, got: 15 }));
    }
}
