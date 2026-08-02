//! The crate-wide error type. Every fallible function in nebula-protocol
//! returns `Result<T, Error>`.

use thiserror::Error as ThisError;

#[derive(Debug, ThisError)]
pub enum Error {
    #[error("header too short: need {need} bytes, got {got}")]
    HeaderTooShort { need: usize, got: usize },

    #[error("malformed DER: {0}")]
    Der(String),

    #[error("certificate expired")]
    CertExpired,

    #[error("certificate signature invalid")]
    CertSignatureInvalid,

    #[error("certificate uses unsupported curve (only Curve25519 is supported)")]
    CertUnsupportedCurve,

    #[error("certificate was not issued by the configured CA")]
    CertUntrusted,

    #[error("certificate contains no networks")]
    CertNoNetworks,

    #[error("replayed or too-old packet counter")]
    ReplayedPacket,

    #[error("AEAD decryption failed")]
    DecryptFailed,

    #[error("noise protocol error: {0}")]
    Noise(#[from] snow::Error),

    #[error("protobuf decode error: {0}")]
    ProtobufDecode(#[from] prost::DecodeError),

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("pem decode error: {0}")]
    Pem(String),

    #[error("handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("handshake carried a zero peer index")]
    HandshakeInvalidRemoteIndex,

    #[error("peer unreachable: no known address for {0}")]
    PeerUnreachable(std::net::IpAddr),

    #[error("timed out waiting for {0}")]
    Timeout(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;
