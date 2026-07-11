//! PEM encode/decode matching slackhq/nebula v1.10.3's exact banner
//! strings (cert/pem.go), so files round-trip with the real `nebula-cert`
//! tool and this crate's sibling `nebula-signer` service byte-for-byte.

use crate::error::Error;

pub const CERTIFICATE_V2_BANNER: &str = "NEBULA CERTIFICATE V2";
pub const X25519_PRIVATE_KEY_BANNER: &str = "NEBULA X25519 PRIVATE KEY";
pub const X25519_PUBLIC_KEY_BANNER: &str = "NEBULA X25519 PUBLIC KEY";
pub const ED25519_PRIVATE_KEY_BANNER: &str = "NEBULA ED25519 PRIVATE KEY";
pub const ED25519_PUBLIC_KEY_BANNER: &str = "NEBULA ED25519 PUBLIC KEY";

/// Decodes a single PEM block, verifying its banner matches `expected_tag`.
pub fn decode(input: &[u8], expected_tag: &str) -> Result<Vec<u8>, Error> {
    let block = pem::parse(input).map_err(|e| Error::Pem(e.to_string()))?;
    if block.tag() != expected_tag {
        return Err(Error::Pem(format!(
            "expected PEM tag {expected_tag:?}, got {:?}",
            block.tag()
        )));
    }
    Ok(block.contents().to_vec())
}

pub fn encode(tag: &str, contents: &[u8]) -> String {
    pem::encode(&pem::Pem::new(tag, contents.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }

    #[test]
    fn decodes_real_ca_cert() {
        let der = decode(&fixture("ca.crt"), CERTIFICATE_V2_BANNER).unwrap();
        assert!(!der.is_empty());
    }

    #[test]
    fn decodes_real_ca_key() {
        // Ground truth: nebula-cert's `ca` command stores the raw Go
        // `ed25519.PrivateKey` (32-byte seed + 32-byte public key = 64
        // bytes) directly — see cmd/nebula-cert/ca.go's `ed25519.GenerateKey`
        // + `MarshalSigningPrivateKeyToPEM` call in the vendored v1.10.3
        // source. Not 32 bytes, unlike the X25519 host keys below.
        let raw = decode(&fixture("ca.key"), ED25519_PRIVATE_KEY_BANNER).unwrap();
        assert_eq!(raw.len(), 64);
    }

    #[test]
    fn decodes_real_host_key() {
        let raw = decode(&fixture("host-a.key"), X25519_PRIVATE_KEY_BANNER).unwrap();
        assert_eq!(raw.len(), 32);
    }

    #[test]
    fn rejects_wrong_banner() {
        let err = decode(&fixture("ca.crt"), X25519_PRIVATE_KEY_BANNER).unwrap_err();
        assert!(matches!(err, crate::Error::Pem(_)));
    }

    #[test]
    fn encode_round_trips_through_decode() {
        let original = b"not real der bytes, just round-trip content";
        let pem_text = encode(CERTIFICATE_V2_BANNER, original);
        let decoded = decode(pem_text.as_bytes(), CERTIFICATE_V2_BANNER).unwrap();
        assert_eq!(decoded, original);
    }
}
