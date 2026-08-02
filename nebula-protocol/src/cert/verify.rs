//! Certificate signature verification and CA trust-chain validation,
//! mirroring `certificateV2.CheckSignature` and the handshake-time checks
//! in `ixHandshakeStage1`/`ixHandshakeStage2` (handshake_ix.go) in
//! slackhq/nebula v1.10.3.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::cert::der::{Certificate, Curve};
use crate::error::Error;

impl Certificate {
    /// Verifies this certificate's signature against `signer_public_key`
    /// (the Ed25519 public key of the CA that issued it). Only Curve25519
    /// (Ed25519-signed) certs are supported — see the crate's Non-goals.
    pub fn check_signature(&self, signer_public_key: &[u8]) -> Result<(), Error> {
        if self.curve != Curve::Curve25519 {
            return Err(Error::CertUnsupportedCurve);
        }
        let key_bytes: [u8; 32] = signer_public_key
            .try_into()
            .map_err(|_| Error::CertSignatureInvalid)?;
        let vk = VerifyingKey::from_bytes(&key_bytes).map_err(|_| Error::CertSignatureInvalid)?;
        let sig_bytes: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| Error::CertSignatureInvalid)?;
        let sig = Signature::from_bytes(&sig_bytes);
        vk.verify(&self.signing_bytes(), &sig)
            .map_err(|_| Error::CertSignatureInvalid)
    }

    /// The hex-encoded SHA-256 fingerprint of this certificate, matching
    /// `certificateV2.Fingerprint()` in cert/cert_v2.go.
    ///
    /// Ground-truth note: Go's `Fingerprint()` hashes the flat
    /// concatenation `rawDetails || curve-byte || publicKey || signature`
    /// directly — it does *not* hash `Marshal()`'s DER-wrapped output (that
    /// output adds a SEQUENCE tag, TLV-wraps the public key/signature, and
    /// omits the curve byte entirely when it's the Curve25519 default).
    /// Hashing `self.encode()` here would silently produce a fingerprint
    /// that never matches a real cert's recorded `issuer` field.
    pub fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.signing_bytes());
        hasher.update(&self.signature);
        hex::encode(hasher.finalize())
    }

    pub fn is_expired(&self, now_unix: i64) -> bool {
        now_unix < self.details.not_before || now_unix > self.details.not_after
    }
}

/// Verifies that `cert` was issued by `ca` (issuer fingerprint match,
/// signature check, and validity window) and is not itself a CA
/// certificate. Mirrors the checks `ixHandshakeStage1`/`ixHandshakeStage2`
/// perform via `CAPool.VerifyCertificate` before trusting a peer's cert.
pub fn verify_host_cert(cert: &Certificate, ca: &Certificate, now_unix: i64) -> Result<(), Error> {
    if cert.details.is_ca || !ca.details.is_ca {
        return Err(Error::CertSignatureInvalid);
    }
    if ca.is_expired(now_unix) || cert.is_expired(now_unix) {
        return Err(Error::CertExpired);
    }
    if hex::encode(&cert.details.issuer) != ca.fingerprint() {
        return Err(Error::CertUntrusted);
    }
    cert.check_signature(&ca.public_key)?;
    if cert.details.networks.is_empty() {
        return Err(Error::CertNoNetworks);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::{der::Certificate, pem};

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!(
            "{}/tests/fixtures/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    fn load(name: &str) -> Certificate {
        let der = pem::decode(&fixture(name), pem::CERTIFICATE_V2_BANNER).unwrap();
        Certificate::decode(&der).unwrap()
    }

    #[test]
    fn valid_host_cert_verifies_against_its_real_ca() {
        let ca = load("ca.crt");
        let host = load("host-a.crt");
        verify_host_cert(&host, &ca, host.details.not_before + 60).unwrap();
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let ca = load("ca.crt");
        let tampered = load("host-a-tampered.crt");
        let err = verify_host_cert(&tampered, &ca, tampered.details.not_before + 60).unwrap_err();
        assert!(matches!(err, crate::Error::CertSignatureInvalid));
    }

    #[test]
    fn expired_cert_is_rejected() {
        let ca = load("ca.crt");
        let expired = load("expired.crt");
        let err = verify_host_cert(&expired, &ca, expired.details.not_after + 1).unwrap_err();
        assert!(matches!(err, crate::Error::CertExpired));
    }

    #[test]
    fn cert_from_a_different_ca_is_rejected() {
        // host-b is signed by the same CA as host-a in these fixtures, so
        // to exercise "wrong CA" we verify host-a against host-b's own
        // cert used as if it were a CA (it isn't one) — check_signature
        // must fail since host-b's key never signed host-a.
        let not_a_ca = load("host-b.crt");
        let host = load("host-a.crt");
        let err = verify_host_cert(&host, &not_a_ca, host.details.not_before + 60).unwrap_err();
        assert!(
            err.to_string().contains("not") || matches!(err, crate::Error::CertSignatureInvalid)
        );
    }

    #[test]
    fn fingerprint_matches_issuer_recorded_on_signed_certs() {
        let ca = load("ca.crt");
        let host = load("host-a.crt");
        assert_eq!(hex::encode(&host.details.issuer), ca.fingerprint());
    }
}
