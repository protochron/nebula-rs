//! A minimal DER TLV codec for Nebula's certificate v2 wire format.
//!
//! This is intentionally not a general-purpose ASN.1 library: nebula v2
//! certs use a small, fixed set of context-specific tags (copied below
//! from `cert/cert_v2.go`'s `TagCert*`/`TagDetails*` constants in
//! slackhq/nebula v1.10.3) and DER's definite-length encoding only. A
//! generic ASN.1 crate would still need every one of these tags spelled
//! out by hand to match nebula's exact (non-canonical) encoding, so a
//! small dedicated codec is both simpler and easier to audit against the
//! Go source directly.

use crate::error::Error;

const CLASS_CONSTRUCTED: u8 = 0x20;
const CLASS_CONTEXT: u8 = 0x80;

const TAG_CERT_DETAILS: u8 = 0 | CLASS_CONSTRUCTED | CLASS_CONTEXT; // 0xA0
const TAG_CERT_CURVE: u8 = 1 | CLASS_CONTEXT; // 0x81
const TAG_CERT_PUBLIC_KEY: u8 = 2 | CLASS_CONTEXT; // 0x82
const TAG_CERT_SIGNATURE: u8 = 3 | CLASS_CONTEXT; // 0x83

const TAG_DETAILS_NAME: u8 = 0 | CLASS_CONTEXT; // 0x80
const TAG_DETAILS_NETWORKS: u8 = 1 | CLASS_CONSTRUCTED | CLASS_CONTEXT; // 0xA1
const TAG_DETAILS_UNSAFE_NETWORKS: u8 = 2 | CLASS_CONSTRUCTED | CLASS_CONTEXT; // 0xA2
const TAG_DETAILS_GROUPS: u8 = 3 | CLASS_CONSTRUCTED | CLASS_CONTEXT; // 0xA3
const TAG_DETAILS_IS_CA: u8 = 4 | CLASS_CONTEXT; // 0x84
const TAG_DETAILS_NOT_BEFORE: u8 = 5 | CLASS_CONTEXT; // 0x85
const TAG_DETAILS_NOT_AFTER: u8 = 6 | CLASS_CONTEXT; // 0x86
const TAG_DETAILS_ISSUER: u8 = 7 | CLASS_CONTEXT; // 0x87

const UNIVERSAL_OCTET_STRING: u8 = 0x04;
const UNIVERSAL_UTF8_STRING: u8 = 0x0C;
const UNIVERSAL_SEQUENCE: u8 = 0x30;

fn write_tlv(out: &mut Vec<u8>, tag: u8, content: &[u8]) {
    out.push(tag);
    write_length(out, content.len());
    out.extend_from_slice(content);
}

fn write_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let first_nonzero = bytes
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(bytes.len() - 1);
        let significant = &bytes[first_nonzero..];
        out.push(0x80 | significant.len() as u8);
        out.extend_from_slice(significant);
    }
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    fn peek_tag(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    fn read_length(&mut self) -> Result<usize, Error> {
        let first = *self
            .data
            .get(self.pos)
            .ok_or_else(|| Error::Der("truncated length".into()))?;
        self.pos += 1;
        if first & 0x80 == 0 {
            return Ok(first as usize);
        }
        let num_bytes = (first & 0x7f) as usize;
        if num_bytes == 0 || num_bytes > 8 {
            return Err(Error::Der("unsupported length encoding".into()));
        }
        let end = self
            .pos
            .checked_add(num_bytes)
            .ok_or_else(|| Error::Der("length overflow".into()))?;
        let slice = self
            .data
            .get(self.pos..end)
            .ok_or_else(|| Error::Der("truncated length".into()))?;
        let mut buf = [0u8; 8];
        buf[8 - num_bytes..].copy_from_slice(slice);
        self.pos = end;
        Ok(u64::from_be_bytes(buf) as usize)
    }

    /// Reads a TLV whose tag must exactly match `expected_tag`, returning its content bytes.
    fn read_tlv(&mut self, expected_tag: u8) -> Result<&'a [u8], Error> {
        let tag = *self
            .data
            .get(self.pos)
            .ok_or_else(|| Error::Der("truncated tag".into()))?;
        if tag != expected_tag {
            return Err(Error::Der(format!(
                "expected tag {expected_tag:#x}, got {tag:#x}"
            )));
        }
        self.pos += 1;
        let len = self.read_length()?;
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| Error::Der("length overflow".into()))?;
        let content = self
            .data
            .get(self.pos..end)
            .ok_or_else(|| Error::Der("truncated content".into()))?;
        self.pos = end;
        Ok(content)
    }

    /// Like `read_tlv`, but returns the full tag+length+content bytes —
    /// needed to reproduce nebula's `rawDetails`, which the certificate
    /// signature covers verbatim (see `signing_bytes` below).
    fn read_tlv_raw(&mut self, expected_tag: u8) -> Result<&'a [u8], Error> {
        let start = self.pos;
        self.read_tlv(expected_tag)?;
        Ok(&self.data[start..self.pos])
    }

    /// Reads a TLV only if the next tag matches `expected_tag`; otherwise
    /// leaves the cursor untouched. Mirrors nebula's `ReadOptionalASN1`.
    fn read_tlv_opt(&mut self, expected_tag: u8) -> Result<Option<&'a [u8]>, Error> {
        if self.peek_tag() == Some(expected_tag) {
            Ok(Some(self.read_tlv(expected_tag)?))
        } else {
            Ok(None)
        }
    }
}

/// Standard DER INTEGER encoding: minimal big-endian two's complement.
/// Nebula's timestamps are always non-negative unix seconds, so this
/// assumes `v >= 0` (matches `cryptobyte.AddASN1Int64WithTag`'s output for
/// non-negative input).
fn encode_der_int(v: i64) -> Vec<u8> {
    let bytes = v.to_be_bytes();
    let mut i = 0;
    while i < 7 && bytes[i] == 0 && (bytes[i + 1] & 0x80) == 0 {
        i += 1;
    }
    bytes[i..].to_vec()
}

fn decode_der_int(b: &[u8]) -> Result<i64, Error> {
    if b.is_empty() || b.len() > 8 {
        return Err(Error::Der("invalid integer length".into()));
    }
    let mut buf = if b[0] & 0x80 != 0 {
        [0xffu8; 8]
    } else {
        [0u8; 8]
    };
    buf[8 - b.len()..].copy_from_slice(b);
    Ok(i64::from_be_bytes(buf))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    Curve25519,
    P256,
}

impl Curve {
    fn from_byte(b: u8) -> Result<Self, Error> {
        match b {
            0 => Ok(Curve::Curve25519),
            1 => Ok(Curve::P256),
            _ => Err(Error::Der(format!("unknown curve {b}"))),
        }
    }
    fn to_byte(self) -> u8 {
        match self {
            Curve::Curve25519 => 0,
            Curve::P256 => 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Network {
    pub addr: std::net::IpAddr,
    pub prefix_len: u8,
}

impl Network {
    /// Nebula encodes a network as `Network ::= OCTET STRING (SIZE (5,17))`
    /// — 4 or 16 address bytes followed by one prefix-length byte, matching
    /// Go's `netip.Prefix.MarshalBinary`/`UnmarshalBinary`.
    fn decode(b: &[u8]) -> Result<Self, Error> {
        match b.len() {
            5 => Ok(Network {
                addr: std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]).into(),
                prefix_len: b[4],
            }),
            17 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&b[..16]);
                Ok(Network {
                    addr: std::net::Ipv6Addr::from(octets).into(),
                    prefix_len: b[16],
                })
            }
            n => Err(Error::Der(format!("invalid network length {n}"))),
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut v = match self.addr {
            std::net::IpAddr::V4(a) => a.octets().to_vec(),
            std::net::IpAddr::V6(a) => a.octets().to_vec(),
        };
        v.push(self.prefix_len);
        v
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Details {
    pub name: String,
    pub networks: Vec<Network>,
    pub unsafe_networks: Vec<Network>,
    pub groups: Vec<String>,
    pub is_ca: bool,
    pub not_before: i64,
    pub not_after: i64,
    /// Raw fingerprint bytes of the issuing CA (hex-decoded on the Go
    /// side before being stored in the cert); empty for a CA certificate.
    pub issuer: Vec<u8>,
}

#[cfg_attr(not(test), allow(dead_code))]
fn encode_details(d: &Details) -> Vec<u8> {
    let mut inner = Vec::new();
    write_tlv(&mut inner, TAG_DETAILS_NAME, d.name.as_bytes());

    if !d.networks.is_empty() {
        let mut nets = Vec::new();
        for n in &d.networks {
            write_tlv(&mut nets, UNIVERSAL_OCTET_STRING, &n.encode());
        }
        write_tlv(&mut inner, TAG_DETAILS_NETWORKS, &nets);
    }
    if !d.unsafe_networks.is_empty() {
        let mut nets = Vec::new();
        for n in &d.unsafe_networks {
            write_tlv(&mut nets, UNIVERSAL_OCTET_STRING, &n.encode());
        }
        write_tlv(&mut inner, TAG_DETAILS_UNSAFE_NETWORKS, &nets);
    }
    if !d.groups.is_empty() {
        let mut groups = Vec::new();
        for g in &d.groups {
            write_tlv(&mut groups, UNIVERSAL_UTF8_STRING, g.as_bytes());
        }
        write_tlv(&mut inner, TAG_DETAILS_GROUPS, &groups);
    }
    if d.is_ca {
        write_tlv(&mut inner, TAG_DETAILS_IS_CA, &[0xff]);
    }
    write_tlv(
        &mut inner,
        TAG_DETAILS_NOT_BEFORE,
        &encode_der_int(d.not_before),
    );
    write_tlv(
        &mut inner,
        TAG_DETAILS_NOT_AFTER,
        &encode_der_int(d.not_after),
    );
    if !d.issuer.is_empty() {
        write_tlv(&mut inner, TAG_DETAILS_ISSUER, &d.issuer);
    }

    let mut out = Vec::new();
    write_tlv(&mut out, TAG_CERT_DETAILS, &inner);
    out
}

fn decode_details(raw_tlv: &[u8]) -> Result<Details, Error> {
    let mut outer = Reader::new(raw_tlv);
    let inner_bytes = outer.read_tlv(TAG_CERT_DETAILS)?;
    let mut r = Reader::new(inner_bytes);

    let name_bytes = r.read_tlv(TAG_DETAILS_NAME)?;
    let name = String::from_utf8(name_bytes.to_vec())
        .map_err(|_| Error::Der("name is not valid utf-8".into()))?;

    let mut networks = Vec::new();
    if let Some(nets) = r.read_tlv_opt(TAG_DETAILS_NETWORKS)? {
        let mut nr = Reader::new(nets);
        while !nr.is_empty() {
            networks.push(Network::decode(nr.read_tlv(UNIVERSAL_OCTET_STRING)?)?);
        }
    }

    let mut unsafe_networks = Vec::new();
    if let Some(nets) = r.read_tlv_opt(TAG_DETAILS_UNSAFE_NETWORKS)? {
        let mut nr = Reader::new(nets);
        while !nr.is_empty() {
            unsafe_networks.push(Network::decode(nr.read_tlv(UNIVERSAL_OCTET_STRING)?)?);
        }
    }

    let mut groups = Vec::new();
    if let Some(gs) = r.read_tlv_opt(TAG_DETAILS_GROUPS)? {
        let mut gr = Reader::new(gs);
        while !gr.is_empty() {
            let g = gr.read_tlv(UNIVERSAL_UTF8_STRING)?;
            groups.push(
                String::from_utf8(g.to_vec())
                    .map_err(|_| Error::Der("group is not valid utf-8".into()))?,
            );
        }
    }

    let is_ca = r.read_tlv_opt(TAG_DETAILS_IS_CA)?.is_some();
    let not_before = decode_der_int(r.read_tlv(TAG_DETAILS_NOT_BEFORE)?)?;
    let not_after = decode_der_int(r.read_tlv(TAG_DETAILS_NOT_AFTER)?)?;
    let issuer = r.read_tlv_opt(TAG_DETAILS_ISSUER)?.unwrap_or(&[]).to_vec();

    Ok(Details {
        name,
        networks,
        unsafe_networks,
        groups,
        is_ca,
        not_before,
        not_after,
        issuer,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    pub details: Details,
    /// The complete `TAG_CERT_DETAILS` TLV, verbatim — this exact byte
    /// range (plus curve and public key) is what the CA's signature
    /// covers. See `signing_bytes`.
    pub raw_details: Vec<u8>,
    pub curve: Curve,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Certificate {
    pub fn decode(der_bytes: &[u8]) -> Result<Self, Error> {
        let mut top = Reader::new(der_bytes);
        let envelope = top.read_tlv(UNIVERSAL_SEQUENCE)?;
        let mut r = Reader::new(envelope);

        let raw_details = r.read_tlv_raw(TAG_CERT_DETAILS)?.to_vec();
        let details = decode_details(&raw_details)?;

        let curve = match r.read_tlv_opt(TAG_CERT_CURVE)? {
            Some(b) if b.len() == 1 => Curve::from_byte(b[0])?,
            Some(_) => return Err(Error::Der("invalid curve encoding".into())),
            None => Curve::Curve25519, // DEFAULT value per cert_v2.asn1
        };

        let public_key = r.read_tlv(TAG_CERT_PUBLIC_KEY)?.to_vec();
        let signature = r.read_tlv(TAG_CERT_SIGNATURE)?.to_vec();

        Ok(Certificate {
            details,
            raw_details,
            curve,
            public_key,
            signature,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut inner = Vec::new();
        inner.extend_from_slice(&self.raw_details);
        if self.curve != Curve::Curve25519 {
            write_tlv(&mut inner, TAG_CERT_CURVE, &[self.curve.to_byte()]);
        }
        write_tlv(&mut inner, TAG_CERT_PUBLIC_KEY, &self.public_key);
        write_tlv(&mut inner, TAG_CERT_SIGNATURE, &self.signature);

        let mut out = Vec::new();
        write_tlv(&mut out, UNIVERSAL_SEQUENCE, &inner);
        out
    }

    /// The exact bytes the CA's Ed25519 signature covers:
    /// `rawDetails || curve-byte || publicKey`, per
    /// `certificateV2.marshalForSigning` in cert/cert_v2.go.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(self.raw_details.len() + 1 + self.public_key.len());
        b.extend_from_slice(&self.raw_details);
        b.push(self.curve.to_byte());
        b.extend_from_slice(&self.public_key);
        b
    }

    /// The reduced encoding carried inside a handshake message
    /// (`NebulaHandshakeDetails.cert`): `rawDetails || signature` only —
    /// curve and public key are omitted because they're already conveyed
    /// by the Noise static key exchange itself. Mirrors
    /// `MarshalForHandshakes` in cert_v2.go.
    pub fn encode_for_handshake(&self) -> Vec<u8> {
        let mut inner = Vec::new();
        inner.extend_from_slice(&self.raw_details);
        write_tlv(&mut inner, TAG_CERT_SIGNATURE, &self.signature);
        let mut out = Vec::new();
        write_tlv(&mut out, UNIVERSAL_SEQUENCE, &inner);
        out
    }

    /// Reconstructs a full `Certificate` from the reduced handshake-message
    /// encoding plus the peer's Noise static public key learned from the
    /// handshake itself. Mirrors `cert.Recombine` in cert_v2.go.
    pub fn recombine(
        handshake_bytes: &[u8],
        peer_public_key: &[u8],
        curve: Curve,
    ) -> Result<Self, Error> {
        let mut top = Reader::new(handshake_bytes);
        let envelope = top.read_tlv(UNIVERSAL_SEQUENCE)?;
        let mut r = Reader::new(envelope);

        let raw_details = r.read_tlv_raw(TAG_CERT_DETAILS)?.to_vec();
        let details = decode_details(&raw_details)?;
        let signature = r.read_tlv(TAG_CERT_SIGNATURE)?.to_vec();

        Ok(Certificate {
            details,
            raw_details,
            curve,
            public_key: peer_public_key.to_vec(),
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::pem;

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!(
            "{}/tests/fixtures/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    fn fixture_json() -> serde_json::Value {
        let raw = fixture("fixtures.json");
        serde_json::from_slice(&raw).unwrap()
    }

    #[test]
    fn decodes_real_ca_cert() {
        let der = pem::decode(&fixture("ca.crt"), pem::CERTIFICATE_V2_BANNER).unwrap();
        let cert = Certificate::decode(&der).unwrap();
        let manifest = fixture_json();
        assert_eq!(cert.details.name, manifest["ca"]["name"]);
        assert_eq!(cert.details.is_ca, true);
        assert_eq!(
            cert.details.not_before,
            manifest["ca"]["not_before"].as_i64().unwrap()
        );
        assert_eq!(
            cert.details.not_after,
            manifest["ca"]["not_after"].as_i64().unwrap()
        );
        assert_eq!(cert.curve, Curve::Curve25519);
        assert_eq!(hex::encode(&cert.public_key).len(), 64);
    }

    #[test]
    fn decodes_real_host_cert_with_networks_and_groups() {
        let der = pem::decode(&fixture("host-a.crt"), pem::CERTIFICATE_V2_BANNER).unwrap();
        let cert = Certificate::decode(&der).unwrap();
        assert_eq!(cert.details.name, "host-a");
        assert_eq!(cert.details.groups, vec!["test".to_string()]);
        assert_eq!(cert.details.networks.len(), 1);
        assert_eq!(
            cert.details.networks[0].addr,
            "10.100.0.1".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(cert.details.networks[0].prefix_len, 16);
        assert!(!cert.details.issuer.is_empty());
    }

    #[test]
    fn encode_round_trips_a_decoded_cert() {
        let der = pem::decode(&fixture("host-a.crt"), pem::CERTIFICATE_V2_BANNER).unwrap();
        let cert = Certificate::decode(&der).unwrap();
        assert_eq!(cert.encode(), der);
    }

    #[test]
    fn decode_rejects_truncated_input() {
        let der = pem::decode(&fixture("host-a.crt"), pem::CERTIFICATE_V2_BANNER).unwrap();
        assert!(Certificate::decode(&der[..der.len() - 5]).is_err());
        assert!(Certificate::decode(&[]).is_err());
    }

    #[test]
    fn encode_for_handshake_omits_curve_and_public_key() {
        let der = pem::decode(&fixture("host-a.crt"), pem::CERTIFICATE_V2_BANNER).unwrap();
        let cert = Certificate::decode(&der).unwrap();
        let hs_bytes = cert.encode_for_handshake();
        assert!(hs_bytes.len() < der.len());
        let recombined = Certificate::recombine(&hs_bytes, &cert.public_key, cert.curve).unwrap();
        assert_eq!(recombined, cert);
    }

    #[test]
    fn encode_details_reproduces_raw_details() {
        // `Certificate::encode` reuses the verbatim `raw_details`, so nothing
        // else exercises the `encode_details` builder against real bytes. A
        // well-formed cert must re-encode its details byte-for-byte — this is
        // the only test that would catch a field-order/int-encoding bug in the
        // encode side. Covers both the host cert (groups + issuer present) and
        // the CA cert (is_ca set, no groups, no issuer).
        for name in ["host-a.crt", "ca.crt"] {
            let der = pem::decode(&fixture(name), pem::CERTIFICATE_V2_BANNER).unwrap();
            let cert = Certificate::decode(&der).unwrap();
            assert_eq!(encode_details(&cert.details), cert.raw_details, "{name}");
        }
    }
}
