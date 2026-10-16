//! GSS-API channel bindings (RFC 2744 §3.11, RFC 4121 §4.1.1.2): tie a
//! Kerberos authentication to the channel it travels over, usually a TLS
//! connection, so an AP-REQ captured from one TLS session cannot be
//! replayed through another.
//!
//! Both sides build the same [`ChannelBindings`]. The initiator puts their
//! MD5 hash in the authenticator checksum
//! ([`InitOptions::channel_bindings`](crate::initiator::InitOptions)), and the
//! acceptor compares it with its own
//! ([`AcceptOptions::channel_bindings`](crate::acceptor::AcceptOptions)).
//! The application data is what RFC 5929 and RFC 9266 define for TLS:
//! [`ChannelBindings::tls_server_end_point`] (the server certificate's
//! hash, what HTTP Negotiate uses), [`ChannelBindings::tls_exporter`] (TLS
//! 1.3) and [`ChannelBindings::tls_unique`].

use sha2::Digest;

use crate::der::Reader;

/// The bindings themselves, laid out as `gss_channel_bindings_struct`.
/// The address types and addresses are almost always zero and empty
/// (`GSS_C_AF_UNSPEC`), as MIT, Windows and every TLS binding leave them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ChannelBindings {
    /// `initiator_addrtype`: the `GSS_C_AF_*` family of `initiator_address`.
    pub initiator_addrtype: u32,
    /// `initiator_address`: the initiator's network address.
    pub initiator_address: Vec<u8>,
    /// `acceptor_addrtype`: the `GSS_C_AF_*` family of `acceptor_address`.
    pub acceptor_addrtype: u32,
    /// `acceptor_address`: the acceptor's network address.
    pub acceptor_address: Vec<u8>,
    /// `application_data`: the channel's binding data, e.g. RFC 5929
    /// `tls-server-end-point`.
    pub application_data: Vec<u8>,
}

impl ChannelBindings {
    /// Bindings carrying only `application_data`.
    pub fn new(application_data: impl Into<Vec<u8>>) -> Self {
        ChannelBindings {
            application_data: application_data.into(),
            ..Default::default()
        }
    }

    /// RFC 5929 §4 `tls-server-end-point`: `"tls-server-end-point:"` and
    /// the hash of the server's certificate (DER), with the hash function
    /// of the certificate's signature algorithm, SHA-256 in place of MD5
    /// or SHA-1. This is what HTTP Negotiate (and LDAP over TLS) binds
    /// to, and the client can compute it from the certificate the server
    /// presented. `None` if the certificate cannot be parsed or its
    /// signature algorithm names no hash (Ed25519, for one).
    pub fn tls_server_end_point(certificate: &[u8]) -> Option<Self> {
        let hash = match signature_hash(certificate)? {
            Hash::Sha256 => sha2::Sha256::digest(certificate).to_vec(),
            Hash::Sha224 => sha2::Sha224::digest(certificate).to_vec(),
            Hash::Sha384 => sha2::Sha384::digest(certificate).to_vec(),
            Hash::Sha512 => sha2::Sha512::digest(certificate).to_vec(),
        };
        let mut data = b"tls-server-end-point:".to_vec();
        data.extend_from_slice(&hash);
        Some(Self::new(data))
    }

    /// RFC 9266 `tls-exporter`: `"tls-exporter:"` and the 32 octets the
    /// TLS library exports with the label `EXPORTER-Channel-Binding` and
    /// no context. The binding for TLS 1.3.
    pub fn tls_exporter(exported: &[u8]) -> Self {
        let mut data = b"tls-exporter:".to_vec();
        data.extend_from_slice(exported);
        Self::new(data)
    }

    /// RFC 5929 §3 `tls-unique`: `"tls-unique:"` and the first Finished
    /// message of the TLS (1.2 or earlier) handshake.
    pub fn tls_unique(finished: &[u8]) -> Self {
        let mut data = b"tls-unique:".to_vec();
        data.extend_from_slice(finished);
        Self::new(data)
    }

    /// The RFC 4121 §4.1.1.2 Bnd field: MD5 over the address types,
    /// lengths (little-endian, as MIT's `kg_checksum_channel_bindings`
    /// lays them out) and values.
    pub(crate) fn md5(&self) -> [u8; 16] {
        let mut buf = Vec::new();
        for (ty, data) in [
            (Some(self.initiator_addrtype), &self.initiator_address),
            (Some(self.acceptor_addrtype), &self.acceptor_address),
            (None, &self.application_data),
        ] {
            if let Some(t) = ty {
                buf.extend_from_slice(&t.to_le_bytes());
            }
            buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
            buf.extend_from_slice(data);
        }
        crate::md5::md5(&buf)
    }
}

#[derive(Debug, PartialEq)]
enum Hash {
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

/// The hash RFC 5929 §4.1 picks for a certificate: its signature
/// algorithm's, upgraded to SHA-256 from MD5 or SHA-1.
fn signature_hash(cert: &[u8]) -> Option<Hash> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, ... }
    let mut c = Reader::new(cert).seq().ok()?;
    c.next().ok()?;
    let mut alg = c.seq().ok()?;
    let oid = alg.expect(0x06).ok()?;
    let arc = |prefix: &[u8], last: u8| {
        oid.len() == prefix.len() + 1 && oid.starts_with(prefix) && oid[prefix.len()] == last
    };
    // 1.2.840.113549.1.1.x (PKCS #1) and 1.2.840.10045.4.x (ECDSA).
    const PKCS1: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01];
    const ECDSA_SHA2: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03];
    const ECDSA_SHA1: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04];
    // 2.16.840.1.101.3.4.3.x (DSA with SHA-2) and 1.2.840.10040.4.3
    // (DSA with SHA-1).
    const DSA_SHA2: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03];
    const X9_57: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04];
    Some(match () {
        // md5WithRSA, sha1WithRSA, ecdsa-with-SHA1, dsa-with-sha1.
        _ if arc(PKCS1, 4) || arc(PKCS1, 5) || arc(ECDSA_SHA1, 1) || arc(X9_57, 3) => Hash::Sha256,
        _ if arc(PKCS1, 14) || arc(ECDSA_SHA2, 1) || arc(DSA_SHA2, 1) => Hash::Sha224,
        _ if arc(PKCS1, 11) || arc(ECDSA_SHA2, 2) || arc(DSA_SHA2, 2) => Hash::Sha256,
        _ if arc(PKCS1, 12) || arc(ECDSA_SHA2, 3) => Hash::Sha384,
        _ if arc(PKCS1, 13) || arc(ECDSA_SHA2, 4) => Hash::Sha512,
        // RSASSA-PSS: the hash is in the parameters (RFC 4055), SHA-1 by
        // default.
        _ if arc(PKCS1, 10) => pss_hash(&mut alg)?,
        _ => return None,
    })
}

/// RSASSA-PSS-params `hashAlgorithm [0]`, SHA-1 (so SHA-256) if absent.
fn pss_hash(alg: &mut Reader<'_>) -> Option<Hash> {
    let Ok(mut params) = alg.seq() else {
        return Some(Hash::Sha256);
    };
    let Ok((0xA0, hash_alg)) = params.next() else {
        return Some(Hash::Sha256);
    };
    let mut h = Reader::new(hash_alg).seq().ok()?;
    let oid = h.expect(0x06).ok()?;
    // 2.16.840.1.101.3.4.2.x: sha256 (1), sha384 (2), sha512 (3), sha224 (4).
    const NIST_HASH: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02];
    match oid.strip_prefix(NIST_HASH) {
        Some([1]) => Some(Hash::Sha256),
        Some([2]) => Some(Hash::Sha384),
        Some([3]) => Some(Hash::Sha512),
        Some([4]) => Some(Hash::Sha224),
        // sha1 (1.3.14.3.2.26).
        None if oid == [0x2B, 0x0E, 0x03, 0x02, 0x1A] => Some(Hash::Sha256),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// The layout MIT hashes: three (type, length, value) triples, the
    /// application data without a type, all little-endian.
    #[test]
    fn the_hash_covers_mits_layout() {
        let cb = ChannelBindings {
            initiator_addrtype: 2,
            initiator_address: vec![127, 0, 0, 1],
            acceptor_addrtype: 2,
            acceptor_address: vec![10, 0, 0, 1],
            application_data: b"app".to_vec(),
        };
        let mut want = vec![2, 0, 0, 0, 4, 0, 0, 0, 127, 0, 0, 1];
        want.extend_from_slice(&[2, 0, 0, 0, 4, 0, 0, 0, 10, 0, 0, 1]);
        want.extend_from_slice(&[3, 0, 0, 0, b'a', b'p', b'p']);
        assert_eq!(cb.md5(), crate::md5::md5(&want));
        // Empty bindings are not "no bindings": twenty zero octets hashed.
        assert_eq!(
            hex(&ChannelBindings::default().md5()),
            hex(&crate::md5::md5(&[0; 20]))
        );
    }

    #[test]
    fn tls_bindings_carry_their_rfc_prefixes() {
        assert_eq!(
            ChannelBindings::tls_exporter(&[7; 32]).application_data[..13],
            *b"tls-exporter:"
        );
        assert_eq!(
            ChannelBindings::tls_unique(&[1, 2]).application_data,
            b"tls-unique:\x01\x02"
        );
    }

    /// The PKINIT test certificates (as `openssl x509 -text` names their
    /// algorithms): sha256WithRSAEncryption hashed with SHA-256,
    /// ecdsa-with-SHA384 with SHA-384, the certificate whole.
    #[cfg(feature = "pkinit")]
    #[test]
    fn tls_server_end_point_hashes_the_certificate() {
        let der = |pem: &str| {
            let blocks = crate::pkinit::pem::blocks(pem.as_bytes()).unwrap();
            blocks
                .into_iter()
                .find(|(l, _)| l == "CERTIFICATE")
                .unwrap()
                .1
        };
        let rsa = der(include_str!("pkinit/testdata/kdc.pem"));
        let ec = der(include_str!("pkinit/testdata/ec-kdc.pem"));
        for (cert, hash) in [
            (&rsa, sha2::Sha256::digest(&rsa).to_vec()),
            (&ec, sha2::Sha384::digest(&ec).to_vec()),
        ] {
            let cb = ChannelBindings::tls_server_end_point(cert).unwrap();
            let mut want = b"tls-server-end-point:".to_vec();
            want.extend_from_slice(&hash);
            assert_eq!(cb.application_data, want);
        }
    }

    /// Hand-built certificate shells: only the signature algorithm matters.
    #[test]
    fn the_hash_follows_the_signature_algorithm() {
        use crate::der::{seq, tlv};
        let cert = |alg: Vec<u8>| seq(&[seq(&[]), alg, tlv(0x03, &[0])]);
        let oid = |o: &[u8]| seq(&[tlv(0x06, o)]);
        let pkcs1 = |n: u8| oid(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, n]);
        let ecdsa = |n: u8| oid(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, n]);
        for (alg, want) in [
            (pkcs1(4), Hash::Sha256),  // md5WithRSA, upgraded
            (pkcs1(5), Hash::Sha256),  // sha1WithRSA, upgraded
            (pkcs1(11), Hash::Sha256), // sha256WithRSA
            (pkcs1(12), Hash::Sha384),
            (pkcs1(13), Hash::Sha512),
            (pkcs1(14), Hash::Sha224),
            (ecdsa(2), Hash::Sha256),
            (ecdsa(3), Hash::Sha384),
            (ecdsa(4), Hash::Sha512),
            (
                oid(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x01]),
                Hash::Sha256,
            ),
        ] {
            assert_eq!(signature_hash(&cert(alg)), Some(want));
        }
        // PSS: from the parameters, SHA-1 (so SHA-256) by default.
        let pss = |params: Vec<u8>| {
            seq(&[
                tlv(0x06, &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 10]),
                params,
            ])
        };
        let sha384 = seq(&[tlv(
            0x06,
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 2],
        )]);
        assert_eq!(
            signature_hash(&cert(pss(seq(&[tlv(0xA0, &sha384)])))),
            Some(Hash::Sha384)
        );
        assert_eq!(signature_hash(&cert(pss(seq(&[])))), Some(Hash::Sha256));
        // Ed25519 (1.3.101.112) names no hash; garbage is no certificate.
        assert_eq!(signature_hash(&cert(oid(&[0x2B, 0x65, 0x70]))), None);
        assert_eq!(signature_hash(b"not a certificate"), None);
    }
}
