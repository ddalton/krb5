//! Entry point for `fuzz/` (`cfg(fuzzing)` only): what PKINIT parses —
//! certificates, PEM and PKCS #12 files, keys, CMS from the KDC, and the
//! KDC's PA-PK-AS-REP.

use super::*;
use std::sync::OnceLock;

/// An anonymous ECDH request, made once, to read replies against.
fn request() -> &'static (Request, Vec<u8>) {
    static R: OnceLock<(Request, Vec<u8>)> = OnceLock::new();
    R.get_or_init(|| {
        let body = der::seq(&[]);
        let (_, req) = super::request(&RequestInput {
            identity: None,
            rfc6112_kdc: true,
            body: &body,
            nonce: 1,
            now: 1_700_000_000,
            usec: 0,
            freshness: None,
            group: DhGroup::P256,
        })
        .expect("an anonymous request");
        (req, body)
    })
}

/// The first octet picks a parser for the rest.
pub fn input(data: &[u8]) {
    let Some((&sel, d)) = data.split_first() else {
        return;
    };
    match sel % 7 {
        0 => {
            if let Ok(c) = x509::Cert::from_der(d) {
                let _ = c.public_key();
                let _ = c.key_usage(0);
                let _ = c.has_eku("1.3.6.1.5.2.3.5");
                let _ = c.san();
                let _ = x509::verify_chain(&c, &[], std::slice::from_ref(&c), 1_700_000_000);
            }
            let _ = x509::parse_certs(d);
        }
        1 => {
            if let Ok(b) = pem::blocks(d) {
                let _ = keys::PrivateKey::from_pem_blocks(&b);
            }
            let _ = Identity::from_pem(d, d);
            let _ = TrustAnchors::from_pem(d);
        }
        2 => {
            let _ = pkcs12::parse(d, Some("fuzz"));
            let _ = pkcs12::parse(d, None);
        }
        3 => {
            let _ = cms::verify(d, cms::ID_PKINIT_DHKEY_DATA, &[], 1_700_000_000);
            let _ = cms::verify(d, cms::ID_PKINIT_AUTH_DATA, &[], 1_700_000_000);
        }
        4 => {
            let _ = rsa::PublicKey::from_der(d);
            let _ = rsa::PrivateKey::from_der(d);
            let _ = ec::PrivateKey::from_sec1(d, None);
            let _ = dh::Group::from_domain_parameters(d);
            let _ = negotiate_group(d, DhGroup::Modp2048);
        }
        5 => {
            let (req, body) = request();
            let settings = Settings::default();
            let client = Principal::new(1, ["alice"], "FUZZ.EXAMPLE");
            let server = Principal::krbtgt("FUZZ.EXAMPLE");
            let _ = req.reply_key(&ReplyInput {
                settings: &settings,
                pa_value: d,
                realm: "FUZZ.EXAMPLE",
                client: &client,
                server: &server,
                as_req: body,
                enctype: 18,
                now: 1_700_000_000,
            });
        }
        _ => {
            let key = Key::new(18, vec![1; 32]).expect("AES-256 key");
            let _ = verify_anonymous(&[(PA_PKINIT_KX, d.to_vec())], &key, &key);
        }
    }
}
