//! MIT krb5's own crypto known-answer tests, run against this crate.
//!
//! `testdata/mit-crypto.json` is the enctype 17-20 subset of the tables in
//! MIT's `src/lib/crypto/crypto_tests/` (`t_decrypt.c`, `t_cksums.c`,
//! `t_derive.c`, `t_str2key.c`, `t_prf.c`), extracted by
//! `scripts/import-mit-vectors.py`. Where the RFC vectors cover one
//! plaintext length or one key usage, MIT's cover several: empty, one
//! octet, under a block, over a block, and usages 0 through 4. The
//! ciphertexts were made with MIT's random confounders, so they are not a
//! second copy of anything in the RFCs.
//!
//! Every vector is checked; none is skipped.

use crate::kdf::{self, Enctype, KeyUse};
use crate::key::Key;
use crate::profile;
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!("../testdata/mit-crypto.json")).expect("mit-crypto.json")
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn field(v: &Value, name: &str) -> Vec<u8> {
    unhex(
        v[name]
            .as_str()
            .unwrap_or_else(|| panic!("{name} missing in {v}")),
    )
}

fn etype(v: &Value) -> i32 {
    v["enctype"].as_i64().unwrap() as i32
}

fn usage(v: &Value) -> u32 {
    v["usage"].as_u64().unwrap() as u32
}

/// Iterate one table, asserting it is not empty and covers all four
/// enctypes, so a broken import fails here rather than passing vacuously.
fn table(name: &str) -> Vec<Value> {
    let all = vectors()[name].as_array().unwrap().clone();
    for e in 17..=20 {
        assert!(
            all.iter().any(|v| etype(v) == e),
            "{name} has no enctype {e} vector"
        );
    }
    all
}

/// `t_decrypt.c`: decrypt MIT's ciphertext, then re-encrypt with the
/// confounder MIT chose and get MIT's exact octets back. The second half
/// pins the encrypt path too, which a random confounder normally hides.
#[test]
fn mit_t_decrypt() {
    for (i, v) in table("decrypt").iter().enumerate() {
        let key = Key::new(etype(v), field(v, "key")).unwrap();
        let ct = field(v, "ciphertext");
        let pt = field(v, "plaintext");
        assert_eq!(key.decrypt(usage(v), &ct).unwrap(), pt, "decrypt {i}: {v}");

        let e = profile::Enctype::from_i32(etype(v)).unwrap();
        let k = kdf::Enctype::from_i32(etype(v)).unwrap();
        let ke = kdf::derive_key(k, key.bytes(), usage(v), KeyUse::Encryption).unwrap();
        let ki = kdf::derive_key(k, key.bytes(), usage(v), KeyUse::Integrity).unwrap();
        let body = &ct[..ct.len() - e.checksum_len()];
        let clear = profile::aes_cts_decrypt(&ke, &[0; 16], body).unwrap();
        let confounder = &clear[..e.confounder_len()];
        assert_eq!(
            profile::encrypt_with_confounder(e, &ke, &ki, confounder, &pt).unwrap(),
            ct,
            "re-encrypt {i}: {v}"
        );

        // And the MAC really is checked: one flipped octet must not decrypt.
        let mut bad = ct.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(key.decrypt(usage(v), &bad).is_err(), "tampered {i}: {v}");
    }
}

/// `t_cksums.c`: the keyed checksum, its verification, and the
/// checksum type MIT pairs with each enctype.
#[test]
fn mit_t_cksums() {
    for (i, v) in table("checksum").iter().enumerate() {
        let key = Key::new(etype(v), field(v, "key")).unwrap();
        let msg = field(v, "plaintext");
        let want = field(v, "checksum");
        assert_eq!(
            key.checksum(usage(v), &msg).unwrap(),
            want,
            "checksum {i}: {v}"
        );
        assert!(
            key.verify_checksum(usage(v), &msg, &want).unwrap(),
            "verify {i}: {v}"
        );
        assert!(
            !key.verify_checksum(usage(v) + 1, &msg, &want).unwrap(),
            "wrong usage {i}"
        );
        assert_eq!(
            i64::from(key.checksum_type()),
            v["cksumtype"].as_i64().unwrap(),
            "{v}"
        );
    }
}

/// `t_derive.c`: DK for 17/18 and KDF-HMAC-SHA2 for 19/20, on MIT's
/// `usage | type-octet` constants. Each is checked twice: through the raw
/// KDF with MIT's constant and output length, and through
/// [`kdf::derive_key`], which has to work both out for itself.
#[test]
fn mit_t_derive() {
    for (i, v) in table("derive").iter().enumerate() {
        let e = Enctype::from_i32(etype(v)).unwrap();
        let base = field(v, "key");
        let constant = field(v, "constant");
        let want = field(v, "derived");

        let raw = match v["alg"].as_str().unwrap() {
            "DERIVE_RFC3961" => kdf::dk(&base, &constant, want.len()).unwrap(),
            "DERIVE_SP800_108_HMAC" => {
                kdf::kdf_hmac_sha2(e, &base, &constant, None, want.len() as u32 * 8).unwrap()
            }
            other => panic!("unexpected derivation {other} for enctype {}", e.etype()),
        };
        assert_eq!(raw, want, "raw derive {i}: {v}");

        assert_eq!(constant.len(), 5, "{v}");
        let usage = u32::from_be_bytes(constant[..4].try_into().unwrap());
        let which = match constant[4] {
            0x99 => KeyUse::Checksum,
            0xAA => KeyUse::Encryption,
            0x55 => KeyUse::Integrity,
            o => panic!("unexpected type octet {o:#04x}"),
        };
        assert_eq!(
            kdf::derive_key(e, &base, usage, which).unwrap(),
            want,
            "derive_key {i}: {v}"
        );
    }
}

/// `t_str2key.c`: PBKDF2 plus the second stage, including the RFC 3962
/// Appendix B passphrases (block-size and over-block-size, the g-clef) and
/// MIT's own vectors with other salts. MIT runs most with its test-only
/// `k5_allow_weak_pbkdf2iter`; the one it runs without that flag expects
/// `KRB5_ERR_BAD_S2K_PARAMS`, and this crate must refuse it the same way.
#[test]
fn mit_t_str2key() {
    let mut refused = 0;
    for (i, v) in table("string_to_key").iter().enumerate() {
        let e = Enctype::from_i32(etype(v)).unwrap();
        let password = field(v, "password");
        let salt = field(v, "salt");
        let params = v["params"]
            .as_str()
            .map(|p| <[u8; 4]>::try_from(unhex(p)).unwrap());
        let allow_weak = v["allow_weak"].as_bool().unwrap();

        if v["error"].as_str() == Some("KRB5_ERR_BAD_S2K_PARAMS") {
            assert!(!allow_weak, "{v}");
            let err = kdf::string_to_key(e, &password, &salt, params).unwrap_err();
            assert!(
                matches!(err, kdf::KdfError::IterationsTooLow { .. }),
                "str2key {i} should be refused: {err}"
            );
            refused += 1;
            continue;
        }
        assert!(v["error"].is_null(), "unknown expected error in {v}");
        let got = if allow_weak {
            kdf::string_to_key_allow_weak(e, &password, &salt, params)
        } else {
            kdf::string_to_key(e, &password, &salt, params)
        }
        .unwrap();
        assert_eq!(got, field(v, "key"), "str2key {i}: {v}");
    }
    assert_eq!(
        refused, 1,
        "MIT's one weak-iteration refusal must be exercised"
    );
}

/// `t_prf.c`: the RFC 3961 simplified-profile PRF for 17/18 and the RFC
/// 8009 PRF for 19/20, through [`Key::prf`]. These are the only published
/// vectors for the 17/18 PRF; RFC 3962 has none.
#[test]
fn mit_t_prf() {
    for (i, v) in table("prf").iter().enumerate() {
        let key = Key::new(etype(v), field(v, "key")).unwrap();
        assert_eq!(
            key.prf(&field(v, "input")).unwrap(),
            field(v, "output"),
            "prf {i}: {v}"
        );
    }
}
