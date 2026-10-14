//! Interop against MIT Kerberos — the gate that vectors cannot close.
//!
//! Every other test in this crate is pinned to published RFC vectors or to a
//! second implementation written from the RFC text. Both are strong, and
//! neither can prove that a real peer accepts our bytes or that we
//! accept a real peer's.
//!
//! The fixtures here were produced by MIT krb5's own `libgssapi`
//! (`python3-gssapi`) against a live KDC, in a Lima VM, on 2026-08-27:
//! a real AS-REQ/TGS-REQ for a real service principal, then
//! `gss_init_sec_context`, `gss_get_mic` and `gss_wrap`. This crate is
//! the acceptor. If these pass, the ticket path, the key derivation, the
//! RFC 4121 framing and the enctype handling all agree with the
//! reference implementation.
//!
//! Regenerating: see `testdata/README.md`. The realm is FLINT.TEST, with
//! one service principal per enctype so each ticket path is exercised.

use crate::acceptor::{KerberosContext, Keytab};

/// The fixtures are RECORDED, so their authenticators are as old as the
/// file. Production uses the 5-minute default; replaying a capture needs
/// the check stood down, which is why
/// [`KerberosContext::accept_token_with_skew`] exists.
const SKEW: i64 = 100 * 365 * 24 * 3600;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Contexts established WITHOUT mutual auth: complete after one step, so
/// these carry MIC and Wrap tokens — and the acceptor must reply with NO AP-REP.
fn fixtures() -> serde_json::Value {
    serde_json::from_str(include_str!("../testdata/interop.json")).expect("interop.json")
}

/// Contexts established WITH mutual auth: the initiator is NOT complete
/// until it has our AP-REP, so these pin the AP-REP path.
fn fixtures_mutual() -> serde_json::Value {
    serde_json::from_str(include_str!("../testdata/interop-mutual.json"))
        .expect("interop-mutual.json")
}

fn keytab() -> Keytab {
    Keytab::load(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/interop.keytab"
    ))
    .expect("interop keytab")
}

/// MIT issues the ticket; we decrypt it.
///
/// This is the single most load-bearing assertion in the tree. It fails
/// against every one of the six defects the audit found: the 0x99/0xAA
/// swap, the missing n-fold, the absent confounder, the HMAC sealed
/// inside the ciphertext, key usage 8 instead of 2, and SHA-256 where
/// enctype 20 needs SHA-384.
#[test]
fn a_real_kdc_ticket_decrypts() {
    let kt = keytab();
    let f = fixtures();
    let mut checked = 0;
    for (label, e) in f.as_object().unwrap() {
        let ap_req = unhex(e["ap_req"].as_str().unwrap());
        let (ctx, ap_rep) = KerberosContext::accept_token_with_skew(&kt, &ap_req, SKEW)
            .unwrap_or_else(|err| panic!("etype {label}: accept_token failed: {err}"));
        assert!(ctx.established, "etype {label}: context must establish");
        assert!(
            ctx.client_principal.starts_with("testuser@"),
            "etype {label}: wrong client {}",
            ctx.client_principal
        );
        // These fixtures did NOT request mutual auth, so there must be
        // no AP-REP — see the dedicated test below.
        assert!(
            ap_rep.is_empty(),
            "etype {label}: an AP-REP was sent for a request that did not ask for one"
        );
        checked += 1;
    }
    assert_eq!(checked, 4, "all four enctype fixtures must be exercised");
}

/// `[libdefaults] clockskew` decides whether a two-month-old capture is
/// still acceptable: a year of skew lets it through, the default does not.
#[test]
fn clockskew_from_krb5_conf_is_applied() {
    let kt = keytab();
    let f = fixtures();
    let ap_req = unhex(
        f.as_object().unwrap().values().next().unwrap()["ap_req"]
            .as_str()
            .unwrap(),
    );
    let year = crate::Krb5Conf::parse("[libdefaults]\n clockskew = 31536000\n").unwrap();
    assert!(KerberosContext::accept_token_with_conf(&kt, &ap_req, &year).is_ok());
    assert!(
        KerberosContext::accept_token_with_conf(&kt, &ap_req, &crate::Krb5Conf::empty()).is_err()
    );
}

/// MIT signs; we verify. Exercises the RFC 4121 MIC framing, the
/// per-message key usages, and the §2 base-key selection — MIT's
/// initiator supplies a subkey, which an early version of the acceptor
/// discarded.
#[test]
fn a_real_mic_from_mit_verifies() {
    let kt = keytab();
    let f = fixtures();
    for (label, e) in f.as_object().unwrap() {
        let (ctx, _) = KerberosContext::accept_token_with_skew(
            &kt,
            &unhex(e["ap_req"].as_str().unwrap()),
            SKEW,
        )
        .unwrap_or_else(|err| panic!("etype {label}: {err}"));
        let tokens = ctx
            .per_message_tokens()
            .unwrap_or_else(|err| panic!("etype {label}: {err}"));
        let msg = unhex(e["message"].as_str().unwrap());
        let mic = unhex(e["mic"].as_str().unwrap());
        tokens
            .verify_mic(&mic, &msg)
            .unwrap_or_else(|err| panic!("etype {label}: MIT MIC rejected: {err}"));

        // Anti-vacuity: the same token must NOT verify over a different
        // message, or "verifies" would mean nothing.
        let mut other = msg.clone();
        other[0] ^= 0x01;
        assert!(
            tokens.verify_mic(&mic, &other).is_err(),
            "etype {label}: MIC verified over the wrong message"
        );
    }
}

/// MIT seals; we unwrap. The confidentiality path end to end.
#[test]
fn a_real_wrap_token_from_mit_unwraps() {
    let kt = keytab();
    let f = fixtures();
    for (label, e) in f.as_object().unwrap() {
        let (ctx, _) = KerberosContext::accept_token_with_skew(
            &kt,
            &unhex(e["ap_req"].as_str().unwrap()),
            SKEW,
        )
        .unwrap_or_else(|err| panic!("etype {label}: {err}"));
        let tokens = ctx.per_message_tokens().unwrap();
        let msg = unhex(e["message"].as_str().unwrap());

        let sealed = unhex(e["wrap"].as_str().unwrap());
        let opened = tokens
            .unwrap(&sealed)
            .unwrap_or_else(|err| panic!("etype {label}: MIT wrap rejected: {err}"));
        assert_eq!(opened.message, msg, "etype {label}: plaintext mismatch");

        // A flipped octet inside the token must not open.
        let mut bad = sealed.clone();
        let n = bad.len();
        bad[n - 1] ^= 0x01;
        assert!(
            tokens.unwrap(&bad).is_err(),
            "etype {label}: a corrupted wrap token opened"
        );
    }
}

/// RFC 4120 §3.2.4: an AP-REP answers MUTUAL-REQUIRED and nothing else.
///
/// An early version of the acceptor discarded `ap-options` and replied with an AP-REP every time. A
/// client that did not ask for mutual auth is ALREADY established when it
/// sends the AP-REQ; handed an unexpected token it feeds it to GSS anyway
/// and gets "Context is already fully established", after which libtirpc
/// abandons the context — with no GSS error of its own to explain it.
/// That is exactly how `mount -o sec=krb5p` failed with a bare
/// "access denied by server".
#[test]
fn an_ap_rep_is_sent_only_when_mutual_auth_is_requested() {
    let kt = keytab();

    // MUTUAL-REQUIRED set: an AP-REP is required.
    let m = fixtures_mutual();
    let mut with = 0;
    for (label, e) in m.as_object().unwrap() {
        let (_ctx, ap_rep) = KerberosContext::accept_token_with_skew(
            &kt,
            &unhex(e["ap_req"].as_str().unwrap()),
            SKEW,
        )
        .unwrap_or_else(|err| panic!("etype {label}: {err}"));
        assert!(
            !ap_rep.is_empty(),
            "etype {label}: MUTUAL-REQUIRED was set and no AP-REP came back"
        );
        with += 1;
    }

    // Not set: there must be NO token at all.
    let n = fixtures();
    let mut without = 0;
    for (label, e) in n.as_object().unwrap() {
        let (_ctx, ap_rep) = KerberosContext::accept_token_with_skew(
            &kt,
            &unhex(e["ap_req"].as_str().unwrap()),
            SKEW,
        )
        .unwrap_or_else(|err| panic!("etype {label}: {err}"));
        assert!(
            ap_rep.is_empty(),
            "etype {label}: an AP-REP was sent unasked — the shipped bug"
        );
        without += 1;
    }

    assert_eq!(with, 4, "both fixture sets must cover all four enctypes");
    assert_eq!(without, 4);
}

/// NEGATIVE LEG: a real MIT ticket, refused once its own endtime has
/// passed.
///
/// The accept path used to check only the AUTHENTICATOR's clock skew.
/// The authenticator is minted fresh by whoever holds the session key,
/// so it is always "now" — which made the ticket's own validity period
/// unenforced, and an expired ticket good forever. `EncTicketPart` even
/// carried `#[allow(dead_code)]`, the compiler saying `endtime` was
/// never read.
///
/// The clock is injected rather than slept for: these fixtures were
/// recorded on 2026-08-27, so an assertion against the real clock would
/// be false today and true tomorrow. Reading the ticket's endtime out of
/// the accepted context is not possible (it is not kept), so the pivot is
/// the fixture's recording date instead: one year on, every one of these
/// tickets is long expired.
#[test]
fn a_real_ticket_is_refused_after_its_endtime() {
    let kt = keytab();
    let f = fixtures();
    // 2027-08-27, a year after the fixtures were captured. MIT's default
    // ticket life is 10 hours and its maximum renewable life 7 days, so
    // no ticket here can still be inside its window.
    const A_YEAR_ON: i64 = 1_819_000_000;
    let mut checked = 0;
    for (label, e) in f.as_object().unwrap() {
        let ap_req = unhex(e["ap_req"].as_str().unwrap());
        // The SAME tolerance production uses. SKEW is not used here: a
        // 100-year tolerance would forgive the expiry, which is exactly
        // how the recorded fixtures keep working in the tests above.
        let err = KerberosContext::accept_token_at(&kt, &ap_req, 300, A_YEAR_ON)
            .err()
            .unwrap_or_else(|| panic!("etype {label}: an expired ticket was ACCEPTED"));
        let msg = err.to_string();
        assert!(
            msg.contains("ticket expired"),
            "etype {label}: refused, but not for the ticket: {msg}"
        );
        // It must fail on the TICKET, not on the authenticator that
        // happens to be equally old -- otherwise this leg would pass
        // against a server that still never looks at endtime.
        assert!(
            !msg.contains("Time skew"),
            "etype {label}: refused for authenticator skew, which proves nothing \
             about the ticket: {msg}"
        );
        checked += 1;
    }
    assert!(checked >= 1, "no fixtures exercised");
}

/// ACCEPTED CONTROL for the leg above.
///
/// Same fixtures, same code path, THE SAME CLOCK -- only the tolerance
/// differs. A refusal leg passes just as well against an accept path
/// that is simply broken, so the variable has to be reduced to one: at
/// 300 s these tickets are refused, at a 100-year tolerance the very
/// same call at the very same instant succeeds. That also pins why the
/// recorded fixtures above keep working.
#[test]
fn the_same_tickets_at_the_same_instant_pass_under_a_wide_tolerance() {
    let kt = keytab();
    let f = fixtures();
    const A_YEAR_ON: i64 = 1_819_000_000;
    let mut checked = 0;
    for (label, e) in f.as_object().unwrap() {
        let ap_req = unhex(e["ap_req"].as_str().unwrap());
        let (ctx, _) = KerberosContext::accept_token_at(&kt, &ap_req, SKEW, A_YEAR_ON)
            .unwrap_or_else(|err| panic!("etype {label}: control failed: {err}"));
        assert!(ctx.established, "etype {label}: control must establish");
        checked += 1;
    }
    assert!(checked >= 1, "no fixtures exercised");
}
