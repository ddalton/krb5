//! RFC 4121 §4.2 per-message tokens: Wrap (TOK_ID `05 04`) and MIC (`04 04`).
//!
//! This is the acceptor side. flint's NFS server is the GSS *acceptor*: it
//! verifies tokens the client (the *initiator*) emitted, and emits tokens of
//! its own. That asymmetry is the whole reason this module exists as a
//! separate layer, because RFC 4121 §2 keys every operation off the sender's
//! role:
//!
//! ```text
//!                     MIC (04 04)          Wrap (05 04)
//!   sender acceptor    23 ACCEPTOR_SIGN     22 ACCEPTOR_SEAL
//!   sender initiator   25 INITIATOR_SIGN    24 INITIATOR_SEAL
//! ```
//!
//! A server therefore *emits* with 22/23 and *verifies* with 24/25. Swapping
//! the pair is the classic bug: it round-trips perfectly against itself —
//! both sides derive the same wrong key — and fails against every real peer.
//! [`Role::seal_usage`] and [`Role::sign_usage`] are the only place the
//! numbers appear, and [`PerMessageTokens`] always asks the *peer's* role for
//! a verify and its *own* role for an emit, so the swap is not expressible.
//!
//! Two further traps, both of which a self-round-trip test sails straight
//! past because the same mistake is made on both sides:
//!
//! * **The header goes at the END of the protected buffer.** §4.2.4 is
//!   `encrypt(plaintext | filler | "header")` and `get_mic(plaintext |
//!   "header")` — data first, header last. This is inverted from nearly every
//!   other protocol and there is no length field to catch it.
//! * **EC and RRC are zeroed in the crypto's copy of the header, but by
//!   different rules that sit one paragraph apart.** With confidentiality
//!   *only RRC* is zeroed and EC keeps its real value; without
//!   confidentiality *both* are zeroed. See [`header_for_seal`] and
//!   [`header_for_sign`].
//!
//! RFC 4121 publishes no test vectors at all — not one hex string beyond the
//! fixed constants — and it cannot, because EC, RRC, the filler octets and
//! the confounder are all sender's choice, so no canonical token exists. The
//! tests below therefore pin this layer three ways: RFC constants and the
//! §4.2.5 rotation semantics directly; the exact buffers handed to the crypto
//! asserted byte-for-byte (that is where the two traps above actually live);
//! and whole tokens against goldens produced by a *separate* implementation
//! written from the RFC text, which was itself first pinned to all 63
//! published RFC 3961/3962/8009 vectors. Those goldens are marked `derived_`,
//! never `rfcNNNN_`, because they are cross-implementation agreement and not
//! IETF-published answers.

use super::kdf;
use super::profile;

// ---------------------------------------------------------------------------
// Wire constants (RFC 4121 §4.2.6)
// ---------------------------------------------------------------------------

/// TOK_ID of a MIC token — RFC 4121 §4.2.6.1.
pub const TOK_ID_MIC: [u8; 2] = [0x04, 0x04];

/// TOK_ID of a Wrap token — RFC 4121 §4.2.6.2.
pub const TOK_ID_WRAP: [u8; 2] = [0x05, 0x04];

/// Both token classes carry a fixed 16-octet header (RFC 4121 §4.2.6).
pub const HEADER_LEN: usize = 16;

/// MIC filler, octets 3..8 — RFC 4121 §4.2.6.1: "five octets of hex value FF".
///
/// A Wrap token has ONE filler octet at `[3]`; a MIC token has FIVE at `[3..8)`.
/// Copy-pasting the Wrap header builder into the MIC path silently shifts
/// SND_SEQ by four octets, so the two are built by separate functions here.
pub const MIC_FILLER: [u8; 5] = [0xFF; 5];

/// Wrap filler, octet 3 — RFC 4121 §4.2.6.2: "the hex value FF".
pub const WRAP_FILLER: u8 = 0xFF;

// ---------------------------------------------------------------------------
// Flags (RFC 4121 §4.2.2)
// ---------------------------------------------------------------------------

/// Bit 0: the sender is the context acceptor.
pub const FLAG_SENT_BY_ACCEPTOR: u8 = 0x01;
/// Bit 1: confidentiality is provided. "It SHALL NOT be set in MIC tokens."
pub const FLAG_SEALED: u8 = 0x02;
/// Bit 2: the base key is a subkey asserted by the acceptor.
pub const FLAG_ACCEPTOR_SUBKEY: u8 = 0x04;

/// The three defined bits. §4.2.2: "The rest of available bits are reserved
/// for future use and MUST be cleared. The receiver MUST ignore unknown
/// flags." Ignoring them means *masking* before a test — never comparing the
/// whole octet against an expected value, which would reject a conforming
/// future peer.
pub const FLAGS_DEFINED: u8 = FLAG_SENT_BY_ACCEPTOR | FLAG_SEALED | FLAG_ACCEPTOR_SUBKEY;

// ---------------------------------------------------------------------------
// Key usages (RFC 4121 §2)
// ---------------------------------------------------------------------------

/// KG-USAGE-ACCEPTOR-SEAL — Wrap tokens sent by the acceptor.
pub const KG_USAGE_ACCEPTOR_SEAL: u32 = 22;
/// KG-USAGE-ACCEPTOR-SIGN — MIC tokens sent by the acceptor.
pub const KG_USAGE_ACCEPTOR_SIGN: u32 = 23;
/// KG-USAGE-INITIATOR-SEAL — Wrap tokens sent by the initiator.
pub const KG_USAGE_INITIATOR_SEAL: u32 = 24;
/// KG-USAGE-INITIATOR-SIGN — MIC tokens sent by the initiator.
pub const KG_USAGE_INITIATOR_SIGN: u32 = 25;

/// Which end of the security context an endpoint is.
///
/// flint's NFS server is always [`Role::Acceptor`]; [`Role::Initiator`] exists
/// so the tests can build the client-side tokens the server must verify
/// without hand-assembling them, and so the direction check has something to
/// reject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Acceptor,
}

impl Role {
    /// RFC 4121 §2 usage for a **Wrap** token sent by this role.
    ///
    /// Note this applies even when the Wrap token carries no confidentiality:
    /// "Even if the Wrap token does not provide for confidentiality, the same
    /// usage values specified above are used." Reaching for SIGN because
    /// nothing is being sealed is wrong and reads backwards to everyone.
    pub fn seal_usage(self) -> u32 {
        match self {
            Role::Acceptor => KG_USAGE_ACCEPTOR_SEAL,
            Role::Initiator => KG_USAGE_INITIATOR_SEAL,
        }
    }

    /// RFC 4121 §2 usage for a **MIC** token sent by this role.
    pub fn sign_usage(self) -> u32 {
        match self {
            Role::Acceptor => KG_USAGE_ACCEPTOR_SIGN,
            Role::Initiator => KG_USAGE_INITIATOR_SIGN,
        }
    }

    /// The value the SentByAcceptor flag carries when this role is the sender.
    pub fn sent_by_acceptor(self) -> bool {
        matches!(self, Role::Acceptor)
    }

    /// The other end. Every verify path derives its usage from this, never
    /// from the local role, so an acceptor cannot accidentally verify with
    /// acceptor usages.
    pub fn peer(self) -> Role {
        match self {
            Role::Acceptor => Role::Initiator,
            Role::Initiator => Role::Acceptor,
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    #[error("token truncated: {got} octets, need {need}")]
    Truncated { got: usize, need: usize },

    #[error("bad TOK_ID {got:02x?}, expected {want:02x?}")]
    BadTokId { got: [u8; 2], want: [u8; 2] },

    #[error("bad filler octets (RFC 4121 §4.2.6 requires 0xFF)")]
    BadFiller,

    #[error(
        "wrong direction: token claims SentByAcceptor={claimed}, \
         but this endpoint is the {local:?} — a reflected token"
    )]
    WrongDirection { claimed: bool, local: Role },

    #[error("Sealed flag set in a MIC token (RFC 4121 §4.2.2: it SHALL NOT be set)")]
    SealedMic,

    #[error(
        "token is flagged AcceptorSubkey but the acceptor asserted no subkey \
         on this context (RFC 4121 §2)"
    )]
    UnexpectedAcceptorSubkey,

    #[error("Wrap token has Sealed={got}, but the {want} service was requested")]
    WrongService { got: bool, want: &'static str },

    #[error("EC is {got} but this enctype's checksum is {want} octets")]
    BadExtraCount { got: usize, want: usize },

    #[error("integrity check failed")]
    IntegrityCheckFailed,

    #[error("the header bound into the ciphertext does not match the transmitted header")]
    HeaderMismatch,

    #[error("confounder must be {want} octets, got {got}")]
    BadConfounder { got: usize, want: usize },

    #[error("crypto: {0}")]
    Crypto(String),
}

// ---------------------------------------------------------------------------
// The crypto seam
// ---------------------------------------------------------------------------

/// The RFC 3961 §5.3/§5.4 operations RFC 4121 §4.2 calls into, as a trait.
///
/// The seam exists for two reasons. First, RFC 4121's `encrypt()` takes a
/// **base key and a usage number** and derives Kc/Ke/Ki itself (RFC 3961
/// §5.3); a token layer that derived a key and handed raw AES a key could
/// never produce an interoperable token, so the usage — not a key — is what
/// crosses this boundary. Second, the confounder is random, which makes a
/// Wrap token unpinnable; [`PerMessageCrypto::encrypt`] therefore accepts an
/// optional confounder so the tests can assert exact token octets instead of
/// falling back to round-tripping the implementation against itself.
pub trait PerMessageCrypto {
    /// `h` for the enctype — the truncated-HMAC length. 12 for enctypes
    /// 17/18, 16 for 19, 24 for 20. NOT the key size, and it does not scale
    /// with it: aes256-cts-hmac-sha1-96 still has h = 12.
    fn checksum_len(&self) -> usize;

    /// The confounder size, `c` — 16 octets for all four AES enctypes.
    fn confounder_len(&self) -> usize;

    /// RFC 3961 §5.3 `encrypt`. `confounder` is `None` in production (a fresh
    /// CSPRNG value per message) and `Some` only in tests.
    fn encrypt(
        &self,
        usage: u32,
        plaintext: &[u8],
        confounder: Option<&[u8]>,
    ) -> Result<Vec<u8>, TokenError>;

    /// RFC 3961 §5.3 `decrypt`: verifies integrity, then strips the
    /// confounder. Returns [`TokenError::IntegrityCheckFailed`] rather than
    /// any plaintext when the MAC does not verify.
    fn decrypt(&self, usage: u32, ciphertext: &[u8]) -> Result<Vec<u8>, TokenError>;

    /// RFC 3961 §5.4 `get_mic` = `HMAC(Kc, message)[1..h]`, keyed with **Kc**
    /// (constant 0x99). Not Ki (0x55), which lives only inside `encrypt`, and
    /// not Ke (0xAA).
    fn get_mic(&self, usage: u32, message: &[u8]) -> Result<Vec<u8>, TokenError>;
}

/// Constant-time equality.
///
/// Every comparison in this module is over attacker-supplied bytes against a
/// secret-derived expectation — a MAC, or the header recovered from inside a
/// ciphertext. A short-circuiting `==` on those is a forgery oracle, so the
/// loop must run to the end regardless. The length test above it is not a
/// leak: token lengths are public.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    core::hint::black_box(diff) == 0
}

// ---------------------------------------------------------------------------
// Header construction (RFC 4121 §4.2.6)
// ---------------------------------------------------------------------------

/// Build the 16-octet MIC header — RFC 4121 §4.2.6.1.
///
/// `04 04 | Flags | FF FF FF FF FF | SND_SEQ(8, big-endian)`.
pub fn mic_header(flags: u8, seq: u64) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[0..2].copy_from_slice(&TOK_ID_MIC);
    h[2] = flags;
    h[3..8].copy_from_slice(&MIC_FILLER);
    h[8..16].copy_from_slice(&seq.to_be_bytes());
    h
}

/// Build the 16-octet Wrap header — RFC 4121 §4.2.6.2.
///
/// `05 04 | Flags | FF | EC(2, BE) | RRC(2, BE) | SND_SEQ(8, BE)`.
///
/// EC and RRC are big-endian here. RFC 4121 §4.1.1's authenticator-checksum
/// fields are *little*-endian — the same document uses both orders — so do not
/// carry an endianness helper across that boundary.
pub fn wrap_header(flags: u8, ec: u16, rrc: u16, seq: u64) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[0..2].copy_from_slice(&TOK_ID_WRAP);
    h[2] = flags;
    h[3] = WRAP_FILLER;
    h[4..6].copy_from_slice(&ec.to_be_bytes());
    h[6..8].copy_from_slice(&rrc.to_be_bytes());
    h[8..16].copy_from_slice(&seq.to_be_bytes());
    h
}

/// The header copy that goes *into* the encryption, for a Wrap token **with**
/// confidentiality — RFC 4121 §4.2.4: "the RRC field ... in the
/// to-be-encrypted header contains the hex value 00 00."
///
/// Only RRC is zeroed. EC keeps its real value. Zeroing EC as well is a
/// widespread bug that is invisible whenever EC is 0 (the normal case for
/// AES) and breaks against any peer that sends filler.
pub fn header_for_seal(transmitted: &[u8; HEADER_LEN]) -> [u8; HEADER_LEN] {
    let mut h = *transmitted;
    h[6] = 0;
    h[7] = 0;
    h
}

/// The header copy that goes into the checksum, for a Wrap token **without**
/// confidentiality — RFC 4121 §4.2.4: "Both the EC field and the RRC field in
/// the token header SHALL be filled with zeroes for the purpose of
/// calculating the checksum."
///
/// The opposite rule from [`header_for_seal`], one paragraph away in the same
/// section. Read EC off the wire *before* calling this: EC is what tells you
/// where the checksum starts, and zeroing the working header first loses it.
pub fn header_for_sign(transmitted: &[u8; HEADER_LEN]) -> [u8; HEADER_LEN] {
    let mut h = *transmitted;
    h[4] = 0;
    h[5] = 0;
    h[6] = 0;
    h[7] = 0;
    h
}

// ---------------------------------------------------------------------------
// Rotation (RFC 4121 §4.2.5)
// ---------------------------------------------------------------------------

/// Rotate a Wrap token's body right by `rrc` octets — RFC 4121 §4.2.5.
///
/// "Excluding the first 16 octets of the token header, the resulting Wrap
/// token ... is rotated to the right by RRC octets." The header is never
/// rotated; only the body is.
///
/// The modulo is not defensive tidying. §4.2.5: "The receiver MUST be able to
/// interpret all possible rotation count values, including rotation counts
/// greater than the length of the token." RRC is a `u16`, so 65535 over an
/// 8-octet body is legal on the wire, and an unreduced index would be a
/// remotely triggerable panic. The empty-body guard is the same hazard: a
/// bare 16-octet token divides by zero.
pub fn rotate_right(body: &[u8], rrc: u16) -> Vec<u8> {
    if body.is_empty() {
        return Vec::new();
    }
    let split = body.len() - (rrc as usize) % body.len();
    let mut out = Vec::with_capacity(body.len());
    out.extend_from_slice(&body[split..]);
    out.extend_from_slice(&body[..split]);
    out
}

/// Undo [`rotate_right`] — the receiver's operation.
///
/// It rotates LEFT. Rotating right a second time is a no-op only when
/// `2·rrc ≡ 0 (mod n)`, so it appears to work at RRC = 0 and breaks on the
/// first peer that picks anything else.
pub fn rotate_left(body: &[u8], rrc: u16) -> Vec<u8> {
    if body.is_empty() {
        return Vec::new();
    }
    let split = (rrc as usize) % body.len();
    let mut out = Vec::with_capacity(body.len());
    out.extend_from_slice(&body[split..]);
    out.extend_from_slice(&body[..split]);
    out
}

// ---------------------------------------------------------------------------
// Token construction and verification
// ---------------------------------------------------------------------------

/// What a verified token yielded. The fields are only meaningful *after* the
/// integrity check passed — SND_SEQ and Flags travel in clear text and are
/// authenticated solely by being bound into the MAC or the ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// SND_SEQ, RFC 4121 §4.2.1. Do **not** enforce ordering on this under
    /// RPCSEC_GSS: RFC 2203 §5.2.2 requires replay/sequence detection to be
    /// off at the GSS layer because RPC reorders and servers are
    /// multi-threaded. Replay defence is the RPC layer's `seq_window`.
    pub seq: u64,
    /// The Flags octet as received, unmasked.
    pub flags: u8,
    /// The recovered application data.
    pub message: Vec<u8>,
}

/// The RFC 4121 §4.2 per-message token layer for one established context.
///
/// `role` is *this endpoint's* role — [`Role::Acceptor`] for flint's NFS
/// server. Emits use `role`; verifies use `role.peer()`. Nothing else in this
/// module names a usage number.
pub struct PerMessageTokens<C: PerMessageCrypto> {
    crypto: C,
    role: Role,
    acceptor_subkey: bool,
}

impl<C: PerMessageCrypto> PerMessageTokens<C> {
    /// `acceptor_subkey` records whether the acceptor asserted a subkey in the
    /// AP-REP. RFC 4121 §2: if it did, the base key IS that subkey and
    /// "subsequent per-message tokens MUST be flagged with AcceptorSubkey".
    /// The flag is not advisory — a receiver that ignores it tries the wrong
    /// base key and sees only an opaque MAC failure. Emits therefore set it
    /// from this bool and verifies enforce it in
    /// `Self::check_acceptor_subkey`.
    pub fn new(crypto: C, role: Role, acceptor_subkey: bool) -> Self {
        Self {
            crypto,
            role,
            acceptor_subkey,
        }
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn crypto(&self) -> &C {
        &self.crypto
    }

    fn base_flags(&self) -> u8 {
        let mut f = 0u8;
        if self.role.sent_by_acceptor() {
            f |= FLAG_SENT_BY_ACCEPTOR;
        }
        if self.acceptor_subkey {
            f |= FLAG_ACCEPTOR_SUBKEY;
        }
        f
    }

    /// Parse and direction-check a received header's Flags octet.
    ///
    /// Two separate checks live here and both are required. Deriving the
    /// usage from the received bit is *not* the direction check: a reflected
    /// token is self-consistent under its own usage and would verify. The
    /// rejection is the second half.
    fn check_direction(&self, flags: u8) -> Result<Role, TokenError> {
        let claimed = flags & FLAG_SENT_BY_ACCEPTOR != 0;
        if claimed == self.role.sent_by_acceptor() {
            return Err(TokenError::WrongDirection {
                claimed,
                local: self.role,
            });
        }
        Ok(self.role.peer())
    }

    /// Enforce RFC 4121 §2's AcceptorSubkey rule on a received token.
    ///
    /// §2: "If the acceptor asserts a subkey, the base key is the
    /// acceptor-asserted subkey and subsequent per-message tokens MUST be
    /// flagged with 'AcceptorSubkey'." The flag therefore names *which* base
    /// key the sender used, and a token that claims a subkey this context
    /// never asserted is describing a key that does not exist here.
    ///
    /// The test is deliberately one-sided, matching MIT krb5's
    /// `gss_krb5int_unseal_token_v3` (`if ((ptr[2] & FLAG_ACCEPTOR_SUBKEY) &&
    /// !ctx->have_acceptor_subkey) goto defective;`): a *set* flag with no
    /// subkey is rejected, a *clear* flag on a context that does have one is
    /// tolerated. Strict equality would reject a peer MIT and Windows both
    /// accept, and the RFC's MUST binds the sender, not the receiver.
    ///
    /// This is not what stops a forgery — the MAC does that, and a mismatched
    /// base key fails it anyway. It stops flint reporting an opaque integrity
    /// failure for what is really a key-agreement disagreement.
    fn check_acceptor_subkey(&self, flags: u8) -> Result<(), TokenError> {
        if flags & FLAG_ACCEPTOR_SUBKEY != 0 && !self.acceptor_subkey {
            return Err(TokenError::UnexpectedAcceptorSubkey);
        }
        Ok(())
    }

    // -- MIC (TOK_ID 04 04) ------------------------------------------------

    /// Emit a MIC token over `message` — RFC 4121 §4.2.6.1.
    ///
    /// The checksum input is `message || header`: §4.2.4 says the checksum is
    /// "calculated first over the to-be-signed plaintext data, and then over
    /// the first 16 octets of the MIC token". Data first. All five filler
    /// octets are inside it — §4.2.6.1: "The Filler field is included in the
    /// checksum calculation for simplicity."
    pub fn emit_mic(&self, seq: u64, message: &[u8]) -> Result<Vec<u8>, TokenError> {
        let header = mic_header(self.base_flags(), seq);
        let mut signed = Vec::with_capacity(message.len() + HEADER_LEN);
        signed.extend_from_slice(message);
        signed.extend_from_slice(&header);

        let cksum = self.crypto.get_mic(self.role.sign_usage(), &signed)?;
        let mut token = Vec::with_capacity(HEADER_LEN + cksum.len());
        token.extend_from_slice(&header);
        token.extend_from_slice(&cksum);
        Ok(token)
    }

    /// Verify a MIC token from the peer over `message` — RFC 4121 §4.2.6.1.
    pub fn verify_mic(&self, token: &[u8], message: &[u8]) -> Result<Verified, TokenError> {
        let h = self.crypto.checksum_len();
        let need = HEADER_LEN + h;

        // Exact, not "at least". A receiver that compares only the first h
        // octets of a longer buffer accepts an extended MAC, and one that
        // takes the length from the caller accepts a truncated one.
        if token.len() != need {
            return Err(TokenError::Truncated {
                got: token.len(),
                need,
            });
        }
        if token[0..2] != TOK_ID_MIC {
            return Err(TokenError::BadTokId {
                got: [token[0], token[1]],
                want: TOK_ID_MIC,
            });
        }
        if token[3..8] != MIC_FILLER {
            return Err(TokenError::BadFiller);
        }

        let flags = token[2];
        // §4.2.2: Sealed "SHALL NOT be set in MIC tokens" — a violation to
        // reject, not a variant to tolerate.
        if flags & FLAG_SEALED != 0 {
            return Err(TokenError::SealedMic);
        }
        self.check_acceptor_subkey(flags)?;
        let sender = self.check_direction(flags)?;

        let mut signed = Vec::with_capacity(message.len() + HEADER_LEN);
        signed.extend_from_slice(message);
        signed.extend_from_slice(&token[0..HEADER_LEN]);

        let expected = self.crypto.get_mic(sender.sign_usage(), &signed)?;
        if !ct_eq(&token[HEADER_LEN..], &expected) {
            return Err(TokenError::IntegrityCheckFailed);
        }

        Ok(Verified {
            seq: u64::from_be_bytes(token[8..16].try_into().unwrap()),
            flags,
            message: message.to_vec(),
        })
    }

    // -- Wrap with confidentiality (TOK_ID 05 04, Sealed) ------------------

    /// Emit a sealed Wrap token with EC = 0 and RRC = 0 — the correct and
    /// simplest choice for every AES enctype.
    ///
    /// EC counts filler inserted so that "there SHALL be no crypto-system
    /// residue present after the decryption" (§4.2.4). AES-CTS has message
    /// block size m = 1 octet (RFC 3962 §6), so it never produces residue and
    /// EC = 0 is always legal. RRC exists only so in-place SSPI encryptors
    /// can move the trailer; 0 is always correct.
    pub fn emit_wrap(&self, seq: u64, plaintext: &[u8]) -> Result<Vec<u8>, TokenError> {
        self.emit_wrap_full(seq, plaintext, 0, 0, None)
    }

    /// Emit a sealed Wrap token, choosing EC, RRC and (for tests) the
    /// confounder — RFC 4121 §4.2.4, §4.2.5, §4.2.6.2.
    ///
    /// The construction is `{header | rotate_right(encrypt(plaintext | filler
    /// | header_enc), rrc)}` where `header_enc` differs from the transmitted
    /// header in RRC alone.
    pub fn emit_wrap_full(
        &self,
        seq: u64,
        plaintext: &[u8],
        ec: u16,
        rrc: u16,
        confounder: Option<&[u8]>,
    ) -> Result<Vec<u8>, TokenError> {
        if let Some(c) = confounder {
            if c.len() != self.crypto.confounder_len() {
                return Err(TokenError::BadConfounder {
                    got: c.len(),
                    want: self.crypto.confounder_len(),
                });
            }
        }
        let header = wrap_header(self.base_flags() | FLAG_SEALED, ec, rrc, seq);
        let to_encrypt = seal_input(plaintext, ec, &header);

        let ct = self
            .crypto
            .encrypt(self.role.seal_usage(), &to_encrypt, confounder)?;

        let mut token = Vec::with_capacity(HEADER_LEN + ct.len());
        token.extend_from_slice(&header);
        token.extend_from_slice(&rotate_right(&ct, rrc));
        Ok(token)
    }

    /// Unwrap a sealed Wrap token from the peer — RFC 4121 §4.2.4/§4.2.5.
    pub fn unwrap(&self, token: &[u8]) -> Result<Verified, TokenError> {
        let (flags, ec, rrc, seq, sender) = self.parse_wrap_header(token, true)?;

        let body = rotate_left(&token[HEADER_LEN..], rrc);
        let full = self.crypto.decrypt(sender.seal_usage(), &body)?;

        // Bounds FIRST. `ec` is attacker-controlled up to 65535 and
        // `len - 16 - ec` underflows: a panic in debug, a catastrophic wrap
        // in release.
        let ec = ec as usize;
        if full.len() < HEADER_LEN + ec {
            return Err(TokenError::Truncated {
                got: full.len(),
                need: HEADER_LEN + ec,
            });
        }

        // The trailing header is what proves the attacker did not rewrite the
        // *cleartext* header. The MAC verifying is not enough on its own:
        // Flags, EC and SND_SEQ travel outside the ciphertext, and only this
        // comparison binds them.
        let recovered = &full[full.len() - HEADER_LEN..];
        let expected = header_for_seal(token[0..HEADER_LEN].try_into().unwrap());
        if !ct_eq(recovered, &expected) {
            return Err(TokenError::HeaderMismatch);
        }

        Ok(Verified {
            seq,
            flags,
            message: full[..full.len() - HEADER_LEN - ec].to_vec(),
        })
    }

    // -- Wrap without confidentiality (TOK_ID 05 04, Sealed clear) --------

    /// Emit an unsealed Wrap token — RFC 4121 §4.2.4, §4.2.6.2.
    ///
    /// `{header | rotate_right(plaintext | get_mic(plaintext | header_chk),
    /// rrc)}`, with EC set to `h` and **both** EC and RRC zeroed in
    /// `header_chk`.
    ///
    /// RPCSEC_GSS never sends this: krb5i integrity is GSS_GetMIC plus a
    /// separate checksum field (RFC 2203 §5.3.2.2), and krb5p is Wrap *with*
    /// confidentiality. It is here for GSS conformance, and because its
    /// receive path carries the EC hazard in `verify_wrap_unsealed`.
    pub fn emit_wrap_unsealed(
        &self,
        seq: u64,
        plaintext: &[u8],
        rrc: u16,
    ) -> Result<Vec<u8>, TokenError> {
        let h = self.crypto.checksum_len();
        let header = wrap_header(self.base_flags(), h as u16, rrc, seq);
        let signed = sign_input(plaintext, &header);

        // SEAL, not SIGN — §2: "Even if the Wrap token does not provide for
        // confidentiality, the same usage values specified above are used."
        let cksum = self.crypto.get_mic(self.role.seal_usage(), &signed)?;

        let mut body = Vec::with_capacity(plaintext.len() + cksum.len());
        body.extend_from_slice(plaintext);
        body.extend_from_slice(&cksum);

        let mut token = Vec::with_capacity(HEADER_LEN + body.len());
        token.extend_from_slice(&header);
        token.extend_from_slice(&rotate_right(&body, rrc));
        Ok(token)
    }

    /// Verify an unsealed Wrap token from the peer — RFC 4121 §4.2.4.
    pub fn verify_wrap_unsealed(&self, token: &[u8]) -> Result<Verified, TokenError> {
        let (flags, ec, rrc, seq, sender) = self.parse_wrap_header(token, false)?;

        // EC is read off the wire and says how many trailing octets are the
        // checksum. Honouring an attacker's EC=1 would authenticate against a
        // one-octet MAC — an authentication bypass, not a robustness nit.
        // §4.2.3 fixes it: without confidentiality EC "SHALL be used to
        // encode the number of octets in the trailing checksum", and that
        // number is h for the negotiated enctype.
        let h = self.crypto.checksum_len();
        if ec as usize != h {
            return Err(TokenError::BadExtraCount {
                got: ec as usize,
                want: h,
            });
        }

        let body = rotate_left(&token[HEADER_LEN..], rrc);
        if body.len() < h {
            return Err(TokenError::Truncated {
                got: body.len(),
                need: h,
            });
        }
        let (plaintext, cksum) = body.split_at(body.len() - h);

        let signed = sign_input(plaintext, token[0..HEADER_LEN].try_into().unwrap());
        let expected = self.crypto.get_mic(sender.seal_usage(), &signed)?;
        if !ct_eq(cksum, &expected) {
            return Err(TokenError::IntegrityCheckFailed);
        }

        Ok(Verified {
            seq,
            flags,
            message: plaintext.to_vec(),
        })
    }

    /// Shared Wrap header parse: length, TOK_ID, filler, Sealed, direction.
    ///
    /// Returns `(flags, ec, rrc, seq, sender_role)`.
    fn parse_wrap_header(
        &self,
        token: &[u8],
        want_sealed: bool,
    ) -> Result<(u8, u16, u16, u64, Role), TokenError> {
        if token.len() < HEADER_LEN {
            return Err(TokenError::Truncated {
                got: token.len(),
                need: HEADER_LEN,
            });
        }
        if token[0..2] != TOK_ID_WRAP {
            return Err(TokenError::BadTokId {
                got: [token[0], token[1]],
                want: TOK_ID_WRAP,
            });
        }
        if token[3] != WRAP_FILLER {
            return Err(TokenError::BadFiller);
        }
        let flags = token[2];
        let sealed = flags & FLAG_SEALED != 0;
        if sealed != want_sealed {
            return Err(TokenError::WrongService {
                got: sealed,
                want: if want_sealed { "privacy" } else { "integrity" },
            });
        }
        self.check_acceptor_subkey(flags)?;
        let sender = self.check_direction(flags)?;
        Ok((
            flags,
            u16::from_be_bytes([token[4], token[5]]),
            u16::from_be_bytes([token[6], token[7]]),
            u64::from_be_bytes(token[8..16].try_into().unwrap()),
            sender,
        ))
    }
}

/// The exact buffer RFC 4121 §4.2.4 encrypts for a sealed Wrap token:
/// `plaintext | filler | header` with RRC zeroed in the header copy.
///
/// Exposed so a test can assert it byte-for-byte. That assertion is the point:
/// the data-then-header order and the zero-RRC-but-keep-EC rule are invisible
/// to any round-trip, because a sender and receiver that are both wrong agree.
pub fn seal_input(plaintext: &[u8], ec: u16, transmitted: &[u8; HEADER_LEN]) -> Vec<u8> {
    let ec = ec as usize;
    let mut out = Vec::with_capacity(plaintext.len() + ec + HEADER_LEN);
    out.extend_from_slice(plaintext);
    // §4.2.4: "The values and size of the filler octets are chosen by
    // implementations". Zeros are fine; only the count is on the wire.
    out.resize(plaintext.len() + ec, 0);
    out.extend_from_slice(&header_for_seal(transmitted));
    out
}

/// The exact buffer RFC 4121 §4.2.4 checksums for an unsealed Wrap token:
/// `plaintext | header` with **both** EC and RRC zeroed.
pub fn sign_input(plaintext: &[u8], transmitted: &[u8; HEADER_LEN]) -> Vec<u8> {
    let mut out = Vec::with_capacity(plaintext.len() + HEADER_LEN);
    out.extend_from_slice(plaintext);
    out.extend_from_slice(&header_for_sign(transmitted));
    out
}

/// The exact buffer RFC 4121 §4.2.4 checksums for a MIC token:
/// `message | header`, header verbatim — a MIC token has no EC or RRC to zero.
pub fn mic_input(message: &[u8], header: &[u8; HEADER_LEN]) -> Vec<u8> {
    let mut out = Vec::with_capacity(message.len() + HEADER_LEN);
    out.extend_from_slice(message);
    out.extend_from_slice(header);
    out
}

// ---------------------------------------------------------------------------
// Binding to the RFC 3961/3962/8009 crypto in `super::kdf` + `super::profile`
// ---------------------------------------------------------------------------

/// The three specific keys for one key usage (RFC 3961 §5.3, RFC 8009 §5).
///
/// All three constants are live. The natural-but-wrong pairing is "Ke to
/// encrypt, Ki to MAC everything": `get_mic` is keyed with **Kc** (0x99), and
/// Ki (0x55) appears only as the tag inside `encrypt`.
struct SpecificKeys {
    kc: Vec<u8>,
    ke: Vec<u8>,
    ki: Vec<u8>,
}

/// [`PerMessageCrypto`] over one established context's base key.
///
/// This is the only place the token layer touches the crypto. It holds the
/// **base key**, never a bare cipher key: RFC 3961 §5.3 keys every operation
/// with `DK(base-key, usage | constant)`, and the usage number — not a key —
/// is what crosses the [`PerMessageCrypto`] boundary. A caller that derived
/// one key and handed it to raw AES has already left the wire format; that is
/// precisely the shape of the defect in [`crate::acceptor`].
///
/// The twelve keys (three per RFC 4121 usage) are derived once at
/// construction rather than per message. That is not only cheaper on the NFS
/// data path, it makes the base key length and enctype fail loudly at context
/// setup instead of on the first wrapped READ.
pub struct ContextKey {
    enctype: profile::Enctype,
    /// Indexed by `usage - KG_USAGE_ACCEPTOR_SEAL`, i.e. usages 22..=25.
    keys: [SpecificKeys; 4],
}

impl ContextKey {
    /// `base_key` is, in RFC 4121 §2's priority order: the acceptor subkey
    /// from the AP-REP if the acceptor asserted one, else the initiator
    /// subkey from the AP-REQ authenticator, else the service ticket's
    /// session key.
    pub fn new(etype: i32, base_key: &[u8]) -> Result<Self, TokenError> {
        let pe = profile::Enctype::from_i32(etype).map_err(|e| TokenError::Crypto(e.to_string()))?;
        let ke_type = kdf::Enctype::from_i32(etype).map_err(|e| TokenError::Crypto(e.to_string()))?;

        let derive = |usage: u32, which: kdf::KeyUse| -> Result<Vec<u8>, TokenError> {
            kdf::derive_key(ke_type, base_key, usage, which)
                .map_err(|e| TokenError::Crypto(e.to_string()))
        };
        let mut keys = Vec::with_capacity(4);
        for usage in KG_USAGE_ACCEPTOR_SEAL..=KG_USAGE_INITIATOR_SIGN {
            keys.push(SpecificKeys {
                kc: derive(usage, kdf::KeyUse::Checksum)?,
                ke: derive(usage, kdf::KeyUse::Encryption)?,
                ki: derive(usage, kdf::KeyUse::Integrity)?,
            });
        }
        Ok(Self {
            enctype: pe,
            keys: keys.try_into().map_err(|_| {
                TokenError::Crypto("usage table must hold exactly four entries".into())
            })?,
        })
    }

    pub fn enctype(&self) -> profile::Enctype {
        self.enctype
    }

    /// Only RFC 4121 §2's four usages are derivable here.
    ///
    /// Refusing everything else is the point of the usage numbers: this key
    /// material is scoped to per-message tokens, and an RFC 4120 usage (a
    /// ticket at 2, an AP-REP at 12) reaching this table would mean a caller
    /// had crossed layers.
    fn keys(&self, usage: u32) -> Result<&SpecificKeys, TokenError> {
        self.keys
            .get(usage.wrapping_sub(KG_USAGE_ACCEPTOR_SEAL) as usize)
            .ok_or_else(|| {
                TokenError::Crypto(format!(
                    "key usage {} is not one of the RFC 4121 §2 per-message usages 22..=25",
                    usage
                ))
            })
    }
}

impl PerMessageCrypto for ContextKey {
    fn checksum_len(&self) -> usize {
        self.enctype.checksum_len()
    }

    fn confounder_len(&self) -> usize {
        self.enctype.confounder_len()
    }

    fn encrypt(
        &self,
        usage: u32,
        plaintext: &[u8],
        confounder: Option<&[u8]>,
    ) -> Result<Vec<u8>, TokenError> {
        let k = self.keys(usage)?;
        match confounder {
            Some(c) => {
                profile::encrypt_with_confounder(self.enctype, &k.ke, &k.ki, c, plaintext)
            }
            None => profile::encrypt(self.enctype, &k.ke, &k.ki, plaintext),
        }
        .map_err(|e| TokenError::Crypto(e.to_string()))
    }

    fn decrypt(&self, usage: u32, ciphertext: &[u8]) -> Result<Vec<u8>, TokenError> {
        let k = self.keys(usage)?;
        // Every decrypt failure collapses to one error. The difference between
        // "MAC mismatch" and "too short" is exactly the oracle an attacker
        // wants, so the token layer does not forward the distinction.
        profile::decrypt(self.enctype, &k.ke, &k.ki, ciphertext)
            .map_err(|_| TokenError::IntegrityCheckFailed)
    }

    fn get_mic(&self, usage: u32, message: &[u8]) -> Result<Vec<u8>, TokenError> {
        let k = self.keys(usage)?;
        profile::checksum(self.enctype, &k.kc, message)
            .map_err(|e| TokenError::Crypto(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hexs(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    // -----------------------------------------------------------------
    // A deterministic, usage-sensitive test double for the crypto seam.
    //
    // Its job is to isolate the RFC 4121 *framing* — header layout, flag
    // handling, EC/RRC rules, rotation, direction checks — from the RFC
    // 3961/8009 crypto, which is pinned to published vectors in
    // `super::profile` and, end to end, by the `derived_*` tests below.
    //
    // Two properties matter. It records the exact buffer it was handed, so
    // the data-then-header order can be asserted rather than round-tripped;
    // and its output DEPENDS ON THE USAGE NUMBER, so a 22/24 or 23/25 swap
    // fails here instead of passing the way it would against a real peer's
    // absence.
    // -----------------------------------------------------------------

    fn stub_mac(usage: u32, msg: &[u8], h: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(h + 8);
        let mut ctr = 0u8;
        while out.len() < h {
            let mut acc: u64 = 0xcbf2_9ce4_8422_2325;
            for b in usage
                .to_be_bytes()
                .iter()
                .chain(std::iter::once(&ctr))
                .chain(msg.iter())
            {
                acc ^= *b as u64;
                acc = acc.wrapping_mul(0x0000_0100_0000_01b3);
            }
            out.extend_from_slice(&acc.to_be_bytes());
            ctr += 1;
        }
        out.truncate(h);
        out
    }

    #[derive(Default)]
    struct Log {
        last_mic_input: Vec<u8>,
        last_mic_usage: u32,
        last_enc_input: Vec<u8>,
        last_enc_usage: u32,
    }

    struct Stub {
        h: usize,
        log: std::cell::RefCell<Log>,
    }

    impl Stub {
        fn new(h: usize) -> Self {
            Self {
                h,
                log: std::cell::RefCell::new(Log::default()),
            }
        }
    }

    impl PerMessageCrypto for Stub {
        fn checksum_len(&self) -> usize {
            self.h
        }
        fn confounder_len(&self) -> usize {
            16
        }
        fn encrypt(
            &self,
            usage: u32,
            plaintext: &[u8],
            confounder: Option<&[u8]>,
        ) -> Result<Vec<u8>, TokenError> {
            let mut lg = self.log.borrow_mut();
            lg.last_enc_input = plaintext.to_vec();
            lg.last_enc_usage = usage;
            drop(lg);
            let conf = confounder.map(|c| c.to_vec()).unwrap_or_else(|| vec![0x5a; 16]);
            let mut p = conf;
            p.extend_from_slice(plaintext);
            let tag = stub_mac(usage, &p, self.h);
            p.extend_from_slice(&tag);
            Ok(p)
        }
        fn decrypt(&self, usage: u32, ciphertext: &[u8]) -> Result<Vec<u8>, TokenError> {
            if ciphertext.len() < 16 + self.h {
                return Err(TokenError::IntegrityCheckFailed);
            }
            let (body, tag) = ciphertext.split_at(ciphertext.len() - self.h);
            if !ct_eq(tag, &stub_mac(usage, body, self.h)) {
                return Err(TokenError::IntegrityCheckFailed);
            }
            Ok(body[16..].to_vec())
        }
        fn get_mic(&self, usage: u32, message: &[u8]) -> Result<Vec<u8>, TokenError> {
            let mut lg = self.log.borrow_mut();
            lg.last_mic_input = message.to_vec();
            lg.last_mic_usage = usage;
            drop(lg);
            Ok(stub_mac(usage, message, self.h))
        }
    }

    fn acceptor(h: usize) -> PerMessageTokens<Stub> {
        PerMessageTokens::new(Stub::new(h), Role::Acceptor, true)
    }
    fn initiator(h: usize) -> PerMessageTokens<Stub> {
        PerMessageTokens::new(Stub::new(h), Role::Initiator, true)
    }

    // =================================================================
    // RFC-pinned constants and semantics.
    //
    // RFC 4121 publishes no crypto test vectors; these are the literal
    // octets and the one worked example the RFC does give.
    // =================================================================

    /// RFC 4121 §4.2.6.1: "Tokens emitted by GSS_GetMIC() contain the hex
    /// value 04 04 expressed in big-endian order in this field."
    #[test]
    fn rfc4121_4_2_6_1_mic_tok_id_is_0404() {
        assert_eq!(TOK_ID_MIC, [0x04, 0x04]);
    }

    /// RFC 4121 §4.2.6.2: "Tokens emitted by GSS_Wrap() contain the hex
    /// value 05 04 expressed in big-endian order in this field."
    #[test]
    fn rfc4121_4_2_6_2_wrap_tok_id_is_0504() {
        assert_eq!(TOK_ID_WRAP, [0x05, 0x04]);
    }

    /// RFC 4121 §4.2.6.1 octets 3..7: "Contains five octets of hex value FF."
    /// The Wrap token's is ONE octet (§4.2.6.2) — the asymmetry that shifts
    /// SND_SEQ by four if the two headers share a builder.
    #[test]
    fn rfc4121_4_2_6_fillers_are_five_ff_for_mic_and_one_ff_for_wrap() {
        assert_eq!(MIC_FILLER, [0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(WRAP_FILLER, 0xFF);
        assert_eq!(mic_header(0, 0)[3..8], [0xFF; 5]);
        assert_eq!(wrap_header(0, 0, 0, 0)[3], 0xFF);
        // ...and the Wrap token's octet 4 is EC, not more filler.
        assert_eq!(wrap_header(0, 0x1234, 0, 0)[4..6], [0x12, 0x34]);
    }

    /// RFC 4121 §4.2.2, "the least significant bit is bit 0":
    /// bit 0 SentByAcceptor, bit 1 Sealed, bit 2 AcceptorSubkey.
    #[test]
    fn rfc4121_4_2_2_flag_bit_values() {
        assert_eq!(FLAG_SENT_BY_ACCEPTOR, 1 << 0);
        assert_eq!(FLAG_SEALED, 1 << 1);
        assert_eq!(FLAG_ACCEPTOR_SUBKEY, 1 << 2);
        assert_eq!(FLAGS_DEFINED, 0x07);
    }

    /// RFC 4121 §2, verbatim table:
    ///   KG-USAGE-ACCEPTOR-SEAL 22, ACCEPTOR-SIGN 23,
    ///   INITIATOR-SEAL 24, INITIATOR-SIGN 25.
    /// And the assignment rule: SIGN for MIC tokens, SEAL for Wrap tokens,
    /// selected by the SENDER's role.
    #[test]
    fn rfc4121_2_key_usage_numbers_and_role_assignment() {
        assert_eq!(KG_USAGE_ACCEPTOR_SEAL, 22);
        assert_eq!(KG_USAGE_ACCEPTOR_SIGN, 23);
        assert_eq!(KG_USAGE_INITIATOR_SEAL, 24);
        assert_eq!(KG_USAGE_INITIATOR_SIGN, 25);

        assert_eq!(Role::Acceptor.seal_usage(), 22);
        assert_eq!(Role::Acceptor.sign_usage(), 23);
        assert_eq!(Role::Initiator.seal_usage(), 24);
        assert_eq!(Role::Initiator.sign_usage(), 25);
    }

    /// A server EMITS with acceptor usages and VERIFIES with initiator ones.
    /// Swapping them is the classic bug and it round-trips against itself,
    /// so this asserts the usage the crypto was actually asked for.
    #[test]
    fn rfc4121_2_server_emits_with_22_23_and_verifies_with_24_25() {
        let srv = acceptor(16);

        srv.emit_mic(0, b"x").unwrap();
        assert_eq!(srv.crypto().log.borrow().last_mic_usage, 23);

        srv.emit_wrap(0, b"x").unwrap();
        assert_eq!(srv.crypto().log.borrow().last_enc_usage, 22);

        // Now verify a token the client built, and check the usage flipped.
        let cli = initiator(16);
        let mic = cli.emit_mic(0, b"x").unwrap();
        assert_eq!(cli.crypto().log.borrow().last_mic_usage, 25);
        srv.verify_mic(&mic, b"x").unwrap();
        assert_eq!(srv.crypto().log.borrow().last_mic_usage, 25);

        let wrap = cli.emit_wrap(0, b"x").unwrap();
        assert_eq!(cli.crypto().log.borrow().last_enc_usage, 24);
        srv.unwrap(&wrap).unwrap();
    }

    /// RFC 4121 §2: "Even if the Wrap token does not provide for
    /// confidentiality, the same usage values specified above are used."
    /// So an unsealed Wrap token uses SEAL (22/24), not SIGN (23/25) — which
    /// reads backwards to everyone.
    #[test]
    fn rfc4121_2_unsealed_wrap_uses_seal_usage_not_sign() {
        let srv = acceptor(16);
        srv.emit_wrap_unsealed(0, b"x", 0).unwrap();
        assert_eq!(srv.crypto().log.borrow().last_mic_usage, 22);

        let cli = initiator(16);
        cli.emit_wrap_unsealed(0, b"x", 0).unwrap();
        assert_eq!(cli.crypto().log.borrow().last_mic_usage, 24);
    }

    /// RFC 4121 §4.2.5, the RFC's only worked example: "Assume that the RRC
    /// value is 3 and the token before the rotation is {"header" | aa | bb |
    /// cc | dd | ee | ff | gg | hh}. The token after rotation would be
    /// {"header" | ff | gg | hh | aa | bb | cc | dd | ee}."
    ///
    /// `aa`..`hh` are POSITIONAL LABELS, not hex — `gg` and `hh` are not
    /// valid hex digits. The byte values below are chosen; the permutation
    /// is the RFC's, asserted as a permutation of positions.
    #[test]
    fn rfc4121_4_2_5_rotation_example_rrc_3() {
        let body: Vec<u8> = (0u8..8).collect(); // positions aa..hh
        let rotated = rotate_right(&body, 3);
        // ff gg hh aa bb cc dd ee  ==  positions 5,6,7,0,1,2,3,4
        assert_eq!(rotated, vec![5, 6, 7, 0, 1, 2, 3, 4]);
        assert_eq!(rotate_left(&rotated, 3), body);
    }

    /// RFC 4121 §4.2.5: "The receiver MUST be able to interpret all possible
    /// rotation count values, including rotation counts greater than the
    /// length of the token." RRC is a u16, so an unreduced index over a short
    /// body is a remotely triggerable panic.
    #[test]
    fn rfc4121_4_2_5_rrc_larger_than_the_body_is_reduced_not_a_panic() {
        let body: Vec<u8> = (0u8..8).collect();
        assert_eq!(rotate_right(&body, 11), rotate_right(&body, 3));
        assert_eq!(rotate_right(&body, 8), body);
        assert_eq!(rotate_right(&body, u16::MAX), rotate_right(&body, 7));
        assert_eq!(rotate_left(&body, u16::MAX), rotate_left(&body, 7));
        // A bare 16-octet token has an empty body: modulo by zero.
        assert!(rotate_right(&[], 3).is_empty());
        assert!(rotate_left(&[], u16::MAX).is_empty());
    }

    /// The receiver rotates LEFT to undo. Rotating right twice is a no-op
    /// only when 2·rrc ≡ 0 (mod n), so it "works" at RRC = 0 and breaks on
    /// the first peer that picks anything else.
    #[test]
    fn rfc4121_4_2_5_rotate_left_inverts_rotate_right_for_every_count() {
        let body: Vec<u8> = (0u8..13).collect();
        for r in 0u16..40 {
            assert_eq!(rotate_left(&rotate_right(&body, r), r), body, "rrc={}", r);
        }
        // The trap: rotating right a second time is NOT the inverse.
        assert_ne!(rotate_right(&rotate_right(&body, 3), 3), body);
    }

    /// RFC 4121 §4.2.4, confidentiality case: "the RRC field ... in the
    /// to-be-encrypted header contains the hex value 00 00." ONLY RRC. EC
    /// keeps its real value — zeroing it too is invisible while EC is 0 and
    /// breaks against any peer that sends filler.
    #[test]
    fn rfc4121_4_2_4_sealed_header_copy_zeroes_rrc_and_keeps_ec() {
        let h = wrap_header(0x06, 0x0005, 0x000d, 7);
        let enc = header_for_seal(&h);
        assert_eq!(&enc[4..6], &[0x00, 0x05], "EC must survive");
        assert_eq!(&enc[6..8], &[0x00, 0x00], "RRC must be zeroed");
        // Everything else is byte-identical to the transmitted header.
        assert_eq!(&enc[0..4], &h[0..4]);
        assert_eq!(&enc[8..16], &h[8..16]);
    }

    /// RFC 4121 §4.2.4, no-confidentiality case: "Both the EC field and the
    /// RRC field in the token header SHALL be filled with zeroes for the
    /// purpose of calculating the checksum." The OPPOSITE rule, one
    /// paragraph away in the same section.
    #[test]
    fn rfc4121_4_2_4_unsealed_header_copy_zeroes_both_ec_and_rrc() {
        let h = wrap_header(0x04, 0x0010, 0x0004, 9);
        let chk = header_for_sign(&h);
        assert_eq!(&chk[4..8], &[0, 0, 0, 0]);
        assert_eq!(&chk[0..4], &h[0..4]);
        assert_eq!(&chk[8..16], &h[8..16]);
        // And the two rules genuinely differ whenever EC != 0.
        assert_ne!(header_for_seal(&h), header_for_sign(&h));
    }

    /// RFC 4121 §4.2.4: the checksum "is calculated first over the
    /// to-be-signed plaintext data, and then over the first 16 octets of the
    /// MIC token" — DATA THEN HEADER. Inverted from nearly every other
    /// protocol, with no length field to catch it, so it is asserted on the
    /// buffer rather than inferred from a round-trip.
    #[test]
    fn rfc4121_4_2_4_mic_checksum_input_is_data_then_header() {
        let srv = acceptor(16);
        let token = srv.emit_mic(0x0102030405060708, b"\x00\x01\x02\x03\x04\x05\x06\x07").unwrap();

        let header = hex("040405ffffffffff0102030405060708");
        assert_eq!(&token[0..16], &header[..]);
        assert_eq!(
            hexs(&srv.crypto().log.borrow().last_mic_input),
            "0001020304050607040405ffffffffff0102030405060708"
        );
        // Header-then-data is the inversion this test exists to exclude. It
        // has the same length and the same octets, so nothing downstream
        // would notice -- only this assertion does.
        let mut inverted = header.clone();
        inverted.extend_from_slice(b"\x00\x01\x02\x03\x04\x05\x06\x07");
        assert_eq!(inverted.len(), srv.crypto().log.borrow().last_mic_input.len());
        assert_ne!(srv.crypto().log.borrow().last_mic_input, inverted);
    }

    /// RFC 4121 §4.2.4: "{"header" | encrypt(plaintext-data | filler |
    /// "header")}" — data, then filler, then the header with RRC zeroed.
    #[test]
    fn rfc4121_4_2_4_sealed_encrypt_input_is_data_filler_header() {
        let srv = acceptor(16);
        // EC = 5 filler octets, RRC = 13, so both rules are exercised at once.
        srv.emit_wrap_full(7, b"\x00\x01\x02\x03\x04\x05\x06\x07", 5, 13, Some(&[0u8; 16]))
            .unwrap();
        assert_eq!(
            hexs(&srv.crypto().log.borrow().last_enc_input),
            concat!(
                "0001020304050607", // plaintext
                "0000000000",       // 5 filler octets (EC)
                "050407ff",         // TOK_ID | Flags | FF
                "0005",             // EC, keeps its value
                "0000",             // RRC, zeroed
                "0000000000000007"  // SND_SEQ
            )
        );
    }

    /// RFC 4121 §4.2.6.1 layout, octet by octet.
    #[test]
    fn rfc4121_4_2_6_1_mic_header_layout() {
        // Initiator, not sealed, acceptor subkey asserted -> Flags 0x04.
        assert_eq!(hexs(&mic_header(0x04, 0)), "040404ffffffffff0000000000000000");
        // Acceptor -> SentByAcceptor set -> Flags 0x05.
        assert_eq!(hexs(&mic_header(0x05, 1)), "040405ffffffffff0000000000000001");
    }

    /// RFC 4121 §4.2.6.2 layout, octet by octet. EC and RRC are big-endian
    /// u16 here; §4.1.1's authenticator-checksum fields are little-endian.
    #[test]
    fn rfc4121_4_2_6_2_wrap_header_layout() {
        assert_eq!(
            hexs(&wrap_header(0x06, 0, 0, 2)),
            "050406ff000000000000000000000002"
        );
        assert_eq!(
            hexs(&wrap_header(0x07, 0x1234, 0xabcd, 0xdead_beef_0000_0001)),
            "050407ff1234abcddeadbeef00000001"
        );
    }

    // =================================================================
    // Refusals. Every one names the octet it rejects.
    // =================================================================

    #[test]
    fn decode_rejects_truncated_mic_token() {
        let srv = acceptor(16);
        let cli = initiator(16);
        let token = cli.emit_mic(0, b"msg").unwrap();
        assert_eq!(token.len(), 16 + 16);

        for n in 0..token.len() {
            assert!(
                matches!(
                    srv.verify_mic(&token[..n], b"msg"),
                    Err(TokenError::Truncated { .. })
                ),
                "a {}-octet MIC token was not rejected as truncated",
                n
            );
        }
        // The length test is EXACT, not "at least": an extended MAC must go
        // too, or a receiver comparing only the first h octets accepts it.
        let mut long = token.clone();
        long.push(0);
        assert!(matches!(
            srv.verify_mic(&long, b"msg"),
            Err(TokenError::Truncated { .. })
        ));
    }

    #[test]
    fn decode_rejects_truncated_wrap_token() {
        let srv = acceptor(16);
        let cli = initiator(16);
        let sealed = cli.emit_wrap(3, b"msg").unwrap();
        for n in 0..HEADER_LEN {
            assert!(matches!(
                srv.unwrap(&sealed[..n]),
                Err(TokenError::Truncated { .. })
            ));
        }
        // A header with no body at all: the rotation must not divide by
        // zero and the crypto must refuse an empty ciphertext.
        assert!(srv.unwrap(&sealed[..HEADER_LEN]).is_err());

        let unsealed = cli.emit_wrap_unsealed(3, b"msg", 0).unwrap();
        for n in 0..HEADER_LEN {
            assert!(matches!(
                srv.verify_wrap_unsealed(&unsealed[..n]),
                Err(TokenError::Truncated { .. })
            ));
        }
    }

    #[test]
    fn decode_rejects_bad_tok_id() {
        let srv = acceptor(16);
        let cli = initiator(16);

        let mut mic = cli.emit_mic(0, b"msg").unwrap();
        mic[0] = 0x05; // the Wrap TOK_ID on a MIC token
        assert_eq!(
            srv.verify_mic(&mic, b"msg"),
            Err(TokenError::BadTokId {
                got: [0x05, 0x04],
                want: TOK_ID_MIC
            })
        );

        let mut wrap = cli.emit_wrap(0, b"msg").unwrap();
        wrap[0] = 0x04;
        assert_eq!(
            srv.unwrap(&wrap),
            Err(TokenError::BadTokId {
                got: [0x04, 0x04],
                want: TOK_ID_WRAP
            })
        );

        // RFC 4121 §4.4 reserves 0x60 0x00..0x60 0xFF so a receiver can tell
        // a bare token from generic GSS-API ASN.1 framing.
        let mut asn1 = cli.emit_wrap(0, b"msg").unwrap();
        asn1[0] = 0x60;
        asn1[1] = 0x2a;
        assert!(matches!(srv.unwrap(&asn1), Err(TokenError::BadTokId { .. })));
    }

    /// RFC 4121 §4.2.2: SentByAcceptor is the direction indicator, "thus
    /// preventing the acceptance of the same message sent back in the
    /// reverse direction by an adversary."
    ///
    /// Deriving the usage from the received bit is NOT this check — a
    /// reflected token is self-consistent under its own usage and verifies
    /// cleanly. The rejection is a separate step, and this is it.
    #[test]
    fn decode_rejects_wrong_flags_direction() {
        let srv = acceptor(16);

        // The server's own tokens, reflected back at it.
        let own_mic = srv.emit_mic(0, b"msg").unwrap();
        assert_eq!(own_mic[2] & FLAG_SENT_BY_ACCEPTOR, FLAG_SENT_BY_ACCEPTOR);
        assert_eq!(
            srv.verify_mic(&own_mic, b"msg"),
            Err(TokenError::WrongDirection {
                claimed: true,
                local: Role::Acceptor
            })
        );

        let own_wrap = srv.emit_wrap(0, b"msg").unwrap();
        assert_eq!(
            srv.unwrap(&own_wrap),
            Err(TokenError::WrongDirection {
                claimed: true,
                local: Role::Acceptor
            })
        );

        let own_unsealed = srv.emit_wrap_unsealed(0, b"msg", 0).unwrap();
        assert_eq!(
            srv.verify_wrap_unsealed(&own_unsealed),
            Err(TokenError::WrongDirection {
                claimed: true,
                local: Role::Acceptor
            })
        );

        // ...and symmetrically, an initiator must reject a token with the
        // bit CLEAR.
        let cli = initiator(16);
        let cli_mic = cli.emit_mic(0, b"msg").unwrap();
        assert_eq!(
            cli.verify_mic(&cli_mic, b"msg"),
            Err(TokenError::WrongDirection {
                claimed: false,
                local: Role::Initiator
            })
        );

        // Sanity: the direction check is what rejected these, not the MAC.
        srv.verify_mic(&cli_mic, b"msg").unwrap();
    }

    #[test]
    fn decode_rejects_failed_integrity_check() {
        let srv = acceptor(16);
        let cli = initiator(16);

        // MIC: flip one bit of the checksum.
        let mut mic = cli.emit_mic(0, b"msg").unwrap();
        let last = mic.len() - 1;
        mic[last] ^= 0x01;
        assert_eq!(
            srv.verify_mic(&mic, b"msg"),
            Err(TokenError::IntegrityCheckFailed)
        );

        // MIC: the right token over the wrong message.
        let mic = cli.emit_mic(0, b"msg").unwrap();
        assert_eq!(
            srv.verify_mic(&mic, b"msh"),
            Err(TokenError::IntegrityCheckFailed)
        );

        // Sealed Wrap: flip one bit of the ciphertext.
        let mut wrap = cli.emit_wrap(0, b"msg").unwrap();
        let last = wrap.len() - 1;
        wrap[last] ^= 0x80;
        assert_eq!(srv.unwrap(&wrap), Err(TokenError::IntegrityCheckFailed));

        // Unsealed Wrap: flip one bit of the trailing checksum.
        let mut un = cli.emit_wrap_unsealed(0, b"msg", 0).unwrap();
        let last = un.len() - 1;
        un[last] ^= 0x01;
        assert_eq!(
            srv.verify_wrap_unsealed(&un),
            Err(TokenError::IntegrityCheckFailed)
        );
    }

    /// RFC 4121 §4.2.2: Sealed "SHALL NOT be set in MIC tokens" — a protocol
    /// violation to reject, not a variant to tolerate.
    #[test]
    fn decode_rejects_sealed_flag_on_a_mic_token() {
        let srv = acceptor(16);
        let cli = initiator(16);
        let mut mic = cli.emit_mic(0, b"msg").unwrap();
        mic[2] |= FLAG_SEALED;
        assert_eq!(srv.verify_mic(&mic, b"msg"), Err(TokenError::SealedMic));
    }

    /// RFC 4121 §2: "If the acceptor asserts a subkey, the base key is the
    /// acceptor-asserted subkey and subsequent per-message tokens MUST be
    /// flagged with 'AcceptorSubkey'."
    ///
    /// A context that asserted no subkey must therefore refuse a token that
    /// claims one: the flag names a base key that does not exist here. The
    /// MAC would fail anyway once the keys really differ, which is exactly
    /// why nothing here caught it before — a self-round-trip constructs both
    /// ends with the same bool, so the flag always agrees with itself.
    ///
    /// One-sided, as in MIT krb5's `gss_krb5int_unseal_token_v3`: set-with-no-
    /// subkey is defective, clear-with-a-subkey is tolerated.
    #[test]
    fn decode_rejects_acceptor_subkey_flag_when_no_subkey_was_asserted() {
        // Server asserted NO subkey; a client that claims one is rejected.
        let srv = PerMessageTokens::new(Stub::new(16), Role::Acceptor, false);
        let cli = initiator(16); // acceptor_subkey = true, so it sets the flag

        let mic = cli.emit_mic(0, b"msg").unwrap();
        assert_eq!(mic[2] & FLAG_ACCEPTOR_SUBKEY, FLAG_ACCEPTOR_SUBKEY);
        assert_eq!(
            srv.verify_mic(&mic, b"msg"),
            Err(TokenError::UnexpectedAcceptorSubkey)
        );
        assert_eq!(
            srv.unwrap(&cli.emit_wrap(0, b"msg").unwrap()),
            Err(TokenError::UnexpectedAcceptorSubkey)
        );
        assert_eq!(
            srv.verify_wrap_unsealed(&cli.emit_wrap_unsealed(0, b"msg", 0).unwrap()),
            Err(TokenError::UnexpectedAcceptorSubkey)
        );

        // Anti-vacuity: it is the FLAG being rejected, not the token. The same
        // client without the flag verifies against the same server.
        let plain = PerMessageTokens::new(Stub::new(16), Role::Initiator, false);
        let mic = plain.emit_mic(0, b"msg").unwrap();
        assert_eq!(mic[2] & FLAG_ACCEPTOR_SUBKEY, 0);
        srv.verify_mic(&mic, b"msg").unwrap();
        srv.unwrap(&plain.emit_wrap(0, b"msg").unwrap()).unwrap();

        // And the tolerated direction: a server that DID assert a subkey still
        // accepts a peer that failed to set the flag. Rejecting here would
        // turn away a peer MIT krb5 accepts.
        let srv_sub = acceptor(16);
        srv_sub.verify_mic(&mic, b"msg").unwrap();
        srv_sub.unwrap(&plain.emit_wrap(0, b"msg").unwrap()).unwrap();
    }

    #[test]
    fn decode_rejects_bad_filler() {
        let srv = acceptor(16);
        let cli = initiator(16);

        let mut mic = cli.emit_mic(0, b"msg").unwrap();
        mic[7] = 0x00; // the fifth filler octet
        assert_eq!(srv.verify_mic(&mic, b"msg"), Err(TokenError::BadFiller));

        let mut wrap = cli.emit_wrap(0, b"msg").unwrap();
        wrap[3] = 0x00;
        assert_eq!(srv.unwrap(&wrap), Err(TokenError::BadFiller));
    }

    /// The service the caller asked for must match the Sealed bit: a
    /// privacy unwrap must not accept an unsealed token, and vice versa.
    #[test]
    fn decode_rejects_the_wrong_wrap_service() {
        let srv = acceptor(16);
        let cli = initiator(16);
        let sealed = cli.emit_wrap(0, b"msg").unwrap();
        let unsealed = cli.emit_wrap_unsealed(0, b"msg", 0).unwrap();

        assert!(matches!(
            srv.verify_wrap_unsealed(&sealed),
            Err(TokenError::WrongService { got: true, .. })
        ));
        assert!(matches!(
            srv.unwrap(&unsealed),
            Err(TokenError::WrongService { got: false, .. })
        ));
    }

    /// AUTHENTICATION BYPASS, not a robustness nit.
    ///
    /// In an unsealed Wrap token EC comes off the wire and says how many
    /// trailing octets are the checksum (RFC 4121 §4.2.3). A receiver that
    /// honours the sender's EC accepts a one-octet MAC — trivially forgeable.
    /// EC MUST equal h for the negotiated enctype.
    #[test]
    fn decode_rejects_extra_count_that_does_not_equal_the_checksum_length() {
        let srv = acceptor(16);
        let cli = initiator(16);
        let good = cli.emit_wrap_unsealed(9, b"msg", 0).unwrap();
        assert_eq!(&good[4..6], &[0x00, 0x10], "EC is emitted as h = 16");
        srv.verify_wrap_unsealed(&good).unwrap();

        // The forgery: claim a 1-octet checksum.
        let mut forged = good.clone();
        forged[4] = 0x00;
        forged[5] = 0x01;
        assert_eq!(
            srv.verify_wrap_unsealed(&forged),
            Err(TokenError::BadExtraCount { got: 1, want: 16 })
        );

        // And an EC beyond the token must not underflow the split either.
        let mut huge = good;
        huge[4] = 0xff;
        huge[5] = 0xff;
        assert_eq!(
            srv.verify_wrap_unsealed(&huge),
            Err(TokenError::BadExtraCount {
                got: 65535,
                want: 16
            })
        );
    }

    /// The trailing header recovered from inside the ciphertext is what binds
    /// the CLEARTEXT header — Flags, EC, SND_SEQ all travel outside the
    /// encryption. A MAC that verifies is not enough on its own.
    #[test]
    fn decode_rejects_a_rewritten_cleartext_header_on_a_sealed_wrap() {
        let srv = acceptor(16);
        let cli = initiator(16);
        let token = cli.emit_wrap(0x1122334455667788, b"msg").unwrap();
        srv.unwrap(&token).unwrap();

        // Rewrite SND_SEQ. The ciphertext is untouched, so the crypto's own
        // integrity check still passes; only the header comparison catches it.
        let mut replayed = token.clone();
        replayed[15] ^= 0xff;
        assert_eq!(srv.unwrap(&replayed), Err(TokenError::HeaderMismatch));

        // Rewrite EC. Same story.
        let mut ec = token.clone();
        ec[5] = 0x04;
        assert!(srv.unwrap(&ec).is_err());
    }

    /// RRC is NOT part of the header comparison — it is zeroed on both sides
    /// (§4.2.4) — so re-rotating a token to a different RRC must still
    /// verify. This is what a conforming SSPI peer does.
    #[test]
    fn rfc4121_4_2_5_a_rerotated_token_still_verifies() {
        let srv = acceptor(16);
        let cli = initiator(16);
        for rrc in [0u16, 1, 7, 13, 64, 4096, u16::MAX] {
            let token = cli.emit_wrap_full(5, b"payload", 0, rrc, None).unwrap();
            assert_eq!(&token[6..8], &rrc.to_be_bytes());
            let v = srv.unwrap(&token).unwrap();
            assert_eq!(v.message, b"payload");
            assert_eq!(v.seq, 5);

            let un = cli.emit_wrap_unsealed(5, b"payload", rrc).unwrap();
            assert_eq!(srv.verify_wrap_unsealed(&un).unwrap().message, b"payload");
        }
    }

    /// `ec` is attacker-controlled up to 65535 and `len - 16 - ec` underflows:
    /// a panic in debug, a catastrophic wrap in release. The bounds check has
    /// to come before the slice.
    #[test]
    fn unwrap_rejects_an_oversized_extra_count_without_underflowing() {
        let srv = acceptor(16);
        let cli = initiator(16);
        // Build with a real EC so the bound is what rejects it, not the MAC.
        let token = cli.emit_wrap_full(1, b"p", 40, 0, None).unwrap();
        // The plaintext is 1 + 40 filler + 16 header = 57 octets, so EC=40 is
        // legal. Now claim EC = 65535 in the cleartext header only.
        let mut huge = token;
        huge[4] = 0xff;
        huge[5] = 0xff;
        assert!(matches!(
            srv.unwrap(&huge),
            Err(TokenError::Truncated { .. }) | Err(TokenError::HeaderMismatch)
        ));
    }

    /// §4.2.2: "The receiver MUST ignore unknown flags." Masking, not an
    /// equality test on the whole octet — otherwise a conforming future peer
    /// is rejected. But the three DEFINED bits are still enforced.
    #[test]
    fn rfc4121_4_2_2_reserved_flag_bits_are_ignored_not_rejected() {
        let srv = acceptor(16);
        let cli = initiator(16);

        // A reserved bit inside the header is covered by the MAC, so it has
        // to be set before the token is built to stay verifiable. Do that by
        // re-deriving the checksum over the mutated header.
        let mut header = mic_header(FLAG_ACCEPTOR_SUBKEY | 0x80, 0);
        header[2] |= 0x40;
        let mic = cli
            .crypto()
            .get_mic(KG_USAGE_INITIATOR_SIGN, &mic_input(b"msg", &header))
            .unwrap();
        let mut token = header.to_vec();
        token.extend_from_slice(&mic);

        let v = srv.verify_mic(&token, b"msg").unwrap();
        assert_eq!(v.flags & 0xc0, 0xc0, "reserved bits survive to the caller");
    }

    // =================================================================
    // End-to-end tokens through the REAL crypto (super::kdf + super::profile).
    //
    // RFC 4121 publishes no token vectors and cannot: EC, RRC, the filler
    // octets and the confounder are all sender's choice, so two conforming
    // implementations given the same key, seq and plaintext emit different
    // tokens. These goldens are therefore named `derived_`, never `rfcNNNN_`.
    //
    // They are not self-round-trips either. Every expected octet below was
    // produced by a SEPARATE implementation written from the RFC text in
    // Python, which was first pinned to all 63 published RFC 3961 §A.1,
    // RFC 3962 §B and RFC 8009 §A vectors (n-fold, CBC-CTS both directions,
    // the 14 AES DK values, the 6 KDF-HMAC-SHA2 keys, the 8 full encryptions
    // and both checksums). Agreement between two independent implementations
    // on the framing, with the crypto underneath pinned to published answers
    // on both sides, is the strongest evidence available for this layer short
    // of a packet capture — which is the one thing that would settle it and
    // which is recorded as an open gate rather than faked here.
    //
    // The confounder is fixed at 000102..0f so the ciphertext is
    // reproducible; production draws it from the OS CSPRNG.
    // =================================================================

    /// RFC 3962 §B's aes128 key for "password"/"ATHENA.MIT.EDUraeburn"
    /// iter 1 — the companion of [`BASE_18`] in the same table.
    const BASE_17: &str = "42263c6e89f4fc28b8df68ee09799f15";
    /// RFC 3962 §B's aes256 key for "password"/"ATHENA.MIT.EDUraeburn"
    /// iter 1, reused here as a context base key so the base key itself is a
    /// published value even though the tokens built from it are not.
    const BASE_18: &str = "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161";
    /// RFC 8009 Appendix A's 128-bit base-key.
    const BASE_19: &str = "3705D96080C17728A0E800EAB6E0D23C";
    /// RFC 8009 Appendix A's 256-bit base-key.
    const BASE_20: &str = "6D404D37FAF79F9DF0D33568D320669800EB4836472EA8A026D16B7182460C52";

    const CONF: &str = "000102030405060708090a0b0c0d0e0f";
    /// The 8-octet application payload every golden below protects.
    const PAYLOAD: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7];

    fn ctx(etype: i32, base: &str, role: Role) -> PerMessageTokens<ContextKey> {
        PerMessageTokens::new(ContextKey::new(etype, &hex(base)).unwrap(), role, true)
    }

    /// Same, with no acceptor subkey asserted — the shape this server emits.
    fn ctx_nosub(etype: i32, base: &str, role: Role) -> PerMessageTokens<ContextKey> {
        PerMessageTokens::new(ContextKey::new(etype, &hex(base)).unwrap(), role, false)
    }

    /// MIC tokens, both directions, all three enctype families.
    ///
    /// The acceptor's Flags octet is 0x05 (SentByAcceptor | AcceptorSubkey)
    /// and the initiator's is 0x04; the checksum length differs per enctype
    /// (12 / 16 / 24), which is why all three are here.
    #[test]
    fn derived_mic_tokens_match_an_independent_implementation() {
        let cases: &[(i32, &str, Role, u64, &str)] = &[
            (17, BASE_17, Role::Initiator, 0,
             "040404ffffffffff00000000000000002c8776d63e1586f0b7d54e4a"),
            (17, BASE_17, Role::Acceptor, 0x0102030405060708,
             "040405ffffffffff010203040506070878852f2225938ea28a11a28f"),
            (18, BASE_18, Role::Initiator, 0,
             "040404ffffffffff0000000000000000532d63a1e102523cbaa5c097"),
            (18, BASE_18, Role::Acceptor, 0x0102030405060708,
             "040405ffffffffff0102030405060708ff34e97cde9edb2e1c58a327"),
            (19, BASE_19, Role::Initiator, 0,
             "040404ffffffffff00000000000000002aee928d6a136c7dcb8d2a8f1cd04e3f"),
            (19, BASE_19, Role::Acceptor, 0x0102030405060708,
             "040405ffffffffff0102030405060708db1d3db90b88d7410a75910578e0b835"),
            (20, BASE_20, Role::Initiator, 0,
             "040404ffffffffff0000000000000000e08e6d060dbe9f71ad6ab85fa00c7f25241392b4f8c7361f"),
            (20, BASE_20, Role::Acceptor, 0x0102030405060708,
             "040405ffffffffff010203040506070854a34723bc61a71f7141a1fd460025e432936f08059dc312"),
        ];
        for (etype, base, role, seq, want) in cases {
            let me = ctx(*etype, base, *role);
            let token = me.emit_mic(*seq, PAYLOAD).unwrap();
            assert_eq!(hexs(&token), *want, "enctype {} role {:?}", etype, role);
            // And the peer accepts it — with the peer's usage, not its own.
            let peer = ctx(*etype, base, role.peer());
            assert_eq!(peer.verify_mic(&token, PAYLOAD).unwrap().seq, *seq);
        }
    }

    /// Sealed Wrap tokens with EC = 0, RRC = 0, both directions.
    ///
    /// Length is `16 + 16 + len(plaintext) + 16 + h`: header, confounder,
    /// data, the appended header copy, and the truncated MAC.
    #[test]
    fn derived_sealed_wrap_tokens_match_an_independent_implementation() {
        let cases: &[(i32, &str, Role, &str)] = &[
            (17, BASE_17, Role::Initiator,
             "050406ff000000000000000000000007ffbf18b827f96b5c325be75e8d595e4f8d8d392596\
              79b917ea5fb3f74c2d4a0f287b6584dfbe3885e86d50aa6ec2506a270ee36b"),
            (17, BASE_17, Role::Acceptor,
             "050407ff0000000000000000000000074caaa925fccd83c289056bf912f70de8e5d062651a\
              08359699b637dc9453aa3d57e5ffb97203592acee19d963a097d7278696c46"),
            (18, BASE_18, Role::Initiator,
             "050406ff0000000000000000000000077e299b9a83dc44dfaa519480cdf11cbc2b83185d98fd2255\
              4be602ed9e90a85de734d16810b93c3278531bc0aa14022fccdf9847"),
            (18, BASE_18, Role::Acceptor,
             "050407ff000000000000000000000007af8e603aa82b1b47f135223602e8b05e6473e05d6a72e38b\
              72075d60a699760fe39dccab9098fd2cae301f8e6730eef182588c60"),
            (19, BASE_19, Role::Initiator,
             "050406ff0000000000000000000000074ceb0df199bd3b95bf86a2581e55e1ed95487197e7e5c41d\
              8ad94cba6250977b196b889a93566d07a0c906e1a64a3bc5050738d2b67b43c8"),
            (19, BASE_19, Role::Acceptor,
             "050407ff000000000000000000000007f024d936e836196982be25c96741b999b34a807a9ec9b126\
              f8d771c590a6b0c2934948627a7fd7a5311f8118410239f45d8c840254ab4b7b"),
            (20, BASE_20, Role::Initiator,
             "050406ff00000000000000000000000784b137d2eb9bb504415a9327d9e95821d59efeea7d2e40cc\
              993f03ca397a27d62daf2896a4bf6712173a6a1024ac5ca099ea3fe6a4306693195801bff6417e79"),
            (20, BASE_20, Role::Acceptor,
             "050407ff000000000000000000000007eab86ebfc360463fcb19dda4f08aac54cb7bdc8a4f89309f\
              3d66647295b796aaf873ae75c15e94d47c4ab0f2598cc9c007a50e27b13226519bc432b92c5f2e65"),
        ];
        for (etype, base, role, want) in cases {
            let me = ctx(*etype, base, *role);
            let token = me
                .emit_wrap_full(7, PAYLOAD, 0, 0, Some(&hex(CONF)))
                .unwrap();
            assert_eq!(
                hexs(&token),
                want.chars().filter(|c| !c.is_whitespace()).collect::<String>(),
                "enctype {} role {:?}",
                etype,
                role
            );
            let peer = ctx(*etype, base, role.peer());
            let v = peer.unwrap(&token).unwrap();
            assert_eq!(v.message, PAYLOAD);
            assert_eq!(v.seq, 7);
        }
    }

    /// The configuration flint ACTUALLY RUNS IN, which had no coverage at all.
    ///
    /// `EncAPRepPart::create(.., None)` never asserts an acceptor subkey, so
    /// this server emits `acceptor_subkey = false` — Flags 0x00 as initiator
    /// and 0x01 as acceptor, against the 0x04/0x05 every other golden here
    /// uses. The flag sits in the Flags octet, which is inside the checksum,
    /// so the whole token differs: e19 initiator MIC is
    /// ...94c38586dfe6d40e5059a56329d97785 here against
    /// ...2aee928d6a136c7dcb8d2a8f1cd04e3f with the subkey asserted. Twenty-one
    /// goldens covering only the flag flint does not set is a suite that could
    /// go green while the shipped path was wrong.
    ///
    /// Expected octets come from the same independent Python implementation as
    /// the goldens above — itself first pinned to FIPS-197 AES, the RFC 3962
    /// Appendix B CTS vectors, and then cross-checked by reproducing every one
    /// of the committed `acceptor_subkey = true` goldens before being trusted
    /// to derive these.
    #[test]
    fn derived_mic_tokens_without_an_acceptor_subkey() {
        let cases: &[(i32, &str, Role, u64, &str)] = &[
            (17, BASE_17, Role::Initiator, 0x0,
             "040400ffffffffff0000000000000000daec54d205dfeb4713361254"),
            (17, BASE_17, Role::Acceptor, 0x102030405060708,
             "040401ffffffffff0102030405060708a6851aa0c42611ab402c53c4"),
            (18, BASE_18, Role::Initiator, 0x0,
             "040400ffffffffff0000000000000000d3dc7bbc47571ee7e303a9a4"),
            (18, BASE_18, Role::Acceptor, 0x102030405060708,
             "040401ffffffffff0102030405060708142ccd49757fa8aa54438b58"),
            (19, BASE_19, Role::Initiator, 0x0,
             "040400ffffffffff000000000000000094c38586dfe6d40e5059a56329d97785"),
            (19, BASE_19, Role::Acceptor, 0x102030405060708,
             "040401ffffffffff01020304050607082dc2fd69c700476bb953c76e9feed764"),
            (20, BASE_20, Role::Initiator, 0x0,
             "040400ffffffffff0000000000000000090ed891f36ae4d9029043c0a34d4e0a1673f43de2164ed7"),
            (20, BASE_20, Role::Acceptor, 0x102030405060708,
             "040401ffffffffff01020304050607085f54e155bc000419b30b1c6d32eea775242d7158ee61083e"),
        ];
        for (etype, base, role, seq, want) in cases {
            let me = ctx_nosub(*etype, base, *role);
            let token = me.emit_mic(*seq, PAYLOAD).unwrap();
            assert_eq!(hexs(&token), *want, "enctype {} role {:?}", etype, role);
            let peer = ctx_nosub(*etype, base, role.peer());
            assert_eq!(peer.verify_mic(&token, PAYLOAD).unwrap().seq, *seq);
        }
    }

    /// Sealed Wrap in the same no-subkey configuration. Flags 0x02 / 0x03.
    #[test]
    fn derived_sealed_wrap_without_an_acceptor_subkey() {
        let cases: &[(i32, &str, Role, &str)] = &[
            (17, BASE_17, Role::Initiator,
             "050402ff000000000000000000000007ffbf18b827f96b5c325be75e8d595e4f41dcba7ec80ace\
              ed80be324c5e924fedc529347823737ca6d42951437408bf00860dce6e"),
            (17, BASE_17, Role::Acceptor,
             "050403ff0000000000000000000000074caaa925fccd83c289056bf912f70de8e8c0515e3ba197\
              a87a013b1586fda4aae94b5ac6f44c2e0771f1f682309f3f1ffc01650d"),
            (18, BASE_18, Role::Initiator,
             "050402ff0000000000000000000000077e299b9a83dc44dfaa519480cdf11cbcfbb6fe270041e5\
              474dd18adc2d57a0726d56e48c96d726cc7fd07b8b12fc9592a32dfdbc"),
            (18, BASE_18, Role::Acceptor,
             "050403ff000000000000000000000007af8e603aa82b1b47f135223602e8b05edf10e3a1459381\
              e7395d7422d2091272a03382245b30d45f7e113eb326098f450191bc2a"),
            (19, BASE_19, Role::Initiator,
             "050402ff0000000000000000000000074ceb0df199bd3b95bf86a2581e55e1ed68cb051d172a3e\
              d6d3ee9a0b8a27c11adcdfa411787cb6728c4f1c5af77965e413223ccf353aa4ef"),
            (19, BASE_19, Role::Acceptor,
             "050403ff000000000000000000000007f024d936e836196982be25c96741b99986d9e9b456223b\
              7c8603be2925d01e1dde62fc57c0fe5ab796c337b06f116c75b54dcab5bd3dfb1a"),
            (20, BASE_20, Role::Initiator,
             "050402ff00000000000000000000000784b137d2eb9bb504415a9327d9e958217bb9eeba253f35\
              d14280a73cba41ba34f194784df10cfdd1c8c81b26ad286c3eb0bb09149344f6f9359fc31b23f1\
              fc76"),
            (20, BASE_20, Role::Acceptor,
             "050403ff000000000000000000000007eab86ebfc360463fcb19dda4f08aac541a024c3bd3046f\
              867bde394ff0555c50d7550ba2c93e5256d7bc261fc163d8a5f2876433b2a121b33de92fe15388\
              77a2"),
        ];
        for (etype, base, role, want) in cases {
            let me = ctx_nosub(*etype, base, *role);
            let token = me.emit_wrap_full(7, PAYLOAD, 0, 0, Some(&hex(CONF))).unwrap();
            assert_eq!(
                hexs(&token),
                want.chars().filter(|c| !c.is_whitespace()).collect::<String>(),
                "enctype {} role {:?}", etype, role
            );
            let peer = ctx_nosub(*etype, base, role.peer());
            let v = peer.unwrap(&token).unwrap();
            assert_eq!(v.message, PAYLOAD);
            assert_eq!(v.seq, 7);
        }
    }

    /// The two configurations must not produce the same octets — otherwise the
    /// goldens above would be pinning nothing that the existing set does not.
    #[test]
    fn the_acceptor_subkey_flag_changes_every_token() {
        for etype in [17, 18, 19, 20] {
            let base = match etype { 17 => BASE_17, 18 => BASE_18, 19 => BASE_19, _ => BASE_20 };
            for role in [Role::Initiator, Role::Acceptor] {
                let with = ctx(etype, base, role).emit_mic(0, PAYLOAD).unwrap();
                let without = ctx_nosub(etype, base, role).emit_mic(0, PAYLOAD).unwrap();
                assert_ne!(with, without, "enctype {} role {:?}", etype, role);
            }
        }
    }

    /// The case that separates a correct implementation from a plausible one:
    /// EC = 5 and RRC = 13 together.
    ///
    /// EC keeps its value inside the encryption while RRC is zeroed there
    /// (§4.2.4), and the body is rotated right by 13 on the wire (§4.2.5).
    /// With EC = 0 and RRC = 0 — the shape every other golden here uses, and
    /// the shape MIT krb5 and Windows interoperate on — both rules are
    /// invisible, so this is the golden that would actually go red.
    #[test]
    fn derived_sealed_wrap_with_nonzero_ec_and_rrc() {
        let cli = ctx(19, BASE_19, Role::Acceptor);
        let token = cli
            .emit_wrap_full(7, PAYLOAD, 5, 13, Some(&hex(CONF)))
            .unwrap();
        assert_eq!(
            hexs(&token),
            concat!(
                "050407ff0005000d0000000000000007",
                "76852b48d396d2ae06d6390df6",
                "f024d936e836196982be25c96741b999",
                "d7b3b3640327bc2df93e6238fade4435e52ef12c53baf39dd805120f1220a4e6"
            )
        );

        // The same token at RRC = 0 is the unrotated body — the first 13
        // octets above are exactly the last 13 here.
        let flat = cli
            .emit_wrap_full(7, PAYLOAD, 5, 0, Some(&hex(CONF)))
            .unwrap();
        assert_eq!(
            hexs(&flat),
            concat!(
                "050407ff000500000000000000000007",
                "f024d936e836196982be25c96741b999",
                "d7b3b3640327bc2df93e6238fade4435e52ef12c53baf39dd805120f1220a4e6",
                "76852b48d396d2ae06d6390df6"
            )
        );
        assert_eq!(rotate_right(&flat[16..], 13), &token[16..]);

        let srv = ctx(19, BASE_19, Role::Initiator);
        assert_eq!(srv.unwrap(&token).unwrap().message, PAYLOAD);
        assert_eq!(srv.unwrap(&flat).unwrap().message, PAYLOAD);
    }

    /// Unsealed Wrap tokens. EC is emitted as `h`, and BOTH EC and RRC are
    /// zeroed in the checksummed header copy — the opposite rule from the
    /// sealed case, one paragraph away in §4.2.4.
    #[test]
    fn derived_unsealed_wrap_tokens_match_an_independent_implementation() {
        let cases: &[(i32, &str, Role, &str)] = &[
            (17, BASE_17, Role::Initiator,
             "050404ff000c000000000000000000090001020304050607a0d8ce1cac59e693a9c31230"),
            (17, BASE_17, Role::Acceptor,
             "050405ff000c000000000000000000090001020304050607af6df208c51d424d9acabfab"),
            (18, BASE_18, Role::Initiator,
             "050404ff000c00000000000000000009000102030405060712af097d1370b835c36fc046"),
            (18, BASE_18, Role::Acceptor,
             "050405ff000c000000000000000000090001020304050607403313145b239381c75a5fe5"),
            (19, BASE_19, Role::Initiator,
             "050404ff0010000000000000000000090001020304050607ce9c8b54b0cb9c79b4329797998a5bd7"),
            (19, BASE_19, Role::Acceptor,
             "050405ff0010000000000000000000090001020304050607dcf0a1550d3a0636fee742b06d358f71"),
            (20, BASE_20, Role::Initiator,
             "050404ff001800000000000000000009000102030405060798df9d2a07a12525b2122f4ec702d0fbfe9a2ad36f045659"),
            (20, BASE_20, Role::Acceptor,
             "050405ff0018000000000000000000090001020304050607584893509f118a3f2bafab2f7b193979b1e4d1ce7af6032f"),
        ];
        for (etype, base, role, want) in cases {
            let me = ctx(*etype, base, *role);
            let token = me.emit_wrap_unsealed(9, PAYLOAD, 0).unwrap();
            assert_eq!(hexs(&token), *want, "enctype {} role {:?}", etype, role);
            let peer = ctx(*etype, base, role.peer());
            assert_eq!(peer.verify_wrap_unsealed(&token).unwrap().message, PAYLOAD);
        }

        // ...and rotated. The plaintext and checksum rotate together, so the
        // checksum cannot even be located until after rotate_left.
        let srv = ctx(19, BASE_19, Role::Acceptor);
        assert_eq!(
            hexs(&srv.emit_wrap_unsealed(9, PAYLOAD, 4).unwrap()),
            "050405ff0010000400000000000000096d358f710001020304050607dcf0a1550d3a0636fee742b0"
        );
    }

    /// The RFC 4121 §2 usages, resolved through the real RFC 3961 §5.3 /
    /// RFC 8009 §5 derivation, are four genuinely different key triples.
    ///
    /// This is what makes the emit/verify usage swap detectable at all: if
    /// 22 and 24 produced the same keys, the classic bug would be invisible
    /// even against a real peer.
    #[test]
    fn derived_the_four_per_message_usages_yield_distinct_keys() {
        for (etype, base) in [(18, BASE_18), (19, BASE_19), (20, BASE_20)] {
            let k = ContextKey::new(etype, &hex(base)).unwrap();
            let mut seen: Vec<Vec<u8>> = Vec::new();
            for usage in 22u32..=25 {
                let ks = k.keys(usage).unwrap();
                for key in [&ks.kc, &ks.ke, &ks.ki] {
                    assert!(!seen.contains(key), "enctype {} usage {} key reused", etype, usage);
                    seen.push(key.clone());
                }
                // RFC 8009 §5's length asymmetry: for enctype 20 Ke is 32
                // octets while Kc and Ki are 24. A single `key_size()` for
                // all three truncates SHA-384's 48 octets to 32 silently.
                assert_eq!(ks.ke.len(), k.enctype().ke_len());
                assert_eq!(ks.ki.len(), k.enctype().ki_len());
                assert_eq!(ks.kc.len(), k.enctype().kc_len());
            }
            assert_eq!(seen.len(), 12);
        }
    }

    /// Usages outside RFC 4121 §2 are refused rather than silently derived.
    /// Usage 2 is an RFC 4120 ticket and has no business here.
    #[test]
    fn context_key_refuses_usages_outside_rfc4121_section_2() {
        let k = ContextKey::new(19, &hex(BASE_19)).unwrap();
        assert!(k.keys(2).is_err());
        assert!(k.keys(21).is_err());
        assert!(k.keys(26).is_err());
        assert!(k.keys(0).is_err());
        for u in 22..=25 {
            assert!(k.keys(u).is_ok());
        }
    }

    /// A wrong-length base key or an unsupported enctype fails at context
    /// setup, not on the first wrapped READ.
    #[test]
    fn context_key_rejects_a_bad_enctype_or_base_key_length() {
        assert!(ContextKey::new(23, &hex(BASE_19)).is_err()); // rc4-hmac
        assert!(ContextKey::new(19, &hex(BASE_20)).is_err()); // 32 octets for aes128
        assert!(ContextKey::new(20, &hex(BASE_19)).is_err()); // 16 octets for aes256
    }

    /// The whole point of the module, stated as a test: a server emits with
    /// acceptor usages and verifies with initiator ones, over real crypto.
    /// Swap them and every one of these fails.
    #[test]
    fn derived_full_duplex_exchange_over_real_crypto() {
        for (etype, base) in [(17, BASE_17), (18, BASE_18), (19, BASE_19), (20, BASE_20)] {
            let srv = ctx(etype, base, Role::Acceptor);
            let cli = ctx(etype, base, Role::Initiator);
            let payload = b"NFSv4 COMPOUND".as_slice();

            let call_mic = cli.emit_mic(1, payload).unwrap();
            assert_eq!(srv.verify_mic(&call_mic, payload).unwrap().seq, 1);
            assert!(cli.verify_mic(&call_mic, payload).is_err(), "reflection");

            let reply_mic = srv.emit_mic(1, &1u32.to_be_bytes()).unwrap();
            cli.verify_mic(&reply_mic, &1u32.to_be_bytes()).unwrap();
            assert!(srv.verify_mic(&reply_mic, &1u32.to_be_bytes()).is_err());

            let call = cli.emit_wrap(2, payload).unwrap();
            assert_eq!(srv.unwrap(&call).unwrap().message, payload);
            assert!(cli.unwrap(&call).is_err(), "reflection");

            let reply = srv.emit_wrap(2, payload).unwrap();
            assert_eq!(cli.unwrap(&reply).unwrap().message, payload);
            assert!(srv.unwrap(&reply).is_err(), "reflection");

            // A fresh confounder per message: the same plaintext twice must
            // not give the same ciphertext.
            assert_ne!(srv.emit_wrap(3, payload).unwrap(), srv.emit_wrap(3, payload).unwrap());
        }
    }

    /// Token lengths, which callers size buffers from.
    /// MIC = 16 + h. Sealed Wrap = 16 + 16 + len + 16 + h with EC = 0.
    #[test]
    fn derived_token_lengths() {
        for (etype, base, h) in [(17, BASE_17, 12usize), (18, BASE_18, 12), (19, BASE_19, 16), (20, BASE_20, 24)] {
            let srv = ctx(etype, base, Role::Acceptor);
            for n in [0usize, 1, 15, 16, 17, 1000] {
                let p = vec![0xa5u8; n];
                assert_eq!(srv.emit_mic(0, &p).unwrap().len(), 16 + h);
                assert_eq!(srv.emit_wrap(0, &p).unwrap().len(), 16 + 16 + n + 16 + h);
                assert_eq!(srv.emit_wrap_unsealed(0, &p, 0).unwrap().len(), 16 + n + h);
            }
        }
    }

    // =================================================================
    // Round trips through the framing (in addition to, never instead of,
    // the pinned tests above).
    // =================================================================

    #[test]
    fn round_trip_every_shape_across_the_two_roles() {
        for h in [12usize, 16, 24] {
            let srv = acceptor(h);
            let cli = initiator(h);
            for payload in [
                &b""[..],
                &b"a"[..],
                &b"0123456789abcdef"[..],
                &vec![0x5au8; 4096][..],
            ] {
                let mic = cli.emit_mic(11, payload).unwrap();
                assert_eq!(mic.len(), HEADER_LEN + h);
                assert_eq!(srv.verify_mic(&mic, payload).unwrap().seq, 11);

                for ec in [0u16, 1, 17] {
                    for rrc in [0u16, 5, 300] {
                        let w = cli.emit_wrap_full(12, payload, ec, rrc, None).unwrap();
                        let v = srv.unwrap(&w).unwrap();
                        assert_eq!(v.message, payload, "h={} ec={} rrc={}", h, ec, rrc);
                        assert_eq!(v.seq, 12);
                    }
                }

                let u = cli.emit_wrap_unsealed(13, payload, 3).unwrap();
                let v = srv.verify_wrap_unsealed(&u).unwrap();
                assert_eq!(v.message, payload);
                assert_eq!(v.seq, 13);
            }
        }
    }
}

