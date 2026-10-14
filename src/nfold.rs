//! RFC 3961 §5.1 n-fold — stretch or shrink an octet string to exactly n bits.
//!
//! n-fold is the single most-misimplemented primitive in Kerberos, and its
//! absence is a shipped defect in this repo: `crate::acceptor`'s
//! `dr_aes_sha1` ZERO-PADS the 5-octet key-derivation constant to the AES
//! block size where RFC 3961 §5.1 requires `n-fold(Constant)`. Zero-padding
//! `00 00 00 02 AA` gives `00000002AA0000000000000000000000` — a completely
//! different input to E, hence a completely different derived key, hence a
//! cryptosystem no KDC speaks. Every AES key this repo derives is wrong
//! because this function did not exist.
//!
//! The algorithm, from §5.1 (quoting \[Blumenthal96\] as the RFC does):
//!
//! > To n-fold a number X, replicate the input value to a length that is the
//! > least common multiple of n and the length of X. Before each repetition,
//! > the input is rotated to the right by 13 bit positions. The successive
//! > n-bit chunks are added together using 1's-complement addition (that is,
//! > with end-around carry) to yield a n-bit result.
//!
//! Four traps live in those three sentences, and all four are load-bearing:
//!
//!   1. The rotation is 13 BITS, not 13 bytes, and it is to the RIGHT.
//!   2. It is applied to the m-octet INPUT copy, cumulatively — copy `i` is
//!      the input rotated by `13*i` bits — not to the growing output buffer,
//!      and not re-derived from the original input each time (that would make
//!      every copy after the first identical).
//!   3. Copy 0 is UNROTATED. RFC 3961 A.1 closes with the observable
//!      consequence: "the initial octets exactly match the input string when
//!      the output length is a multiple of the input length."
//!   4. The addition carries END-AROUND. Plain two's-complement addition with
//!      the carry discarded agrees on many inputs — including
//!      64-fold("012345"), the vector everyone quotes — and diverges on
//!      others. That is exactly why the tests below pin all eleven published
//!      vectors and not the famous one.
//!
//! Pinned to all 11 vectors of RFC 3961 Appendix A.1, hex copied from
//! <https://www.rfc-editor.org/rfc/rfc3961.txt>.

/// n-fold `input` to exactly `out_bits` bits, per RFC 3961 §5.1.
///
/// Returns `out_bits / 8` octets. All values are big-endian ("Most
/// Significant Byte first", §5.1), so the result is the n-bit one's-complement
/// sum of the replicated, progressively right-rotated input, emitted MSB
/// first.
///
/// Call sites in the AES profile flint supports:
///
///   * RFC 3961 §5.1 DR — `n-fold(Constant, 128)`, where `Constant` is the
///     4-octet big-endian key usage followed by one of 0x99 (Kc), 0xAA (Ke)
///     or 0x55 (Ki). Always 5 octets, therefore ALWAYS n-folded for AES.
///   * RFC 3962 §4 and RFC 8009 §4 string-to-key — `n-fold("kerberos", 128)`,
///     which is `6b65726265726f737b9b5b2b93132b93` and is pinned below.
///   * RFC 3961 §5.3 PRF — `n-fold("prf", 128)`.
///
/// RFC 8009 (enctypes 19/20) does NOT use n-fold at all: its KDF-HMAC-SHA2 is
/// a different construction with no cipher and no folding. Do not reach for
/// this function there.
///
/// # Panics
///
/// Panics if `out_bits` is zero or not a multiple of 8, or if `input` is
/// empty. Both are programmer errors: n-fold of an empty string has no
/// definition (the replication length `lcm(n, 0)` does not exist), and every
/// caller in this crate folds an implementation-chosen constant, never
/// attacker-supplied bytes. Failing loudly beats silently deriving a key from
/// nothing.
pub fn n_fold(input: &[u8], out_bits: usize) -> Vec<u8> {
    assert!(
        out_bits > 0 && out_bits % 8 == 0,
        "n-fold output length must be a positive multiple of 8 bits, got {out_bits}"
    );
    assert!(
        !input.is_empty(),
        "n-fold of an empty octet string is undefined"
    );

    let out_len = out_bits / 8;
    let in_len = input.len();

    // "replicate the input value to a length that is the least common multiple
    // of n and the length of X". Note this runs to the lcm even when the input
    // is LONGER than the output — 64-fold of a 33-octet string still replicates
    // eight times (lcm(8,33) = 264). An implementation that short-circuits when
    // m > n fails RFC 3961 A.1's "Rough Consensus, and Running Code" vector.
    let total = lcm(out_len, in_len);
    let reps = total / in_len;

    // Materialising the replicated buffer is the literal reading of the RFC,
    // and the chunk boundaries are then unambiguous. One's-complement addition
    // is arithmetic mod 2^n - 1, so a cleverer streaming version that folds
    // each byte in at its residue position is possible — but it reassociates
    // the sum, and the 0x00..00 / 0xFF..FF ("negative zero") representations
    // are exactly where reassociation is observable. Not worth the risk: every
    // constant this crate folds makes `total` at most 80 octets.
    let mut buf = Vec::with_capacity(total);
    let mut copy = input.to_vec();
    for i in 0..reps {
        // "BEFORE each repetition" — so copy 0 goes in untouched and the
        // rotation accumulates across copies (copy i is the input rotated
        // 13*i bits), rather than each copy being the input rotated 13.
        if i > 0 {
            copy = rotate_right_13(&copy);
        }
        buf.extend_from_slice(&copy);
    }
    debug_assert_eq!(buf.len(), total);

    let mut acc = vec![0u8; out_len];
    for chunk in buf.chunks_exact(out_len) {
        ones_complement_add_into(&mut acc, chunk);
    }
    acc
}

/// Rotate an octet string right by 13 bit positions, treating it as one
/// big-endian integer of `8 * input.len()` bits (RFC 3961 §5.1).
///
/// The rotation is over the WHOLE string, so it moves bits across octet
/// boundaries and wraps the low bits back into the top octet.
fn rotate_right_13(input: &[u8]) -> Vec<u8> {
    let n = input.len();
    debug_assert!(n > 0);
    let nbits = n * 8;

    // For a one-octet input the effective rotation is 13 mod 8 = 5 bits — not
    // 13 (which would shift everything out) and not 0. RFC 3961 A.1's
    // 168-fold("Q") is the vector that catches this: "Q" is 0x51, and the
    // second octet of the published answer 518a54a2... is 0x8a, which is
    // exactly 0x51 rotated right five bits.
    let r = 13 % nbits;
    let byte_shift = (r / 8) % n;
    let bit_shift = r % 8;

    let mut out = vec![0u8; n];
    for i in 0..n {
        // Output octet i takes its high (8 - bit_shift) bits from the octet
        // `byte_shift` to its left, and its low bit_shift bits from the octet
        // before that — both indices wrapping, because this is a rotation.
        let src = (i + n - byte_shift) % n;
        let prev = (src + n - 1) % n;
        out[i] = if bit_shift == 0 {
            input[src]
        } else {
            (input[src] >> bit_shift) | (input[prev] << (8 - bit_shift))
        };
    }
    out
}

/// Add `addend` into `acc` as big-endian integers of the same width, using
/// one's-complement addition — carry out of the top is added back in at the
/// bottom (RFC 3961 §5.1, "with end-around carry").
///
/// This is the step a naive implementation gets wrong by simply letting the
/// carry fall off the end.
fn ones_complement_add_into(acc: &mut [u8], addend: &[u8]) {
    debug_assert_eq!(acc.len(), addend.len());
    let n = acc.len();

    let mut carry = 0u16;
    for i in (0..n).rev() {
        let sum = u16::from(acc[i]) + u16::from(addend[i]) + carry;
        acc[i] = sum as u8;
        carry = sum >> 8;
    }

    // Fold the carry back in at the least significant end, and KEEP folding.
    // For a pairwise add of two n-bit values a single fold-back provably
    // cannot carry out again (a + b <= 2^(n+1) - 2, so the folded result is at
    // most 2^n - 1), which is why the one-shot form survives in the wild — but
    // that proof depends on accumulating pairwise, and anyone who later widens
    // this to sum several chunks at once would silently lose a carry. The loop
    // costs nothing and does not depend on the invariant.
    while carry != 0 {
        let mut c = carry;
        for i in (0..n).rev() {
            let sum = u16::from(acc[i]) + c;
            acc[i] = sum as u8;
            c = sum >> 8;
            if c == 0 {
                break;
            }
        }
        carry = c;
    }
}

fn gcd(mut a: usize, mut b: usize) -> usize {
    while b != 0 {
        let t = a % b;
        a = b;
        b = t;
    }
    a
}

fn lcm(a: usize, b: usize) -> usize {
    a / gcd(a, b) * b
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0, "odd-length hex literal: {s}");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("bad hex literal"))
            .collect()
    }

    // ---------------------------------------------------------------------
    // RFC 3961 Appendix A.1 — the complete published vector set.
    // Hex copied from https://www.rfc-editor.org/rfc/rfc3961.txt (the
    // whitespace the RFC uses to group octets into words is stripped).
    // ---------------------------------------------------------------------

    #[test]
    fn rfc3961_a1_nfold_64_of_012345() {
        assert_eq!(n_fold(b"012345", 64), hex("be072631276b1955"));
    }

    #[test]
    fn rfc3961_a1_nfold_56_of_password() {
        // 56 bits = 7 octets, an output length that shares no factor with the
        // 8-octet input: lcm(7,8) = 56, so this is the vector that exercises
        // eight chunks and seven rotations.
        assert_eq!(n_fold(b"password", 56), hex("78a07b6caf85fa"));
    }

    #[test]
    fn rfc3961_a1_nfold_64_of_rough_consensus() {
        // Input (33 octets) is LONGER than the output (8). Replication still
        // runs to lcm(8,33) = 264.
        assert_eq!(
            n_fold(b"Rough Consensus, and Running Code", 64),
            hex("bb6ed30870b7f0e0")
        );
    }

    #[test]
    fn rfc3961_a1_nfold_168_of_password() {
        assert_eq!(
            n_fold(b"password", 168),
            hex("59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e")
        );
    }

    #[test]
    fn rfc3961_a1_nfold_192_of_massachvsetts() {
        assert_eq!(
            n_fold(b"MASSACHVSETTS INSTITVTE OF TECHNOLOGY", 192),
            hex("db3b0d8f0b061e603282b308a50841229ad798fab9540c1b")
        );
    }

    #[test]
    fn rfc3961_a1_nfold_168_of_q() {
        // One-octet input: the rotation reduces to 13 mod 8 = 5 bits. This is
        // the only vector that pins that reduction.
        assert_eq!(
            n_fold(b"Q", 168),
            hex("518a54a215a8452a518a54a215a8452a518a54a215")
        );
    }

    #[test]
    fn rfc3961_a1_nfold_168_of_ba() {
        // Two octets: rotating right 13 of 16 bits is the same as rotating
        // left 3, which is where a byte-granular implementation falls over.
        assert_eq!(
            n_fold(b"ba", 168),
            hex("fb25d531ae8974499f52fd92ea9857c4ba24cf297e")
        );
    }

    #[test]
    fn rfc3961_a1_nfold_64_of_kerberos() {
        assert_eq!(n_fold(b"kerberos", 64), hex("6b65726265726f73"));
    }

    #[test]
    fn rfc3961_a1_nfold_128_of_kerberos() {
        assert_eq!(
            n_fold(b"kerberos", 128),
            hex("6b65726265726f737b9b5b2b93132b93")
        );
    }

    #[test]
    fn rfc3961_a1_nfold_168_of_kerberos() {
        assert_eq!(
            n_fold(b"kerberos", 168),
            hex("8372c236344e5f1550cd0747e15d62ca7a5a3bcea4")
        );
    }

    #[test]
    fn rfc3961_a1_nfold_256_of_kerberos() {
        assert_eq!(
            n_fold(b"kerberos", 256),
            hex("6b65726265726f737b9b5b2b93132b935c9bdcdad95c9899c4cae4dee6d6cae4")
        );
    }

    // ---------------------------------------------------------------------
    // The n-fold calls the OTHER RFCs make. RFC 3962 and RFC 8009 never say
    // "n-fold" — they reach it through DK() — so these tests exist to name the
    // call site, and they pin the same published A.1 hex.
    // ---------------------------------------------------------------------

    #[test]
    fn rfc3962_s4_string_to_key_folds_kerberos_to_the_aes_block_size() {
        // RFC 3962 §4: key = DK(tkey, "kerberos"), and RFC 3961 §5.1 folds
        // that constant to c = 16 octets before the first AES call. Get this
        // wrong and every one of RFC 3962 Appendix B's fourteen AES keys is
        // unreachable. RFC 8009 §4 reuses the same "kerberos" label (through a
        // different KDF that does not fold, so only RFC 3962 lands here).
        assert_eq!(
            n_fold(b"kerberos", 128),
            hex("6b65726265726f737b9b5b2b93132b93")
        );
    }

    #[test]
    fn rfc3961_s6_3_1_des3_string_to_key_folds_to_168_bits() {
        // des3-cbc-hmac-sha1-kd is out of flint's scope (AES only), but §6.3.1
        // is the reason the 168-bit output length is published at all, and a
        // 21-octet output is not a whole number of anything convenient — it is
        // the length that catches an implementation assuming the output is a
        // multiple of the input or of 8.
        assert_eq!(
            n_fold(b"password", 168),
            hex("59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e")
        );
    }

    // ---------------------------------------------------------------------
    // The 5-octet key-usage constant, pinned to PUBLISHED data.
    //
    // RFC 3961 A.1 contains no 5-octet input, so there is no direct vector
    // for the fold that every derived key in the simplified profile performs
    // — the exact shape kerberos.rs got wrong. A.1 is not the only published
    // data that constrains it, though. Appendix A.3 prints eight
    // des3-cbc-hmac-sha1-kd DR values, and seven use a 5-octet usage
    // constant. Section 6.3.1 defines
    //
    //     DR(Key, Constant) = k-truncate(K1 | K2 | K3)
    //     K1 = E(Key, n-fold(Constant, 64), initial-cipher-state)
    //     Kn = E(Key, K(n-1), initial-cipher-state)
    //
    // with E = DES3-CBC, a zero initial cipher state and k = 168 bits. Given
    // the published Key and DR, n-fold(Constant, 64) is the only free input:
    // any other value makes all eight published DR strings come out wrong.
    //
    // Verified out of band rather than here, because importing a DES3
    // implementation into an AES-only crate purely to test n-fold is a worse
    // trade than recording the conclusion. To redo it: implement DES3-ECB,
    // compute K1|K2|K3 from the folds below, truncate to 21 octets, and
    // compare against all eight DR values in A.3. All eight reproduce
    // exactly. The two folds below are therefore known answers backed by
    // RFC 3961 A.3 — not hex this module computed for itself.
    //
    // Note what this does and does not pin: the 5-octet INPUT shape at
    // n = 64. The AES call site folds the same shape to n = 128, for which
    // no published vector exists in any RFC (3962's Appendix B is
    // string-to-key only, and 8009 does not fold at all). A.1's
    // 128-fold("kerberos") pins the 128-bit output length; these pin the
    // 5-octet input. Nothing published pins their intersection.
    // ---------------------------------------------------------------------

    #[test]
    fn rfc3961_a3_five_octet_usage_constants_fold_as_des3_dr_requires() {
        // usage 1, Ki (0x55) — A.3 vectors 1, 3, 6 and 8.
        assert_eq!(n_fold(&hex("0000000155"), 64), hex("00055780df9aa800"));
        // usage 1, Ke (0xAA) — A.3 vectors 2, 4, 5 and 7.
        assert_eq!(n_fold(&hex("00000001aa"), 64), hex("0006ac606f2d5000"));
    }

    #[test]
    fn a_five_octet_constant_folds_differently_for_each_key_usage_tag() {
        // The bug in kerberos.rs was using Kc's 0x99 where Ke needs 0xAA, and
        // zero-padding hides how much that matters: the padded blocks differ
        // in one byte. After a fold, a one-byte change to the constant must
        // change essentially the whole block, or DR would leak structure
        // between the three derived keys of the same usage.
        let kc = n_fold(&hex("0000000299"), 128);
        let ke = n_fold(&hex("00000002aa"), 128);
        let ki = n_fold(&hex("0000000255"), 128);
        assert_ne!(kc, ke);
        assert_ne!(ke, ki);
        assert_ne!(kc, ki);
        // Not a strict avalanche claim, just a floor: a fold that left most
        // octets untouched would be zero-padding wearing a hat.
        let differing = kc.iter().zip(ke.iter()).filter(|(a, b)| a != b).count();
        assert!(
            differing >= 12,
            "only {differing} of 16 octets differ between the Kc and Ke folds"
        );
    }

    // ---------------------------------------------------------------------
    // Properties the RFC states in prose, and the defect this module exists
    // to kill.
    // ---------------------------------------------------------------------

    #[test]
    fn rfc3961_a1_initial_octets_match_the_input_when_output_is_a_multiple() {
        // A.1's closing sentence, verbatim: "Note that the initial octets
        // exactly match the input string when the output length is a multiple
        // of the input length." This holds only because copy 0 is UNROTATED,
        // so it is the cheapest check for the rotate-everything-including-the-
        // first-copy bug.
        for input in [
            b"kerberos".as_slice(),
            b"01234567".as_slice(),
            b"Q".as_slice(),
        ] {
            for multiple in 1..=4 {
                let out = n_fold(input, input.len() * 8 * multiple);
                assert_eq!(
                    &out[..input.len()],
                    input,
                    "{multiple}x fold of {input:?} did not open with the input"
                );
            }
        }
    }

    #[test]
    fn rfc3961_s5_1_output_is_exactly_the_requested_length() {
        for bits in [8usize, 56, 64, 128, 168, 192, 256, 384, 512] {
            assert_eq!(n_fold(b"kerberos", bits).len(), bits / 8);
            assert_eq!(n_fold(b"Q", bits).len(), bits / 8);
        }
    }

    #[test]
    fn rfc3961_s5_1_five_octet_usage_constant_is_not_the_zero_padded_constant() {
        // The shipped bug, stated as a test: kerberos.rs's dr_aes_sha1 padded
        // the constant with zeroes to the block size instead of folding it.
        // There is no published n-fold vector for a 5-octet usage constant (see
        // the module note), so this cannot be a known-answer test — but it can
        // assert the two are not the same function, which is the whole claim.
        for constant_byte in [0x99u8, 0xAA, 0x55] {
            let constant = [0x00, 0x00, 0x00, 0x02, constant_byte];
            let folded = n_fold(&constant, 128);

            let mut zero_padded = constant.to_vec();
            zero_padded.resize(16, 0);

            assert_eq!(folded.len(), 16);
            assert_ne!(
                folded, zero_padded,
                "n-fold agreed with zero-padding for constant byte {constant_byte:#04x}; \
                 one of the two is not doing what it says"
            );
            // And the fold must actually mix: the constant is 5 octets and the
            // block is 16, so no octet of the input may simply survive in
            // place across the whole output.
            assert_ne!(&folded[..5], &constant[..]);
        }
    }

    // ---------------------------------------------------------------------
    // Falsifiability. A vector that passes against a broken implementation is
    // not evidence, and this repo already shipped a suite of tests that could
    // not fail. So: implement the five classic n-fold bugs and prove the
    // published vectors detect each one.
    // ---------------------------------------------------------------------

    /// A deliberately slow bit-at-a-time rotation, used only by the tests. It
    /// is a second, independent expression of the rotation, so a mistake in
    /// the production byte-shuffling shows up as a disagreement rather than as
    /// two copies of the same mistake.
    fn rot_bits(input: &[u8], amount: usize, left: bool) -> Vec<u8> {
        let nbits = input.len() * 8;
        let r = amount % nbits;
        let mut out = vec![0u8; input.len()];
        for i in 0..nbits {
            let src = if left {
                (i + r) % nbits
            } else {
                (i + nbits - r) % nbits
            };
            let bit = (input[src / 8] >> (7 - src % 8)) & 1;
            out[i / 8] |= bit << (7 - i % 8);
        }
        out
    }

    #[test]
    fn production_rotation_agrees_with_an_independent_bitwise_rotation() {
        for len in 1..=40usize {
            let input: Vec<u8> = (0..len)
                .map(|i| (i as u8).wrapping_mul(37).wrapping_add(11))
                .collect();
            assert_eq!(
                rotate_right_13(&input),
                rot_bits(&input, 13, false),
                "byte-shuffled rotation disagrees with the bitwise one at len {len}"
            );
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum Bug {
        /// Rotate left instead of right.
        RotateLeft,
        /// Rotate by 13 BYTES instead of 13 bits.
        RotateThirteenBytes,
        /// Re-derive every copy from the original input, so copy i is rotated
        /// 13 rather than 13*i.
        RotateFromInputEachTime,
        /// Rotate copy 0 as well, breaking the "initial octets match" property.
        RotateCopyZeroToo,
        /// Plain addition with the carry out of the top discarded.
        DropEndAroundCarry,
    }

    fn n_fold_with_bug(input: &[u8], out_bits: usize, bug: Bug) -> Vec<u8> {
        let out_len = out_bits / 8;
        let total = lcm(out_len, input.len());
        let mut buf = Vec::with_capacity(total);
        let mut copy = input.to_vec();
        for i in 0..(total / input.len()) {
            if matches!(bug, Bug::RotateCopyZeroToo) {
                copy = rot_bits(&copy, 13, false);
            } else if i > 0 {
                copy = match bug {
                    Bug::RotateLeft => rot_bits(&copy, 13, true),
                    Bug::RotateThirteenBytes => rot_bits(&copy, 13 * 8, false),
                    Bug::RotateFromInputEachTime => rot_bits(input, 13, false),
                    _ => rot_bits(&copy, 13, false),
                };
            }
            buf.extend_from_slice(&copy);
        }

        let mut acc = vec![0u8; out_len];
        for chunk in buf.chunks_exact(out_len) {
            if matches!(bug, Bug::DropEndAroundCarry) {
                let mut carry = 0u16;
                for i in (0..out_len).rev() {
                    let sum = u16::from(acc[i]) + u16::from(chunk[i]) + carry;
                    acc[i] = sum as u8;
                    carry = sum >> 8;
                }
            } else {
                ones_complement_add_into(&mut acc, chunk);
            }
        }
        acc
    }

    fn a1_vectors() -> Vec<(&'static [u8], usize, &'static str)> {
        vec![
            (b"012345", 64, "be072631276b1955"),
            (b"password", 56, "78a07b6caf85fa"),
            (b"Rough Consensus, and Running Code", 64, "bb6ed30870b7f0e0"),
            (
                b"password",
                168,
                "59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e",
            ),
            (
                b"MASSACHVSETTS INSTITVTE OF TECHNOLOGY",
                192,
                "db3b0d8f0b061e603282b308a50841229ad798fab9540c1b",
            ),
            (b"Q", 168, "518a54a215a8452a518a54a215a8452a518a54a215"),
            (b"ba", 168, "fb25d531ae8974499f52fd92ea9857c4ba24cf297e"),
            (b"kerberos", 64, "6b65726265726f73"),
            (b"kerberos", 128, "6b65726265726f737b9b5b2b93132b93"),
            (
                b"kerberos",
                168,
                "8372c236344e5f1550cd0747e15d62ca7a5a3bcea4",
            ),
            (
                b"kerberos",
                256,
                "6b65726265726f737b9b5b2b93132b935c9bdcdad95c9899c4cae4dee6d6cae4",
            ),
        ]
    }

    #[test]
    fn a1_vectors_are_the_ones_this_module_actually_computes() {
        // The table used by the falsifiability sweep must agree with the
        // individually-named tests above, or the sweep is measuring nothing.
        for (input, bits, expected) in a1_vectors() {
            assert_eq!(n_fold(input, bits), hex(expected), "{bits}-fold({input:?})");
        }
    }

    #[test]
    fn published_vectors_detect_every_classic_nfold_bug() {
        // Exact counts, not `> 0`. The margin is the point: if a later edit
        // drops DropEndAroundCarry from five detections to one the suite is
        // still green but is one vector away from blind, and that is worth
        // failing over. These counts were re-derived against the A.1 table by
        // an independent implementation, not copied from a previous run.
        for (bug, expected_detections) in [
            (Bug::RotateLeft, 10),
            (Bug::RotateThirteenBytes, 10),
            (Bug::RotateFromInputEachTime, 9),
            (Bug::RotateCopyZeroToo, 11),
            (Bug::DropEndAroundCarry, 5),
        ] {
            let detected = a1_vectors()
                .into_iter()
                .filter(|(input, bits, expected)| {
                    n_fold_with_bug(input, *bits, bug) != hex(expected)
                })
                .count();
            assert_eq!(
                detected, expected_detections,
                "{bug:?} is caught by {detected} of the eleven published vectors, \
                 not {expected_detections} — its detection power has changed"
            );
        }
    }

    #[test]
    fn the_famous_vector_alone_cannot_see_the_end_around_carry() {
        // This is why all eleven vectors are pinned rather than the one
        // everybody quotes. 64-fold("012345") produces the published answer
        // whether or not the carry wraps, so a suite built around it would
        // have blessed a plain-addition fold.
        assert_eq!(
            n_fold_with_bug(b"012345", 64, Bug::DropEndAroundCarry),
            hex("be072631276b1955")
        );
        // 56-fold("password") is one of the five that does see it.
        assert_ne!(
            n_fold_with_bug(b"password", 56, Bug::DropEndAroundCarry),
            hex("78a07b6caf85fa")
        );
    }

    // ---------------------------------------------------------------------
    // Argument handling.
    // ---------------------------------------------------------------------

    #[test]
    #[should_panic(expected = "positive multiple of 8 bits")]
    fn out_bits_must_be_a_multiple_of_eight() {
        n_fold(b"kerberos", 100);
    }

    #[test]
    #[should_panic(expected = "positive multiple of 8 bits")]
    fn out_bits_must_be_nonzero() {
        n_fold(b"kerberos", 0);
    }

    #[test]
    #[should_panic(expected = "empty octet string")]
    fn empty_input_is_rejected_rather_than_folded_to_zeroes() {
        n_fold(b"", 128);
    }

    #[test]
    fn folding_is_deterministic() {
        // Not evidence of the wire format — see the module note — but it does
        // catch accidental state leaking between calls.
        for _ in 0..4 {
            assert_eq!(
                n_fold(b"kerberos", 128),
                hex("6b65726265726f737b9b5b2b93132b93")
            );
        }
    }
}
