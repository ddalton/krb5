//! edwards25519 (RFC 7748, RFC 8032 encoding) for SPAKE: the group MIT's
//! client offers by default. Field elements are five 51-bit limbs; points
//! are extended twisted Edwards coordinates (a = -1) with the complete
//! formulas of Hisil, Wong, Carter and Dawson (2008). Every operation on
//! a secret (the password-derived multiplier w, our private scalar) runs
//! in constant time: fixed 4-bit windows with every table entry read,
//! selection by masks, reduction by conditional subtraction.

use std::sync::OnceLock;

const MASK: u64 = (1 << 51) - 1;

/// An element of GF(2^255 - 19), limbs below 2^52 between operations.
#[derive(Clone, Copy, Debug)]
pub(super) struct Fe([u64; 5]);

fn m(a: u64, b: u64) -> u128 {
    u128::from(a) * u128::from(b)
}

impl Fe {
    const ZERO: Fe = Fe([0; 5]);
    const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    fn small(v: u64) -> Fe {
        Fe([v, 0, 0, 0, 0])
    }

    /// The 255 low bits of `b`, little-endian (the top bit is ignored).
    fn from_bytes(b: &[u8; 32]) -> Fe {
        let load = |i: usize| u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
        Fe([
            load(0) & MASK,
            (load(6) >> 3) & MASK,
            (load(12) >> 6) & MASK,
            (load(19) >> 1) & MASK,
            (load(24) >> 12) & MASK,
        ])
    }

    /// The canonical (fully reduced) little-endian encoding.
    fn to_bytes(self) -> [u8; 32] {
        let mut l = self.reduce().0;
        // q = 1 exactly when the value is at least p.
        let mut q = (l[0] + 19) >> 51;
        for limb in &l[1..] {
            q = (limb + q) >> 51;
        }
        l[0] += 19 * q;
        for i in 0..4 {
            l[i + 1] += l[i] >> 51;
            l[i] &= MASK;
        }
        l[4] &= MASK;
        let mut out = [0u8; 32];
        let (mut acc, mut bits, mut at) = (0u128, 0, 0);
        for limb in l {
            acc |= u128::from(limb) << bits;
            bits += 51;
            while bits >= 8 {
                out[at] = acc as u8;
                acc >>= 8;
                bits -= 8;
                at += 1;
            }
        }
        out[at] = acc as u8;
        out
    }

    fn reduce(self) -> Fe {
        let l = self.0;
        let c: [u64; 5] = std::array::from_fn(|i| l[i] >> 51);
        Fe([
            (l[0] & MASK) + c[4] * 19,
            (l[1] & MASK) + c[0],
            (l[2] & MASK) + c[1],
            (l[3] & MASK) + c[2],
            (l[4] & MASK) + c[3],
        ])
    }

    fn add(self, o: Fe) -> Fe {
        Fe(std::array::from_fn(|i| self.0[i] + o.0[i])).reduce()
    }

    /// self - o, as self + 16p - o so no limb goes negative.
    fn sub(self, o: Fe) -> Fe {
        const P16_0: u64 = 36_028_797_018_963_664;
        const P16_N: u64 = 36_028_797_018_963_952;
        Fe(std::array::from_fn(|i| {
            self.0[i] + if i == 0 { P16_0 } else { P16_N } - o.0[i]
        }))
        .reduce()
    }

    fn neg(self) -> Fe {
        Fe::ZERO.sub(self)
    }

    fn mul(self, o: Fe) -> Fe {
        let (a, b) = (self.0, o.0);
        let b19: [u64; 5] = std::array::from_fn(|i| b[i] * 19);
        let c0 =
            m(a[0], b[0]) + m(a[4], b19[1]) + m(a[3], b19[2]) + m(a[2], b19[3]) + m(a[1], b19[4]);
        let mut c1 =
            m(a[1], b[0]) + m(a[0], b[1]) + m(a[4], b19[2]) + m(a[3], b19[3]) + m(a[2], b19[4]);
        let mut c2 =
            m(a[2], b[0]) + m(a[1], b[1]) + m(a[0], b[2]) + m(a[4], b19[3]) + m(a[3], b19[4]);
        let mut c3 =
            m(a[3], b[0]) + m(a[2], b[1]) + m(a[1], b[2]) + m(a[0], b[3]) + m(a[4], b19[4]);
        let mut c4 = m(a[4], b[0]) + m(a[3], b[1]) + m(a[2], b[2]) + m(a[1], b[3]) + m(a[0], b[4]);
        let mut out = [0u64; 5];
        c1 += c0 >> 51;
        out[0] = (c0 as u64) & MASK;
        c2 += c1 >> 51;
        out[1] = (c1 as u64) & MASK;
        c3 += c2 >> 51;
        out[2] = (c2 as u64) & MASK;
        c4 += c3 >> 51;
        out[3] = (c3 as u64) & MASK;
        let carry = (c4 >> 51) as u64;
        out[4] = (c4 as u64) & MASK;
        out[0] += carry * 19;
        out[1] += out[0] >> 51;
        out[0] &= MASK;
        Fe(out)
    }

    fn square(self) -> Fe {
        self.mul(self)
    }

    /// self^e for a public exponent `e` (little-endian).
    fn pow(self, e: &[u8; 32]) -> Fe {
        let mut r = Fe::ONE;
        for i in (0..256).rev() {
            r = r.square();
            if (e[i / 8] >> (i % 8)) & 1 == 1 {
                r = r.mul(self);
            }
        }
        r
    }

    /// 1/self (0 for 0): self^(p-2).
    fn invert(self) -> Fe {
        let mut e = [0xFF; 32];
        e[0] = 0xEB;
        e[31] = 0x7F;
        self.pow(&e)
    }

    /// self^((p-5)/8), for square roots.
    fn pow_p58(self) -> Fe {
        let mut e = [0xFF; 32];
        e[0] = 0xFD;
        e[31] = 0x0F;
        self.pow(&e)
    }

    fn ct_eq(self, o: Fe) -> bool {
        let (a, b) = (self.to_bytes(), o.to_bytes());
        a.iter().zip(&b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
    }

    fn is_negative(self) -> bool {
        self.to_bytes()[0] & 1 == 1
    }

    /// `a` if `choice` is 0, `b` if it is 1, without branching.
    fn select(a: Fe, b: Fe, choice: u64) -> Fe {
        let mask = choice.wrapping_neg();
        Fe(std::array::from_fn(|i| a.0[i] ^ (mask & (a.0[i] ^ b.0[i]))))
    }
}

struct Constants {
    d: Fe,
    d2: Fe,
    sqrt_m1: Fe,
    base: Point,
}

fn constants() -> &'static Constants {
    static C: OnceLock<Constants> = OnceLock::new();
    C.get_or_init(|| {
        let d = Fe::small(121_665).neg().mul(Fe::small(121_666).invert());
        // 2^((p-1)/4)
        let mut e = [0xFF; 32];
        e[0] = 0xFB;
        e[31] = 0x1F;
        let sqrt_m1 = Fe::small(2).pow(&e);
        let mut c = Constants {
            d,
            d2: d.add(d),
            sqrt_m1,
            base: Point::IDENTITY,
        };
        // RFC 8032 §5.1: B has y = 4/5 and x positive.
        let mut b = [0x66; 32];
        b[0] = 0x58;
        c.base = Point::decode_with(&b, &c).expect("the base point decodes");
        c
    })
}

/// A point in extended coordinates: x = X/Z, y = Y/Z, xy = T/Z.
#[derive(Clone, Copy, Debug)]
pub(super) struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

impl Point {
    pub(super) const IDENTITY: Point = Point {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
        t: Fe::ZERO,
    };

    pub(super) fn base() -> Point {
        constants().base
    }

    /// RFC 8032 §5.1.3 decoding: `None` for a y with no x on the curve,
    /// or "-0".
    pub(super) fn decode(b: &[u8; 32]) -> Option<Point> {
        Self::decode_with(b, constants())
    }

    fn decode_with(b: &[u8; 32], c: &Constants) -> Option<Point> {
        let y = Fe::from_bytes(b);
        let sign = b[31] >> 7;
        let yy = y.square();
        let u = yy.sub(Fe::ONE);
        let v = c.d.mul(yy).add(Fe::ONE);
        // x = u v^3 (u v^7)^((p-5)/8), then fix up by sqrt(-1).
        let v3 = v.square().mul(v);
        let mut x = u.mul(v3).mul(u.mul(v3.square().mul(v)).pow_p58());
        let vxx = v.mul(x.square());
        if vxx.ct_eq(u) {
        } else if vxx.ct_eq(u.neg()) {
            x = x.mul(c.sqrt_m1);
        } else {
            return None;
        }
        if x.ct_eq(Fe::ZERO) && sign == 1 {
            return None;
        }
        if x.is_negative() != (sign == 1) {
            x = x.neg();
        }
        Some(Point {
            x,
            y,
            z: Fe::ONE,
            t: x.mul(y),
        })
    }

    pub(super) fn encode(&self) -> [u8; 32] {
        let zi = self.z.invert();
        let (x, y) = (self.x.mul(zi), self.y.mul(zi));
        let mut b = y.to_bytes();
        b[31] |= (x.to_bytes()[0] & 1) << 7;
        b
    }

    /// add-2008-hwcd-3, complete for a = -1.
    pub(super) fn add(&self, q: &Point) -> Point {
        let d2 = constants().d2;
        let a = self.y.sub(self.x).mul(q.y.sub(q.x));
        let b = self.y.add(self.x).mul(q.y.add(q.x));
        let c = self.t.mul(d2).mul(q.t);
        let d = self.z.add(self.z).mul(q.z);
        let (e, f, g, h) = (b.sub(a), d.sub(c), d.add(c), b.add(a));
        Point {
            x: e.mul(f),
            y: g.mul(h),
            z: f.mul(g),
            t: e.mul(h),
        }
    }

    /// dbl-2008-hwcd, a = -1.
    fn double(&self) -> Point {
        let a = self.x.square();
        let b = self.y.square();
        let c = self.z.square().add(self.z.square());
        let d = a.neg();
        let e = self.x.add(self.y).square().sub(a).sub(b);
        let g = d.add(b);
        let f = g.sub(c);
        let h = d.sub(b);
        Point {
            x: e.mul(f),
            y: g.mul(h),
            z: f.mul(g),
            t: e.mul(h),
        }
    }

    pub(super) fn neg(&self) -> Point {
        Point {
            x: self.x.neg(),
            y: self.y,
            z: self.z,
            t: self.t.neg(),
        }
    }

    fn select(a: &Point, b: &Point, choice: u64) -> Point {
        Point {
            x: Fe::select(a.x, b.x, choice),
            y: Fe::select(a.y, b.y, choice),
            z: Fe::select(a.z, b.z, choice),
            t: Fe::select(a.t, b.t, choice),
        }
    }

    /// k * self for a 256-bit little-endian `k`, in constant time.
    pub(super) fn mul(&self, k: &[u8; 32]) -> Point {
        let mut table = [Point::IDENTITY; 16];
        for i in 1..16 {
            table[i] = table[i - 1].add(self);
        }
        let mut acc = Point::IDENTITY;
        for i in (0..64).rev() {
            for _ in 0..4 {
                acc = acc.double();
            }
            let nibble = u64::from((k[i / 2] >> (4 * (i % 2))) & 0x0F);
            let mut pick = Point::IDENTITY;
            for (j, entry) in table.iter().enumerate() {
                // 1 exactly when j == nibble.
                let eq = ((j as u64 ^ nibble).wrapping_sub(1) >> 63) & 1;
                pick = Point::select(&pick, entry, eq);
            }
            acc = acc.add(&pick);
        }
        acc
    }
}

/// The group order L = 2^252 + 27742317777372353535851937790883648493,
/// as 64-bit little-endian limbs.
const L: [u64; 4] = [
    0x5812_631a_5cf5_d3ed,
    0x14de_f9de_a2f7_9cd6,
    0,
    0x1000_0000_0000_0000,
];

/// `k` (little-endian, any 256-bit value) mod L, in constant time: a
/// value below 2^256 is below 16L, so subtracting 8L, 4L, 2L and L where
/// each fits leaves the remainder.
pub(super) fn reduce_scalar(k: &[u8; 32]) -> [u8; 32] {
    let mut x: [u64; 4] =
        std::array::from_fn(|i| u64::from_le_bytes(k[8 * i..8 * i + 8].try_into().unwrap()));
    for shift in [3u32, 2, 1, 0] {
        let mut ml = [0u64; 4];
        let mut carry = 0u64;
        for i in 0..4 {
            ml[i] = (L[i] << shift) | carry;
            carry = if shift == 0 { 0 } else { L[i] >> (64 - shift) };
        }
        let mut diff = [0u64; 4];
        let mut borrow = 0u64;
        for i in 0..4 {
            let (d1, b1) = x[i].overflowing_sub(ml[i]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            diff[i] = d2;
            borrow = u64::from(b1 | b2);
        }
        // Keep the difference when there was no borrow.
        let keep = borrow.wrapping_sub(1);
        for i in 0..4 {
            x[i] ^= keep & (x[i] ^ diff[i]);
        }
    }
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[8 * i..8 * i + 8].copy_from_slice(&x[i].to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(s: &str) -> [u8; 32] {
        let v: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        v.try_into().unwrap()
    }

    #[test]
    fn the_constants_are_what_they_claim() {
        let c = constants();
        assert!(c.sqrt_m1.square().ct_eq(Fe::ONE.neg()));
        assert!(c.d.mul(Fe::small(121_666)).ct_eq(Fe::small(121_665).neg()));
        // RFC 8032's d, big-endian.
        let mut d = hex32("52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3");
        d.reverse();
        assert_eq!(c.d.to_bytes(), d);
        // L·B is the identity; the base point re-encodes.
        let mut l = [0u8; 32];
        for i in 0..4 {
            l[8 * i..8 * i + 8].copy_from_slice(&L[i].to_le_bytes());
        }
        assert_eq!(Point::base().mul(&l).encode(), Point::IDENTITY.encode());
        let mut b = [0x66; 32];
        b[0] = 0x58;
        assert_eq!(Point::base().encode(), b);
    }

    /// RFC 8032 §7.1 test 1: the public key is the clamped, hashed secret
    /// key times B. Independent of SPAKE's vectors.
    #[test]
    fn rfc_8032_public_key() {
        use sha2::{Digest, Sha512};
        let sk = hex32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let h = Sha512::digest(sk);
        let mut s: [u8; 32] = h[..32].try_into().unwrap();
        s[0] &= 248;
        s[31] &= 127;
        s[31] |= 64;
        assert_eq!(
            Point::base().mul(&s).encode(),
            hex32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        );
    }

    #[test]
    fn field_round_trips_and_reduces() {
        // p itself encodes as zero; p - 1 as itself.
        let mut p = [0xFF; 32];
        p[0] = 0xED;
        p[31] = 0x7F;
        assert_eq!(Fe::from_bytes(&p).to_bytes(), [0; 32]);
        let mut pm1 = p;
        pm1[0] = 0xEC;
        assert_eq!(Fe::from_bytes(&pm1).to_bytes(), pm1);
        let x = Fe::from_bytes(&hex32(
            "0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210",
        ));
        assert!(x.mul(x.invert()).ct_eq(Fe::ONE));
        assert!(x.sub(x).ct_eq(Fe::ZERO));
        assert!(x.add(x.neg()).ct_eq(Fe::ZERO));
    }

    #[test]
    fn points_add_double_and_decode_consistently() {
        let b = Point::base();
        let two = b.add(&b);
        assert_eq!(two.encode(), b.double().encode());
        let mut k = [0u8; 32];
        k[0] = 5;
        let five = b.mul(&k);
        assert_eq!(five.encode(), two.double().add(&b).encode());
        assert_eq!(
            Point::decode(&five.encode()).unwrap().encode(),
            five.encode()
        );
        assert_eq!(b.add(&b.neg()).encode(), Point::IDENTITY.encode());
        // y = 2 has no x on the curve.
        let mut bad = [0u8; 32];
        bad[0] = 2;
        assert!(Point::decode(&bad).is_none());
        // RFC 8032 §5.1.3: x = 0 with the sign bit set ("-0") is refused;
        // y = 1 (the identity) has x = 0.
        let mut minus_zero = Point::IDENTITY.encode();
        assert!(Point::decode(&minus_zero).is_some());
        minus_zero[31] |= 0x80;
        assert!(Point::decode(&minus_zero).is_none());
    }

    #[test]
    fn scalars_reduce_mod_l() {
        let mut l = [0u8; 32];
        for i in 0..4 {
            l[8 * i..8 * i + 8].copy_from_slice(&L[i].to_le_bytes());
        }
        assert_eq!(reduce_scalar(&l), [0; 32]);
        let mut l1 = l;
        l1[0] += 1;
        let mut one = [0u8; 32];
        one[0] = 1;
        assert_eq!(reduce_scalar(&l1), one);
        // 2^256 - 1 mod L, from Python: (2**256 - 1) % L.
        assert_eq!(
            reduce_scalar(&[0xFF; 32]),
            hex32("1c95988d7431ecd670cf7d73f45befc6feffffffffffffffffffffffffffff0f")
        );
    }
}
