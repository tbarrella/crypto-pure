//! Module for Curve25519 ECDH.
//!
//! Translated to Rust from Daniel J. Bernstein's public domain SUPERCOP `ref10` implementation.
use core::ops::{AddAssign, MulAssign, SubAssign};

/// Computes a public key for use in Curve25519 Diffie-Hellman key exchange.
///
/// # Panics
///
/// Panics if `secret_key.len()` is not equal to 32.
pub fn gen_pk(secret_key: &[u8]) -> [u8; 32] {
    let mut public_key = [0; 32];
    let mut basepoint = [0; 32];
    basepoint[0] = 9;
    scalarmult(&mut public_key, secret_key, &basepoint);
    public_key
}

/// Computes a Curve25519 Diffie-Hellman shared secret given a secret key and another's public key.
///
/// # Panics
///
/// Panics if `public_key.len()` or `secret_key.len()` is not equal to 32.
pub fn dh(public_key: &[u8], secret_key: &[u8]) -> [u8; 32] {
    let mut secret = [0; 32];
    scalarmult(&mut secret, secret_key, public_key);
    secret
}

#[inline(never)]
pub(crate) fn verify_32(x: &[u8; 32], y: &[u8]) -> i32 {
    let differentbits = x
        .iter()
        .zip(y)
        .fold(0, |acc, (x, y)| acc | i32::from(x ^ y));
    (1 & ((differentbits - 1) >> 8)) - 1
}

pub(crate) fn load_3(x: &[u8]) -> u64 {
    let mut result = u64::from(x[0]);
    result |= u64::from(x[1]) << 8;
    result |= u64::from(x[2]) << 16;
    result
}

pub(crate) fn load_4(x: &[u8]) -> u64 {
    let mut result = u64::from(x[0]);
    result |= u64::from(x[1]) << 8;
    result |= u64::from(x[2]) << 16;
    result |= u64::from(x[3]) << 24;
    result
}

#[derive(Clone, Copy, Default)]
pub(crate) struct Fe(pub(crate) [i32; 10]);

macro_rules! square_many {
    ($f:expr, $i:expr) => {
        for _ in 1..$i {
            $f.square();
        }
    };
}

macro_rules! fe_invert {
    ($out:expr, $z:expr) => {
        let mut t0 = &mut Fe::default();
        let mut t1 = &mut Fe::default();
        let mut t2 = &mut Fe::default();
        let t3 = &mut Fe::default();

        t0.assign_square($z);

        t1.assign_square(t0);
        t1.square();

        t1 *= $z;

        t0 *= t1;

        t2.assign_square(t0);

        t1 *= t2;

        t2.assign_square(t1);
        square_many!(t2, 5);

        t1 *= t2;

        t2.assign_square(t1);
        square_many!(t2, 10);
        t2 *= t1;

        t3.assign_square(t2);
        square_many!(t3, 20);

        t2 *= t3;
        square_many!(t2, 11);

        t1 *= t2;

        t2.assign_square(t1);
        square_many!(t2, 50);

        t2 *= t1;

        t3.assign_square(t2);
        square_many!(t3, 100);

        t2 *= t3;
        square_many!(t2, 51);

        t1 *= t2;
        square_many!(t1, 6);

        $out.assign_product(t1, t0);
    };
}

macro_rules! fe_mul {
    ($h:expr, $f:expr, $g:expr) => {
        let f0 = $f[0];
        let f1 = $f[1];
        let f2 = $f[2];
        let f3 = $f[3];
        let f4 = $f[4];
        let f5 = $f[5];
        let f6 = $f[6];
        let f7 = $f[7];
        let f8 = $f[8];
        let f9 = $f[9];
        let g0 = $g[0];
        let g1 = $g[1];
        let g2 = $g[2];
        let g3 = $g[3];
        let g4 = $g[4];
        let g5 = $g[5];
        let g6 = $g[6];
        let g7 = $g[7];
        let g8 = $g[8];
        let g9 = $g[9];
        let g1_19 = 19 * g1;
        let g2_19 = 19 * g2;
        let g3_19 = 19 * g3;
        let g4_19 = 19 * g4;
        let g5_19 = 19 * g5;
        let g6_19 = 19 * g6;
        let g7_19 = 19 * g7;
        let g8_19 = 19 * g8;
        let g9_19 = 19 * g9;
        let f1_2 = 2 * f1;
        let f3_2 = 2 * f3;
        let f5_2 = 2 * f5;
        let f7_2 = 2 * f7;
        let f9_2 = 2 * f9;
        let f0g0 = i64::from(f0) * i64::from(g0);
        let f0g1 = i64::from(f0) * i64::from(g1);
        let f0g2 = i64::from(f0) * i64::from(g2);
        let f0g3 = i64::from(f0) * i64::from(g3);
        let f0g4 = i64::from(f0) * i64::from(g4);
        let f0g5 = i64::from(f0) * i64::from(g5);
        let f0g6 = i64::from(f0) * i64::from(g6);
        let f0g7 = i64::from(f0) * i64::from(g7);
        let f0g8 = i64::from(f0) * i64::from(g8);
        let f0g9 = i64::from(f0) * i64::from(g9);
        let f1g0 = i64::from(f1) * i64::from(g0);
        let f1g1_2 = i64::from(f1_2) * i64::from(g1);
        let f1g2 = i64::from(f1) * i64::from(g2);
        let f1g3_2 = i64::from(f1_2) * i64::from(g3);
        let f1g4 = i64::from(f1) * i64::from(g4);
        let f1g5_2 = i64::from(f1_2) * i64::from(g5);
        let f1g6 = i64::from(f1) * i64::from(g6);
        let f1g7_2 = i64::from(f1_2) * i64::from(g7);
        let f1g8 = i64::from(f1) * i64::from(g8);
        let f1g9_38 = i64::from(f1_2) * i64::from(g9_19);
        let f2g0 = i64::from(f2) * i64::from(g0);
        let f2g1 = i64::from(f2) * i64::from(g1);
        let f2g2 = i64::from(f2) * i64::from(g2);
        let f2g3 = i64::from(f2) * i64::from(g3);
        let f2g4 = i64::from(f2) * i64::from(g4);
        let f2g5 = i64::from(f2) * i64::from(g5);
        let f2g6 = i64::from(f2) * i64::from(g6);
        let f2g7 = i64::from(f2) * i64::from(g7);
        let f2g8_19 = i64::from(f2) * i64::from(g8_19);
        let f2g9_19 = i64::from(f2) * i64::from(g9_19);
        let f3g0 = i64::from(f3) * i64::from(g0);
        let f3g1_2 = i64::from(f3_2) * i64::from(g1);
        let f3g2 = i64::from(f3) * i64::from(g2);
        let f3g3_2 = i64::from(f3_2) * i64::from(g3);
        let f3g4 = i64::from(f3) * i64::from(g4);
        let f3g5_2 = i64::from(f3_2) * i64::from(g5);
        let f3g6 = i64::from(f3) * i64::from(g6);
        let f3g7_38 = i64::from(f3_2) * i64::from(g7_19);
        let f3g8_19 = i64::from(f3) * i64::from(g8_19);
        let f3g9_38 = i64::from(f3_2) * i64::from(g9_19);
        let f4g0 = i64::from(f4) * i64::from(g0);
        let f4g1 = i64::from(f4) * i64::from(g1);
        let f4g2 = i64::from(f4) * i64::from(g2);
        let f4g3 = i64::from(f4) * i64::from(g3);
        let f4g4 = i64::from(f4) * i64::from(g4);
        let f4g5 = i64::from(f4) * i64::from(g5);
        let f4g6_19 = i64::from(f4) * i64::from(g6_19);
        let f4g7_19 = i64::from(f4) * i64::from(g7_19);
        let f4g8_19 = i64::from(f4) * i64::from(g8_19);
        let f4g9_19 = i64::from(f4) * i64::from(g9_19);
        let f5g0 = i64::from(f5) * i64::from(g0);
        let f5g1_2 = i64::from(f5_2) * i64::from(g1);
        let f5g2 = i64::from(f5) * i64::from(g2);
        let f5g3_2 = i64::from(f5_2) * i64::from(g3);
        let f5g4 = i64::from(f5) * i64::from(g4);
        let f5g5_38 = i64::from(f5_2) * i64::from(g5_19);
        let f5g6_19 = i64::from(f5) * i64::from(g6_19);
        let f5g7_38 = i64::from(f5_2) * i64::from(g7_19);
        let f5g8_19 = i64::from(f5) * i64::from(g8_19);
        let f5g9_38 = i64::from(f5_2) * i64::from(g9_19);
        let f6g0 = i64::from(f6) * i64::from(g0);
        let f6g1 = i64::from(f6) * i64::from(g1);
        let f6g2 = i64::from(f6) * i64::from(g2);
        let f6g3 = i64::from(f6) * i64::from(g3);
        let f6g4_19 = i64::from(f6) * i64::from(g4_19);
        let f6g5_19 = i64::from(f6) * i64::from(g5_19);
        let f6g6_19 = i64::from(f6) * i64::from(g6_19);
        let f6g7_19 = i64::from(f6) * i64::from(g7_19);
        let f6g8_19 = i64::from(f6) * i64::from(g8_19);
        let f6g9_19 = i64::from(f6) * i64::from(g9_19);
        let f7g0 = i64::from(f7) * i64::from(g0);
        let f7g1_2 = i64::from(f7_2) * i64::from(g1);
        let f7g2 = i64::from(f7) * i64::from(g2);
        let f7g3_38 = i64::from(f7_2) * i64::from(g3_19);
        let f7g4_19 = i64::from(f7) * i64::from(g4_19);
        let f7g5_38 = i64::from(f7_2) * i64::from(g5_19);
        let f7g6_19 = i64::from(f7) * i64::from(g6_19);
        let f7g7_38 = i64::from(f7_2) * i64::from(g7_19);
        let f7g8_19 = i64::from(f7) * i64::from(g8_19);
        let f7g9_38 = i64::from(f7_2) * i64::from(g9_19);
        let f8g0 = i64::from(f8) * i64::from(g0);
        let f8g1 = i64::from(f8) * i64::from(g1);
        let f8g2_19 = i64::from(f8) * i64::from(g2_19);
        let f8g3_19 = i64::from(f8) * i64::from(g3_19);
        let f8g4_19 = i64::from(f8) * i64::from(g4_19);
        let f8g5_19 = i64::from(f8) * i64::from(g5_19);
        let f8g6_19 = i64::from(f8) * i64::from(g6_19);
        let f8g7_19 = i64::from(f8) * i64::from(g7_19);
        let f8g8_19 = i64::from(f8) * i64::from(g8_19);
        let f8g9_19 = i64::from(f8) * i64::from(g9_19);
        let f9g0 = i64::from(f9) * i64::from(g0);
        let f9g1_38 = i64::from(f9_2) * i64::from(g1_19);
        let f9g2_19 = i64::from(f9) * i64::from(g2_19);
        let f9g3_38 = i64::from(f9_2) * i64::from(g3_19);
        let f9g4_19 = i64::from(f9) * i64::from(g4_19);
        let f9g5_38 = i64::from(f9_2) * i64::from(g5_19);
        let f9g6_19 = i64::from(f9) * i64::from(g6_19);
        let f9g7_38 = i64::from(f9_2) * i64::from(g7_19);
        let f9g8_19 = i64::from(f9) * i64::from(g8_19);
        let f9g9_38 = i64::from(f9_2) * i64::from(g9_19);
        let mut h0 = f0g0
            + f1g9_38
            + f2g8_19
            + f3g7_38
            + f4g6_19
            + f5g5_38
            + f6g4_19
            + f7g3_38
            + f8g2_19
            + f9g1_38;
        let mut h1 = f0g1
            + f1g0
            + f2g9_19
            + f3g8_19
            + f4g7_19
            + f5g6_19
            + f6g5_19
            + f7g4_19
            + f8g3_19
            + f9g2_19;
        let mut h2 = f0g2
            + f1g1_2
            + f2g0
            + f3g9_38
            + f4g8_19
            + f5g7_38
            + f6g6_19
            + f7g5_38
            + f8g4_19
            + f9g3_38;
        let mut h3 =
            f0g3 + f1g2 + f2g1 + f3g0 + f4g9_19 + f5g8_19 + f6g7_19 + f7g6_19 + f8g5_19 + f9g4_19;
        let mut h4 =
            f0g4 + f1g3_2 + f2g2 + f3g1_2 + f4g0 + f5g9_38 + f6g8_19 + f7g7_38 + f8g6_19 + f9g5_38;
        let mut h5 =
            f0g5 + f1g4 + f2g3 + f3g2 + f4g1 + f5g0 + f6g9_19 + f7g8_19 + f8g7_19 + f9g6_19;
        let mut h6 =
            f0g6 + f1g5_2 + f2g4 + f3g3_2 + f4g2 + f5g1_2 + f6g0 + f7g9_38 + f8g8_19 + f9g7_38;
        let mut h7 = f0g7 + f1g6 + f2g5 + f3g4 + f4g3 + f5g2 + f6g1 + f7g0 + f8g9_19 + f9g8_19;
        let mut h8 = f0g8 + f1g7_2 + f2g6 + f3g5_2 + f4g4 + f5g3_2 + f6g2 + f7g1_2 + f8g0 + f9g9_38;
        let mut h9 = f0g9 + f1g8 + f2g7 + f3g6 + f4g5 + f5g4 + f6g3 + f7g2 + f8g1 + f9g0;
        let mut carry0;
        let carry1;
        let carry2;
        let carry3;
        let mut carry4;
        let carry5;
        let carry6;
        let carry7;
        let carry8;
        let carry9;

        carry0 = (h0 + (1 << 25)) >> 26;
        h1 += carry0;
        h0 -= carry0 << 26;
        carry4 = (h4 + (1 << 25)) >> 26;
        h5 += carry4;
        h4 -= carry4 << 26;

        carry1 = (h1 + (1 << 24)) >> 25;
        h2 += carry1;
        h1 -= carry1 << 25;
        carry5 = (h5 + (1 << 24)) >> 25;
        h6 += carry5;
        h5 -= carry5 << 25;

        carry2 = (h2 + (1 << 25)) >> 26;
        h3 += carry2;
        h2 -= carry2 << 26;
        carry6 = (h6 + (1 << 25)) >> 26;
        h7 += carry6;
        h6 -= carry6 << 26;

        carry3 = (h3 + (1 << 24)) >> 25;
        h4 += carry3;
        h3 -= carry3 << 25;
        carry7 = (h7 + (1 << 24)) >> 25;
        h8 += carry7;
        h7 -= carry7 << 25;

        carry4 = (h4 + (1 << 25)) >> 26;
        h5 += carry4;
        h4 -= carry4 << 26;
        carry8 = (h8 + (1 << 25)) >> 26;
        h9 += carry8;
        h8 -= carry8 << 26;

        carry9 = (h9 + (1 << 24)) >> 25;
        h0 += carry9 * 19;
        h9 -= carry9 << 25;

        carry0 = (h0 + (1 << 25)) >> 26;
        h1 += carry0;
        h0 -= carry0 << 26;

        $h[0] = h0 as i32;
        $h[1] = h1 as i32;
        $h[2] = h2 as i32;
        $h[3] = h3 as i32;
        $h[4] = h4 as i32;
        $h[5] = h5 as i32;
        $h[6] = h6 as i32;
        $h[7] = h7 as i32;
        $h[8] = h8 as i32;
        $h[9] = h9 as i32;
    };
}

macro_rules! fe_sq {
    ($h:expr, $f:expr) => {
        let f0 = $f[0];
        let f1 = $f[1];
        let f2 = $f[2];
        let f3 = $f[3];
        let f4 = $f[4];
        let f5 = $f[5];
        let f6 = $f[6];
        let f7 = $f[7];
        let f8 = $f[8];
        let f9 = $f[9];
        let f0_2 = 2 * f0;
        let f1_2 = 2 * f1;
        let f2_2 = 2 * f2;
        let f3_2 = 2 * f3;
        let f4_2 = 2 * f4;
        let f5_2 = 2 * f5;
        let f6_2 = 2 * f6;
        let f7_2 = 2 * f7;
        let f5_38 = 38 * f5;
        let f6_19 = 19 * f6;
        let f7_38 = 38 * f7;
        let f8_19 = 19 * f8;
        let f9_38 = 38 * f9;
        let f0f0 = i64::from(f0) * i64::from(f0);
        let f0f1_2 = i64::from(f0_2) * i64::from(f1);
        let f0f2_2 = i64::from(f0_2) * i64::from(f2);
        let f0f3_2 = i64::from(f0_2) * i64::from(f3);
        let f0f4_2 = i64::from(f0_2) * i64::from(f4);
        let f0f5_2 = i64::from(f0_2) * i64::from(f5);
        let f0f6_2 = i64::from(f0_2) * i64::from(f6);
        let f0f7_2 = i64::from(f0_2) * i64::from(f7);
        let f0f8_2 = i64::from(f0_2) * i64::from(f8);
        let f0f9_2 = i64::from(f0_2) * i64::from(f9);
        let f1f1_2 = i64::from(f1_2) * i64::from(f1);
        let f1f2_2 = i64::from(f1_2) * i64::from(f2);
        let f1f3_4 = i64::from(f1_2) * i64::from(f3_2);
        let f1f4_2 = i64::from(f1_2) * i64::from(f4);
        let f1f5_4 = i64::from(f1_2) * i64::from(f5_2);
        let f1f6_2 = i64::from(f1_2) * i64::from(f6);
        let f1f7_4 = i64::from(f1_2) * i64::from(f7_2);
        let f1f8_2 = i64::from(f1_2) * i64::from(f8);
        let f1f9_76 = i64::from(f1_2) * i64::from(f9_38);
        let f2f2 = i64::from(f2) * i64::from(f2);
        let f2f3_2 = i64::from(f2_2) * i64::from(f3);
        let f2f4_2 = i64::from(f2_2) * i64::from(f4);
        let f2f5_2 = i64::from(f2_2) * i64::from(f5);
        let f2f6_2 = i64::from(f2_2) * i64::from(f6);
        let f2f7_2 = i64::from(f2_2) * i64::from(f7);
        let f2f8_38 = i64::from(f2_2) * i64::from(f8_19);
        let f2f9_38 = i64::from(f2) * i64::from(f9_38);
        let f3f3_2 = i64::from(f3_2) * i64::from(f3);
        let f3f4_2 = i64::from(f3_2) * i64::from(f4);
        let f3f5_4 = i64::from(f3_2) * i64::from(f5_2);
        let f3f6_2 = i64::from(f3_2) * i64::from(f6);
        let f3f7_76 = i64::from(f3_2) * i64::from(f7_38);
        let f3f8_38 = i64::from(f3_2) * i64::from(f8_19);
        let f3f9_76 = i64::from(f3_2) * i64::from(f9_38);
        let f4f4 = i64::from(f4) * i64::from(f4);
        let f4f5_2 = i64::from(f4_2) * i64::from(f5);
        let f4f6_38 = i64::from(f4_2) * i64::from(f6_19);
        let f4f7_38 = i64::from(f4) * i64::from(f7_38);
        let f4f8_38 = i64::from(f4_2) * i64::from(f8_19);
        let f4f9_38 = i64::from(f4) * i64::from(f9_38);
        let f5f5_38 = i64::from(f5) * i64::from(f5_38);
        let f5f6_38 = i64::from(f5_2) * i64::from(f6_19);
        let f5f7_76 = i64::from(f5_2) * i64::from(f7_38);
        let f5f8_38 = i64::from(f5_2) * i64::from(f8_19);
        let f5f9_76 = i64::from(f5_2) * i64::from(f9_38);
        let f6f6_19 = i64::from(f6) * i64::from(f6_19);
        let f6f7_38 = i64::from(f6) * i64::from(f7_38);
        let f6f8_38 = i64::from(f6_2) * i64::from(f8_19);
        let f6f9_38 = i64::from(f6) * i64::from(f9_38);
        let f7f7_38 = i64::from(f7) * i64::from(f7_38);
        let f7f8_38 = i64::from(f7_2) * i64::from(f8_19);
        let f7f9_76 = i64::from(f7_2) * i64::from(f9_38);
        let f8f8_19 = i64::from(f8) * i64::from(f8_19);
        let f8f9_38 = i64::from(f8) * i64::from(f9_38);
        let f9f9_38 = i64::from(f9) * i64::from(f9_38);
        let mut h0 = f0f0 + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38;
        let mut h1 = f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38;
        let mut h2 = f0f2_2 + f1f1_2 + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19;
        let mut h3 = f0f3_2 + f1f2_2 + f4f9_38 + f5f8_38 + f6f7_38;
        let mut h4 = f0f4_2 + f1f3_4 + f2f2 + f5f9_76 + f6f8_38 + f7f7_38;
        let mut h5 = f0f5_2 + f1f4_2 + f2f3_2 + f6f9_38 + f7f8_38;
        let mut h6 = f0f6_2 + f1f5_4 + f2f4_2 + f3f3_2 + f7f9_76 + f8f8_19;
        let mut h7 = f0f7_2 + f1f6_2 + f2f5_2 + f3f4_2 + f8f9_38;
        let mut h8 = f0f8_2 + f1f7_4 + f2f6_2 + f3f5_4 + f4f4 + f9f9_38;
        let mut h9 = f0f9_2 + f1f8_2 + f2f7_2 + f3f6_2 + f4f5_2;
        let mut carry0;
        let carry1;
        let carry2;
        let carry3;
        let mut carry4;
        let carry5;
        let carry6;
        let carry7;
        let carry8;
        let carry9;

        carry0 = (h0 + (1 << 25)) >> 26;
        h1 += carry0;
        h0 -= carry0 << 26;
        carry4 = (h4 + (1 << 25)) >> 26;
        h5 += carry4;
        h4 -= carry4 << 26;

        carry1 = (h1 + (1 << 24)) >> 25;
        h2 += carry1;
        h1 -= carry1 << 25;
        carry5 = (h5 + (1 << 24)) >> 25;
        h6 += carry5;
        h5 -= carry5 << 25;

        carry2 = (h2 + (1 << 25)) >> 26;
        h3 += carry2;
        h2 -= carry2 << 26;
        carry6 = (h6 + (1 << 25)) >> 26;
        h7 += carry6;
        h6 -= carry6 << 26;

        carry3 = (h3 + (1 << 24)) >> 25;
        h4 += carry3;
        h3 -= carry3 << 25;
        carry7 = (h7 + (1 << 24)) >> 25;
        h8 += carry7;
        h7 -= carry7 << 25;

        carry4 = (h4 + (1 << 25)) >> 26;
        h5 += carry4;
        h4 -= carry4 << 26;
        carry8 = (h8 + (1 << 25)) >> 26;
        h9 += carry8;
        h8 -= carry8 << 26;

        carry9 = (h9 + (1 << 24)) >> 25;
        h0 += carry9 * 19;
        h9 -= carry9 << 25;

        carry0 = (h0 + (1 << 25)) >> 26;
        h1 += carry0;
        h0 -= carry0 << 26;

        $h[0] = h0 as i32;
        $h[1] = h1 as i32;
        $h[2] = h2 as i32;
        $h[3] = h3 as i32;
        $h[4] = h4 as i32;
        $h[5] = h5 as i32;
        $h[6] = h6 as i32;
        $h[7] = h7 as i32;
        $h[8] = h8 as i32;
        $h[9] = h9 as i32;
    };
}

fn scalarmult(q: &mut [u8; 32], n: &[u8], p: &[u8]) {
    assert_eq!(32, n.len());
    assert_eq!(32, p.len());
    let mut e = [0; 32];
    let x1 = &mut Fe::default();
    let mut x2 = &mut Fe::default();
    let mut z2 = &mut Fe::default();
    let x3 = &mut Fe::default();
    let z3 = &mut Fe::default();
    let mut tmp0 = &mut Fe::default();
    let mut tmp1 = &mut Fe::default();
    let mut swap;
    let mut b;

    e.copy_from_slice(n);
    e[0] &= 248;
    e[31] &= 127;
    e[31] |= 64;
    x1.assign_from_bytes(p);
    x2.assign_one();
    z2.assign_zero();
    *x3 = *x1;
    z3.assign_one();

    swap = 0;
    for pos in (0..255).rev() {
        b = u32::from(e[pos / 8] >> (pos & 7));
        b &= 1;
        swap ^= b;
        x2.cswap_with(x3, swap);
        z2.cswap_with(z3, swap);
        swap = b;

        tmp0.assign_difference(x3, z3);

        tmp1.assign_difference(x2, z2);

        x2 += z2;

        z2.assign_sum(x3, z3);

        z3.assign_product(tmp0, x2);

        z2 *= tmp1;

        tmp0.assign_square(tmp1);

        tmp1.assign_square(x2);

        x3.assign_sum(z3, z2);

        z2.subtract_from(z3);

        x2.assign_product(tmp1, tmp0);

        tmp1 -= tmp0;

        z2.square();

        z3.mul121666(tmp1);

        x3.square();

        tmp0 += z3;

        z3.assign_product(x1, z2);

        z2.assign_product(tmp1, tmp0);
    }
    x2.cswap_with(x3, swap);
    z2.cswap_with(z3, swap);

    z2.invert();
    x2 *= z2;
    x2.write_bytes(q);
}

impl From<[i32; 10]> for Fe {
    fn from(x: [i32; 10]) -> Self {
        Self(x)
    }
}

impl Fe {
    pub(crate) fn assign_zero(&mut self) {
        for l in &mut self.0 {
            *l = 0;
        }
    }

    pub(crate) fn assign_one(&mut self) {
        let h = &mut self.0;
        h[0] = 1;
        for l in h.iter_mut().skip(1) {
            *l = 0;
        }
    }

    pub(crate) fn assign_sum(&mut self, f: &Fe, g: &Fe) {
        for (l, (x, y)) in self.0.iter_mut().zip(f.0.iter().zip(&g.0)) {
            *l = x + y;
        }
    }

    fn cswap_with(&mut self, g: &mut Fe, b: u32) {
        let f = &mut self.0;
        let g = &mut g.0;
        let f0 = f[0];
        let f1 = f[1];
        let f2 = f[2];
        let f3 = f[3];
        let f4 = f[4];
        let f5 = f[5];
        let f6 = f[6];
        let f7 = f[7];
        let f8 = f[8];
        let f9 = f[9];
        let g0 = g[0];
        let g1 = g[1];
        let g2 = g[2];
        let g3 = g[3];
        let g4 = g[4];
        let g5 = g[5];
        let g6 = g[6];
        let g7 = g[7];
        let g8 = g[8];
        let g9 = g[9];
        let mut x0 = f0 ^ g0;
        let mut x1 = f1 ^ g1;
        let mut x2 = f2 ^ g2;
        let mut x3 = f3 ^ g3;
        let mut x4 = f4 ^ g4;
        let mut x5 = f5 ^ g5;
        let mut x6 = f6 ^ g6;
        let mut x7 = f7 ^ g7;
        let mut x8 = f8 ^ g8;
        let mut x9 = f9 ^ g9;
        let b = b.wrapping_neg() as i32;
        x0 &= b;
        x1 &= b;
        x2 &= b;
        x3 &= b;
        x4 &= b;
        x5 &= b;
        x6 &= b;
        x7 &= b;
        x8 &= b;
        x9 &= b;
        f[0] = f0 ^ x0;
        f[1] = f1 ^ x1;
        f[2] = f2 ^ x2;
        f[3] = f3 ^ x3;
        f[4] = f4 ^ x4;
        f[5] = f5 ^ x5;
        f[6] = f6 ^ x6;
        f[7] = f7 ^ x7;
        f[8] = f8 ^ x8;
        f[9] = f9 ^ x9;
        g[0] = g0 ^ x0;
        g[1] = g1 ^ x1;
        g[2] = g2 ^ x2;
        g[3] = g3 ^ x3;
        g[4] = g4 ^ x4;
        g[5] = g5 ^ x5;
        g[6] = g6 ^ x6;
        g[7] = g7 ^ x7;
        g[8] = g8 ^ x8;
        g[9] = g9 ^ x9;
    }

    pub(crate) fn assign_from_bytes(&mut self, s: &[u8]) {
        let h = &mut self.0;
        let mut h0 = load_4(s) as i64;
        let mut h1 = (load_3(&s[4..]) << 6) as i64;
        let mut h2 = (load_3(&s[7..]) << 5) as i64;
        let mut h3 = (load_3(&s[10..]) << 3) as i64;
        let mut h4 = (load_3(&s[13..]) << 2) as i64;
        let mut h5 = load_4(&s[16..]) as i64;
        let mut h6 = (load_3(&s[20..]) << 7) as i64;
        let mut h7 = (load_3(&s[23..]) << 5) as i64;
        let mut h8 = (load_3(&s[26..]) << 4) as i64;
        let mut h9 = ((load_3(&s[29..]) & 8388607) << 2) as i64;

        let carry9 = (h9 + (1 << 24)) >> 25;
        h0 += carry9 * 19;
        h9 -= carry9 << 25;
        let carry1 = (h1 + (1 << 24)) >> 25;
        h2 += carry1;
        h1 -= carry1 << 25;
        let carry3 = (h3 + (1 << 24)) >> 25;
        h4 += carry3;
        h3 -= carry3 << 25;
        let carry5 = (h5 + (1 << 24)) >> 25;
        h6 += carry5;
        h5 -= carry5 << 25;
        let carry7 = (h7 + (1 << 24)) >> 25;
        h8 += carry7;
        h7 -= carry7 << 25;

        let carry0 = (h0 + (1 << 25)) >> 26;
        h1 += carry0;
        h0 -= carry0 << 26;
        let carry2 = (h2 + (1 << 25)) >> 26;
        h3 += carry2;
        h2 -= carry2 << 26;
        let carry4 = (h4 + (1 << 25)) >> 26;
        h5 += carry4;
        h4 -= carry4 << 26;
        let carry6 = (h6 + (1 << 25)) >> 26;
        h7 += carry6;
        h6 -= carry6 << 26;
        let carry8 = (h8 + (1 << 25)) >> 26;
        h9 += carry8;
        h8 -= carry8 << 26;

        h[0] = h0 as i32;
        h[1] = h1 as i32;
        h[2] = h2 as i32;
        h[3] = h3 as i32;
        h[4] = h4 as i32;
        h[5] = h5 as i32;
        h[6] = h6 as i32;
        h[7] = h7 as i32;
        h[8] = h8 as i32;
        h[9] = h9 as i32;
    }

    pub(crate) fn inverse(&self) -> Self {
        let mut inv = Self::default();
        fe_invert!(&mut inv, self);
        inv
    }

    fn invert(&mut self) {
        fe_invert!(self, self);
    }

    pub(crate) fn assign_product(&mut self, f: &Fe, g: &Fe) {
        fe_mul!(&mut self.0, f.0, g.0);
    }

    fn mul121666(&mut self, f: &Fe) {
        let h = &mut self.0;
        let f = f.0;
        let f0 = f[0];
        let f1 = f[1];
        let f2 = f[2];
        let f3 = f[3];
        let f4 = f[4];
        let f5 = f[5];
        let f6 = f[6];
        let f7 = f[7];
        let f8 = f[8];
        let f9 = f[9];
        let mut h0 = i64::from(f0) * 121666;
        let mut h1 = i64::from(f1) * 121666;
        let mut h2 = i64::from(f2) * 121666;
        let mut h3 = i64::from(f3) * 121666;
        let mut h4 = i64::from(f4) * 121666;
        let mut h5 = i64::from(f5) * 121666;
        let mut h6 = i64::from(f6) * 121666;
        let mut h7 = i64::from(f7) * 121666;
        let mut h8 = i64::from(f8) * 121666;
        let mut h9 = i64::from(f9) * 121666;

        let carry9 = (h9 + (1 << 24)) >> 25;
        h0 += carry9 * 19;
        h9 -= carry9 << 25;
        let carry1 = (h1 + (1 << 24)) >> 25;
        h2 += carry1;
        h1 -= carry1 << 25;
        let carry3 = (h3 + (1 << 24)) >> 25;
        h4 += carry3;
        h3 -= carry3 << 25;
        let carry5 = (h5 + (1 << 24)) >> 25;
        h6 += carry5;
        h5 -= carry5 << 25;
        let carry7 = (h7 + (1 << 24)) >> 25;
        h8 += carry7;
        h7 -= carry7 << 25;

        let carry0 = (h0 + (1 << 25)) >> 26;
        h1 += carry0;
        h0 -= carry0 << 26;
        let carry2 = (h2 + (1 << 25)) >> 26;
        h3 += carry2;
        h2 -= carry2 << 26;
        let carry4 = (h4 + (1 << 25)) >> 26;
        h5 += carry4;
        h4 -= carry4 << 26;
        let carry6 = (h6 + (1 << 25)) >> 26;
        h7 += carry6;
        h6 -= carry6 << 26;
        let carry8 = (h8 + (1 << 25)) >> 26;
        h9 += carry8;
        h8 -= carry8 << 26;

        h[0] = h0 as i32;
        h[1] = h1 as i32;
        h[2] = h2 as i32;
        h[3] = h3 as i32;
        h[4] = h4 as i32;
        h[5] = h5 as i32;
        h[6] = h6 as i32;
        h[7] = h7 as i32;
        h[8] = h8 as i32;
        h[9] = h9 as i32;
    }

    pub(crate) fn pow22523(&mut self) {
        let mut t0 = &mut Fe::default();
        let mut t1 = &mut Fe::default();
        let t2 = &mut Fe::default();

        t0.assign_square(self);

        t1.assign_square(t0);
        t1.square();
        t1 *= self;

        t0 *= t1;
        t0.square();
        t0 *= t1;

        t1.assign_square(t0);
        square_many!(t1, 5);

        t0 *= t1;

        t1.assign_square(t0);
        square_many!(t1, 10);
        t1 *= t0;

        t2.assign_square(t1);
        square_many!(t2, 20);

        t1 *= t2;
        square_many!(t1, 11);

        t0 *= t1;

        t1.assign_square(t0);
        square_many!(t1, 50);
        t1 *= t0;

        t2.assign_square(t1);
        square_many!(t2, 100);

        t1 *= t2;
        square_many!(t1, 51);

        t0 *= t1;
        t0.square();
        t0.square();
        *self *= t0;
    }

    pub(crate) fn assign_square(&mut self, f: &Fe) {
        fe_sq!(&mut self.0, f.0);
    }

    fn square(&mut self) {
        fe_sq!(&mut self.0, self.0);
    }

    pub(crate) fn assign_difference(&mut self, f: &Fe, g: &Fe) {
        for (l, (x, y)) in self.0.iter_mut().zip(f.0.iter().zip(&g.0)) {
            *l = x - y;
        }
    }

    pub(crate) fn subtract_from(&mut self, f: &Fe) {
        for (l, r) in self.0.iter_mut().zip(&f.0) {
            *l = r - *l;
        }
    }

    pub(crate) fn write_bytes(&self, s: &mut [u8]) {
        assert_eq!(32, s.len());
        let h = self.0;
        let mut h0 = h[0];
        let mut h1 = h[1];
        let mut h2 = h[2];
        let mut h3 = h[3];
        let mut h4 = h[4];
        let mut h5 = h[5];
        let mut h6 = h[6];
        let mut h7 = h[7];
        let mut h8 = h[8];
        let mut h9 = h[9];

        let mut q = (19 * h9 + (1 << 24)) >> 25;
        q = (h0 + q) >> 26;
        q = (h1 + q) >> 25;
        q = (h2 + q) >> 26;
        q = (h3 + q) >> 25;
        q = (h4 + q) >> 26;
        q = (h5 + q) >> 25;
        q = (h6 + q) >> 26;
        q = (h7 + q) >> 25;
        q = (h8 + q) >> 26;
        q = (h9 + q) >> 25;

        h0 += 19 * q;

        let carry0 = h0 >> 26;
        h1 += carry0;
        h0 -= carry0 << 26;
        let carry1 = h1 >> 25;
        h2 += carry1;
        h1 -= carry1 << 25;
        let carry2 = h2 >> 26;
        h3 += carry2;
        h2 -= carry2 << 26;
        let carry3 = h3 >> 25;
        h4 += carry3;
        h3 -= carry3 << 25;
        let carry4 = h4 >> 26;
        h5 += carry4;
        h4 -= carry4 << 26;
        let carry5 = h5 >> 25;
        h6 += carry5;
        h5 -= carry5 << 25;
        let carry6 = h6 >> 26;
        h7 += carry6;
        h6 -= carry6 << 26;
        let carry7 = h7 >> 25;
        h8 += carry7;
        h7 -= carry7 << 25;
        let carry8 = h8 >> 26;
        h9 += carry8;
        h8 -= carry8 << 26;
        let carry9 = h9 >> 25;
        h9 -= carry9 << 25;

        s[0] = h0 as u8;
        s[1] = (h0 >> 8) as u8;
        s[2] = (h0 >> 16) as u8;
        s[3] = ((h0 >> 24) | (h1 << 2)) as u8;
        s[4] = (h1 >> 6) as u8;
        s[5] = (h1 >> 14) as u8;
        s[6] = ((h1 >> 22) | (h2 << 3)) as u8;
        s[7] = (h2 >> 5) as u8;
        s[8] = (h2 >> 13) as u8;
        s[9] = ((h2 >> 21) | (h3 << 5)) as u8;
        s[10] = (h3 >> 3) as u8;
        s[11] = (h3 >> 11) as u8;
        s[12] = ((h3 >> 19) | (h4 << 6)) as u8;
        s[13] = (h4 >> 2) as u8;
        s[14] = (h4 >> 10) as u8;
        s[15] = (h4 >> 18) as u8;
        s[16] = h5 as u8;
        s[17] = (h5 >> 8) as u8;
        s[18] = (h5 >> 16) as u8;
        s[19] = ((h5 >> 24) | (h6 << 1)) as u8;
        s[20] = (h6 >> 7) as u8;
        s[21] = (h6 >> 15) as u8;
        s[22] = ((h6 >> 23) | (h7 << 3)) as u8;
        s[23] = (h7 >> 5) as u8;
        s[24] = (h7 >> 13) as u8;
        s[25] = ((h7 >> 21) | (h8 << 4)) as u8;
        s[26] = (h8 >> 4) as u8;
        s[27] = (h8 >> 12) as u8;
        s[28] = ((h8 >> 20) | (h9 << 6)) as u8;
        s[29] = (h9 >> 2) as u8;
        s[30] = (h9 >> 10) as u8;
        s[31] = (h9 >> 18) as u8;
    }
}

impl<'a> AddAssign<&'a Fe> for Fe {
    fn add_assign(&mut self, rhs: &'a Fe) {
        for (l, r) in self.0.iter_mut().zip(&rhs.0) {
            *l += r;
        }
    }
}

impl<'a, 'b> AddAssign<&'a Fe> for &'b mut Fe {
    fn add_assign(&mut self, rhs: &'a Fe) {
        for (l, r) in self.0.iter_mut().zip(&rhs.0) {
            *l += r;
        }
    }
}

impl<'a> MulAssign<&'a Fe> for Fe {
    fn mul_assign(&mut self, rhs: &'a Fe) {
        fe_mul!(&mut self.0, self.0, rhs.0);
    }
}

impl<'a, 'b> MulAssign<&'a Fe> for &'b mut Fe {
    fn mul_assign(&mut self, rhs: &'a Fe) {
        fe_mul!(&mut self.0, self.0, rhs.0);
    }
}

impl<'a> SubAssign<&'a Fe> for Fe {
    fn sub_assign(&mut self, rhs: &'a Fe) {
        for (l, r) in self.0.iter_mut().zip(&rhs.0) {
            *l -= r;
        }
    }
}

impl<'a, 'b> SubAssign<&'a Fe> for &'b mut Fe {
    fn sub_assign(&mut self, rhs: &'a Fe) {
        for (l, r) in self.0.iter_mut().zip(&rhs.0) {
            *l -= r;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::*;

    fn check(x: &str, k: &str, u: &str) {
        let s = &mut [0; 32];
        scalarmult(s, &h2b(k), &h2b(u));
        assert_eq!(&h2b(x), s);
    }

    /*
    fn check_decode(k: &str, u: &str, k10: &str, u10: &str) {
        assert_eq!(
            Field::new(BigUint::parse_bytes(k10.as_bytes(), 10).unwrap()),
            decode_scalar(&h2b(k))
        );
        assert_eq!(
            Field::new(BigUint::parse_bytes(u10.as_bytes(), 10).unwrap()),
            decode_u_coordinate(&h2b(u))
        );
    }
    */

    #[test]
    fn test_x25519() {
        let k = "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4";
        let u = "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c";
        let x = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552";
        check(x, k, u);

        /*
        let k10 = "31029842492115040904895560451863089656472772604678260265531221036453811406496";
        let u10 = "34426434033919594451155107781188821651316167215306631574996226621102155684838";
        check_decode(k, u, k10, u10);
        */

        let k = "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d";
        let u = "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493";
        let x = "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957";
        check(x, k, u);

        /*
        let k10 = "35156891815674817266734212754503633747128614016119564763269015315466259359304";
        let u10 = "8883857351183929894090759386610649319417338800022198945255395922347792736741";
        check_decode(k, u, k10, u10);
        */

        let k = &mut [0; 32];
        k.copy_from_slice(&h2b(
            "0900000000000000000000000000000000000000000000000000000000000000",
        ));
        let u = &mut k.clone();
        let x = &mut [0; 32];
        // slow to do 1 mil iterations, or 1000 without --release
        for i in 0..1 {
            scalarmult(x, k, u);
            if i == 0 {
                assert_eq!(
                    &h2b("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"),
                    x
                );
            } else if i == 999 {
                assert_eq!(
                    &h2b("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"),
                    x
                );
            } else if i == 999999 {
                assert_eq!(
                    &h2b("7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424"),
                    x
                );
            }
            u.copy_from_slice(k);
            k.copy_from_slice(x);
        }
    }

    #[test]
    fn test_gen_pk() {
        let sk_a = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
        let pk_a = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
        let sk_b = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
        let pk_b = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
        let k = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
        assert_eq!(h2b(pk_a), gen_pk(&h2b(sk_a)));
        assert_eq!(h2b(pk_b), gen_pk(&h2b(sk_b)));
        check(k, sk_a, pk_b);
        check(k, sk_b, pk_a);
    }
}
