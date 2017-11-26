// Translated to Rust from the public domain SUPERCOP `ref10` implementation (Daniel J. Bernstein)
use core::ops::{AddAssign, MulAssign, SubAssign};
use const_curve25519::{BASE, BI, D, D2, SQRTM1};
use sha2::{sha512, HashFunction, Sha512};

const ZERO: [u8; 32] = [0; 32];

/// Computes a public key for use in curve25519 Diffie-Hellman key exchange.
///
/// After geting a shared secret, make sure to abort if it's 0.
///
/// # Panics
///
/// Panics if `sk.len()` is not equal to 32.
pub fn gen_pk(sk: &[u8]) -> [u8; 32] {
    let mut pk = [0; 32];
    let mut basepoint = [0; 32];
    basepoint[0] = 9;
    scalarmult(&mut pk, sk, &basepoint);
    pk
}

/// Computes a curve25519 Diffie-Hellman shared secret given a secret key and another's public key.
///
/// # Panics
///
/// Panics if `pk.len()` or `sk.len()` is not equal to 32.
pub fn dh(pk: &[u8], sk: &[u8]) -> [u8; 32] {
    let mut secret = [0; 32];
    scalarmult(&mut secret, sk, pk);
    secret
}

pub fn gen_sign_pk(sk: &[u8]) -> [u8; 32] {
    assert_eq!(32, sk.len());
    let mut pk = [0; 32];
    let az = &mut sha512(sk);
    let a = &mut GeP3::default();
    az[0] &= 248;
    az[31] &= 63;
    az[31] |= 64;

    ge_scalarmult_base(a, az);
    ge_p3_tobytes(&mut pk, a);
    pk
}

pub fn sign(m: &[u8], sk: &[u8], pk: &[u8]) -> [u8; 64] {
    assert_eq!(32, sk.len());
    assert_eq!(32, pk.len());
    let r = &mut GeP3::default();

    let mut az = sha512(sk);
    az[0] &= 248;
    az[31] &= 63;
    az[31] |= 64;

    let nonce = &mut [0; Sha512::DIGEST_SIZE];
    let mut hash_function = Sha512::default();
    hash_function.update(&az[32..]);
    hash_function.update(m);
    hash_function.write_digest(nonce);
    sc_reduce(nonce);
    ge_scalarmult_base(r, nonce);

    let mut signature = [0; 64];
    signature[32..].copy_from_slice(pk);
    ge_p3_tobytes(&mut signature[..32], r);

    let hram = &mut [0; Sha512::DIGEST_SIZE];
    hash_function = Sha512::default();
    hash_function.update(&signature);
    hash_function.update(m);
    hash_function.write_digest(hram);
    sc_reduce(hram);

    sc_muladd(&mut signature[32..], hram, &az, nonce);
    signature
}

pub fn verify(message: &[u8], signature: &[u8], pk: &[u8]) -> bool {
    assert_eq!(32, pk.len());
    if signature.len() != 64 || (signature[63] & 224 != 0) {
        return false;
    }
    let a = match GeP3::from_bytes_negate_vartime(pk) {
        Some(g) => g,
        None => return false,
    };

    let rcopy = &signature[..32];
    let scopy = &signature[32..];
    let h = &mut [0; Sha512::DIGEST_SIZE];

    let mut hash_function = Sha512::default();
    hash_function.update(rcopy);
    hash_function.update(pk);
    hash_function.update(message);
    hash_function.write_digest(h);
    sc_reduce(h);

    let r = GeP2::from_double_scalarmult_vartime(h, &a, scopy);
    let rcheck = r.to_bytes();
    verify_32(&rcheck, rcopy) == 0
}

#[inline(never)]
fn verify_32(x: &[u8; 32], y: &[u8]) -> i32 {
    let differentbits = x.iter().zip(y).fold(
        0,
        |acc, (x, y)| acc | i32::from(x ^ y),
    );
    (1 & ((differentbits - 1) >> 8)) - 1
}

macro_rules! square_many { ($f:expr, $i:expr) => (
    for _ in 1..$i {
        $f.square();
    }
)}

macro_rules! fe_invert { ($out:expr, $z:expr) => (
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
)}

macro_rules! fe_mul { ($h:expr, $f:expr, $g:expr) => (
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
    let f1g1_2 = i64::from(i64::from(f1_2)) * i64::from(g1);
    let f1g2 = i64::from(f1) * i64::from(g2);
    let f1g3_2 = i64::from(i64::from(f1_2)) * i64::from(g3);
    let f1g4 = i64::from(f1) * i64::from(g4);
    let f1g5_2 = i64::from(i64::from(f1_2)) * i64::from(g5);
    let f1g6 = i64::from(f1) * i64::from(g6);
    let f1g7_2 = i64::from(i64::from(f1_2)) * i64::from(g7);
    let f1g8 = i64::from(f1) * i64::from(g8);
    let f1g9_38 = i64::from(i64::from(f1_2)) * i64::from(g9_19);
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
    let f3g1_2 = i64::from(i64::from(f3_2)) * i64::from(g1);
    let f3g2 = i64::from(f3) * i64::from(g2);
    let f3g3_2 = i64::from(i64::from(f3_2)) * i64::from(g3);
    let f3g4 = i64::from(f3) * i64::from(g4);
    let f3g5_2 = i64::from(i64::from(f3_2)) * i64::from(g5);
    let f3g6 = i64::from(f3) * i64::from(g6);
    let f3g7_38 = i64::from(i64::from(f3_2)) * i64::from(g7_19);
    let f3g8_19 = i64::from(f3) * i64::from(g8_19);
    let f3g9_38 = i64::from(i64::from(f3_2)) * i64::from(g9_19);
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
    let f5g1_2 = i64::from(i64::from(f5_2)) * i64::from(g1);
    let f5g2 = i64::from(f5) * i64::from(g2);
    let f5g3_2 = i64::from(i64::from(f5_2)) * i64::from(g3);
    let f5g4 = i64::from(f5) * i64::from(g4);
    let f5g5_38 = i64::from(i64::from(f5_2)) * i64::from(g5_19);
    let f5g6_19 = i64::from(f5) * i64::from(g6_19);
    let f5g7_38 = i64::from(i64::from(f5_2)) * i64::from(g7_19);
    let f5g8_19 = i64::from(f5) * i64::from(g8_19);
    let f5g9_38 = i64::from(i64::from(f5_2)) * i64::from(g9_19);
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
    let f7g1_2 = i64::from(i64::from(f7_2)) * i64::from(g1);
    let f7g2 = i64::from(f7) * i64::from(g2);
    let f7g3_38 = i64::from(i64::from(f7_2)) * i64::from(g3_19);
    let f7g4_19 = i64::from(f7) * i64::from(g4_19);
    let f7g5_38 = i64::from(i64::from(f7_2)) * i64::from(g5_19);
    let f7g6_19 = i64::from(f7) * i64::from(g6_19);
    let f7g7_38 = i64::from(i64::from(f7_2)) * i64::from(g7_19);
    let f7g8_19 = i64::from(f7) * i64::from(g8_19);
    let f7g9_38 = i64::from(i64::from(f7_2)) * i64::from(g9_19);
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
    let f9g1_38 = i64::from(i64::from(f9_2)) * i64::from(g1_19);
    let f9g2_19 = i64::from(f9) * i64::from(g2_19);
    let f9g3_38 = i64::from(i64::from(f9_2)) * i64::from(g3_19);
    let f9g4_19 = i64::from(f9) * i64::from(g4_19);
    let f9g5_38 = i64::from(i64::from(f9_2)) * i64::from(g5_19);
    let f9g6_19 = i64::from(f9) * i64::from(g6_19);
    let f9g7_38 = i64::from(i64::from(f9_2)) * i64::from(g7_19);
    let f9g8_19 = i64::from(f9) * i64::from(g8_19);
    let f9g9_38 = i64::from(i64::from(f9_2)) * i64::from(g9_19);
    let mut h0 = f0g0 + f1g9_38 + f2g8_19 + f3g7_38 + f4g6_19 + f5g5_38 + f6g4_19 +
        f7g3_38 + f8g2_19 + f9g1_38;
    let mut h1 = f0g1 + f1g0 + f2g9_19 + f3g8_19 + f4g7_19 + f5g6_19 + f6g5_19 + f7g4_19 +
        f8g3_19 + f9g2_19;
    let mut h2 = f0g2 + f1g1_2 + f2g0 + f3g9_38 + f4g8_19 + f5g7_38 + f6g6_19 + f7g5_38 +
        f8g4_19 + f9g3_38;
    let mut h3 = f0g3 + f1g2 + f2g1 + f3g0 + f4g9_19 + f5g8_19 + f6g7_19 + f7g6_19 + f8g5_19 +
        f9g4_19;
    let mut h4 = f0g4 + f1g3_2 + f2g2 + f3g1_2 + f4g0 + f5g9_38 + f6g8_19 + f7g7_38 +
        f8g6_19 + f9g5_38;
    let mut h5 = f0g5 + f1g4 + f2g3 + f3g2 + f4g1 + f5g0 + f6g9_19 + f7g8_19 + f8g7_19 +
        f9g6_19;
    let mut h6 = f0g6 + f1g5_2 + f2g4 + f3g3_2 + f4g2 + f5g1_2 + f6g0 + f7g9_38 + f8g8_19 +
        f9g7_38;
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
)}

macro_rules! fe_sq { ($h:expr, $f:expr) => (
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
)}

fn sc_muladd(s: &mut [u8], a: &[u8; 64], b: &[u8; 64], c: &[u8; 64]) {
    assert_eq!(32, s.len());
    let a0 = 2097151 & load_3(a) as i64;
    let a1 = 2097151 & (load_4(&a[2..]) >> 5) as i64;
    let a2 = 2097151 & (load_3(&a[5..]) >> 2) as i64;
    let a3 = 2097151 & (load_4(&a[7..]) >> 7) as i64;
    let a4 = 2097151 & (load_4(&a[10..]) >> 4) as i64;
    let a5 = 2097151 & (load_3(&a[13..]) >> 1) as i64;
    let a6 = 2097151 & (load_4(&a[15..]) >> 6) as i64;
    let a7 = 2097151 & (load_3(&a[18..]) >> 3) as i64;
    let a8 = 2097151 & load_3(&a[21..]) as i64;
    let a9 = 2097151 & (load_4(&a[23..]) >> 5) as i64;
    let a10 = 2097151 & (load_3(&a[26..]) >> 2) as i64;
    let a11 = (load_4(&a[28..]) >> 7) as i64;
    let b0 = 2097151 & load_3(b) as i64;
    let b1 = 2097151 & (load_4(&b[2..]) >> 5) as i64;
    let b2 = 2097151 & (load_3(&b[5..]) >> 2) as i64;
    let b3 = 2097151 & (load_4(&b[7..]) >> 7) as i64;
    let b4 = 2097151 & (load_4(&b[10..]) >> 4) as i64;
    let b5 = 2097151 & (load_3(&b[13..]) >> 1) as i64;
    let b6 = 2097151 & (load_4(&b[15..]) >> 6) as i64;
    let b7 = 2097151 & (load_3(&b[18..]) >> 3) as i64;
    let b8 = 2097151 & load_3(&b[21..]) as i64;
    let b9 = 2097151 & (load_4(&b[23..]) >> 5) as i64;
    let b10 = 2097151 & (load_3(&b[26..]) >> 2) as i64;
    let b11 = (load_4(&b[28..]) >> 7) as i64;
    let c0 = 2097151 & load_3(c) as i64;
    let c1 = 2097151 & (load_4(&c[2..]) >> 5) as i64;
    let c2 = 2097151 & (load_3(&c[5..]) >> 2) as i64;
    let c3 = 2097151 & (load_4(&c[7..]) >> 7) as i64;
    let c4 = 2097151 & (load_4(&c[10..]) >> 4) as i64;
    let c5 = 2097151 & (load_3(&c[13..]) >> 1) as i64;
    let c6 = 2097151 & (load_4(&c[15..]) >> 6) as i64;
    let c7 = 2097151 & (load_3(&c[18..]) >> 3) as i64;
    let c8 = 2097151 & load_3(&c[21..]) as i64;
    let c9 = 2097151 & (load_4(&c[23..]) >> 5) as i64;
    let c10 = 2097151 & (load_3(&c[26..]) >> 2) as i64;
    let c11 = (load_4(&c[28..]) >> 7) as i64;
    let mut s0;
    let mut s1;
    let mut s2;
    let mut s3;
    let mut s4;
    let mut s5;
    let mut s6;
    let mut s7;
    let mut s8;
    let mut s9;
    let mut s10;
    let mut s11;
    let mut s12;
    let mut s13;
    let mut s14;
    let mut s15;
    let mut s16;
    let mut s17;
    let mut s18;
    let mut s19;
    let mut s20;
    let mut s21;
    let mut s22;
    let mut s23;
    let mut carry0;
    let mut carry1;
    let mut carry2;
    let mut carry3;
    let mut carry4;
    let mut carry5;
    let mut carry6;
    let mut carry7;
    let mut carry8;
    let mut carry9;
    let mut carry10;
    let mut carry11;
    let mut carry12;
    let mut carry13;
    let mut carry14;
    let mut carry15;
    let mut carry16;
    let carry17;
    let carry18;
    let carry19;
    let carry20;
    let carry21;
    let carry22;

    s0 = c0 + a0 * b0;
    s1 = c1 + a0 * b1 + a1 * b0;
    s2 = c2 + a0 * b2 + a1 * b1 + a2 * b0;
    s3 = c3 + a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0;
    s4 = c4 + a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;
    s5 = c5 + a0 * b5 + a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1 + a5 * b0;
    s6 = c6 + a0 * b6 + a1 * b5 + a2 * b4 + a3 * b3 + a4 * b2 + a5 * b1 + a6 * b0;
    s7 = c7 + a0 * b7 + a1 * b6 + a2 * b5 + a3 * b4 + a4 * b3 + a5 * b2 + a6 * b1 + a7 * b0;
    s8 = c8 + a0 * b8 + a1 * b7 + a2 * b6 + a3 * b5 + a4 * b4 + a5 * b3 + a6 * b2 + a7 * b1 +
        a8 * b0;
    s9 = c9 + a0 * b9 + a1 * b8 + a2 * b7 + a3 * b6 + a4 * b5 + a5 * b4 + a6 * b3 + a7 * b2 +
        a8 * b1 + a9 * b0;
    s10 = c10 + a0 * b10 + a1 * b9 + a2 * b8 + a3 * b7 + a4 * b6 + a5 * b5 + a6 * b4 +
        a7 * b3 + a8 * b2 + a9 * b1 + a10 * b0;
    s11 = c11 + a0 * b11 + a1 * b10 + a2 * b9 + a3 * b8 + a4 * b7 + a5 * b6 +
        a6 * b5 + a7 * b4 + a8 * b3 + a9 * b2 + a10 * b1 + a11 * b0;
    s12 = a1 * b11 + a2 * b10 + a3 * b9 + a4 * b8 + a5 * b7 + a6 * b6 + a7 * b5 + a8 * b4 +
        a9 * b3 + a10 * b2 + a11 * b1;
    s13 = a2 * b11 + a3 * b10 + a4 * b9 + a5 * b8 + a6 * b7 + a7 * b6 + a8 * b5 + a9 * b4 +
        a10 * b3 + a11 * b2;
    s14 = a3 * b11 + a4 * b10 + a5 * b9 + a6 * b8 + a7 * b7 + a8 * b6 + a9 * b5 + a10 * b4 +
        a11 * b3;
    s15 = a4 * b11 + a5 * b10 + a6 * b9 + a7 * b8 + a8 * b7 + a9 * b6 + a10 * b5 + a11 * b4;
    s16 = a5 * b11 + a6 * b10 + a7 * b9 + a8 * b8 + a9 * b7 + a10 * b6 + a11 * b5;
    s17 = a6 * b11 + a7 * b10 + a8 * b9 + a9 * b8 + a10 * b7 + a11 * b6;
    s18 = a7 * b11 + a8 * b10 + a9 * b9 + a10 * b8 + a11 * b7;
    s19 = a8 * b11 + a9 * b10 + a10 * b9 + a11 * b8;
    s20 = a9 * b11 + a10 * b10 + a11 * b9;
    s21 = a10 * b11 + a11 * b10;
    s22 = a11 * b11;
    s23 = 0;

    carry0 = (s0 + (1 << 20)) >> 21;
    s1 += carry0;
    s0 -= carry0 << 21;
    carry2 = (s2 + (1 << 20)) >> 21;
    s3 += carry2;
    s2 -= carry2 << 21;
    carry4 = (s4 + (1 << 20)) >> 21;
    s5 += carry4;
    s4 -= carry4 << 21;
    carry6 = (s6 + (1 << 20)) >> 21;
    s7 += carry6;
    s6 -= carry6 << 21;
    carry8 = (s8 + (1 << 20)) >> 21;
    s9 += carry8;
    s8 -= carry8 << 21;
    carry10 = (s10 + (1 << 20)) >> 21;
    s11 += carry10;
    s10 -= carry10 << 21;
    carry12 = (s12 + (1 << 20)) >> 21;
    s13 += carry12;
    s12 -= carry12 << 21;
    carry14 = (s14 + (1 << 20)) >> 21;
    s15 += carry14;
    s14 -= carry14 << 21;
    carry16 = (s16 + (1 << 20)) >> 21;
    s17 += carry16;
    s16 -= carry16 << 21;
    carry18 = (s18 + (1 << 20)) >> 21;
    s19 += carry18;
    s18 -= carry18 << 21;
    carry20 = (s20 + (1 << 20)) >> 21;
    s21 += carry20;
    s20 -= carry20 << 21;
    carry22 = (s22 + (1 << 20)) >> 21;
    s23 += carry22;
    s22 -= carry22 << 21;

    carry1 = (s1 + (1 << 20)) >> 21;
    s2 += carry1;
    s1 -= carry1 << 21;
    carry3 = (s3 + (1 << 20)) >> 21;
    s4 += carry3;
    s3 -= carry3 << 21;
    carry5 = (s5 + (1 << 20)) >> 21;
    s6 += carry5;
    s5 -= carry5 << 21;
    carry7 = (s7 + (1 << 20)) >> 21;
    s8 += carry7;
    s7 -= carry7 << 21;
    carry9 = (s9 + (1 << 20)) >> 21;
    s10 += carry9;
    s9 -= carry9 << 21;
    carry11 = (s11 + (1 << 20)) >> 21;
    s12 += carry11;
    s11 -= carry11 << 21;
    carry13 = (s13 + (1 << 20)) >> 21;
    s14 += carry13;
    s13 -= carry13 << 21;
    carry15 = (s15 + (1 << 20)) >> 21;
    s16 += carry15;
    s15 -= carry15 << 21;
    carry17 = (s17 + (1 << 20)) >> 21;
    s18 += carry17;
    s17 -= carry17 << 21;
    carry19 = (s19 + (1 << 20)) >> 21;
    s20 += carry19;
    s19 -= carry19 << 21;
    carry21 = (s21 + (1 << 20)) >> 21;
    s22 += carry21;
    s21 -= carry21 << 21;

    s11 += s23 * 666643;
    s12 += s23 * 470296;
    s13 += s23 * 654183;
    s14 -= s23 * 997805;
    s15 += s23 * 136657;
    s16 -= s23 * 683901;
    // s23 = 0;

    s10 += s22 * 666643;
    s11 += s22 * 470296;
    s12 += s22 * 654183;
    s13 -= s22 * 997805;
    s14 += s22 * 136657;
    s15 -= s22 * 683901;
    // s22 = 0;

    s9 += s21 * 666643;
    s10 += s21 * 470296;
    s11 += s21 * 654183;
    s12 -= s21 * 997805;
    s13 += s21 * 136657;
    s14 -= s21 * 683901;
    // s21 = 0;

    s8 += s20 * 666643;
    s9 += s20 * 470296;
    s10 += s20 * 654183;
    s11 -= s20 * 997805;
    s12 += s20 * 136657;
    s13 -= s20 * 683901;
    // s20 = 0;

    s7 += s19 * 666643;
    s8 += s19 * 470296;
    s9 += s19 * 654183;
    s10 -= s19 * 997805;
    s11 += s19 * 136657;
    s12 -= s19 * 683901;
    // s19 = 0;

    s6 += s18 * 666643;
    s7 += s18 * 470296;
    s8 += s18 * 654183;
    s9 -= s18 * 997805;
    s10 += s18 * 136657;
    s11 -= s18 * 683901;
    // s18 = 0;

    carry6 = (s6 + (1 << 20)) >> 21;
    s7 += carry6;
    s6 -= carry6 << 21;
    carry8 = (s8 + (1 << 20)) >> 21;
    s9 += carry8;
    s8 -= carry8 << 21;
    carry10 = (s10 + (1 << 20)) >> 21;
    s11 += carry10;
    s10 -= carry10 << 21;
    carry12 = (s12 + (1 << 20)) >> 21;
    s13 += carry12;
    s12 -= carry12 << 21;
    carry14 = (s14 + (1 << 20)) >> 21;
    s15 += carry14;
    s14 -= carry14 << 21;
    carry16 = (s16 + (1 << 20)) >> 21;
    s17 += carry16;
    s16 -= carry16 << 21;

    carry7 = (s7 + (1 << 20)) >> 21;
    s8 += carry7;
    s7 -= carry7 << 21;
    carry9 = (s9 + (1 << 20)) >> 21;
    s10 += carry9;
    s9 -= carry9 << 21;
    carry11 = (s11 + (1 << 20)) >> 21;
    s12 += carry11;
    s11 -= carry11 << 21;
    carry13 = (s13 + (1 << 20)) >> 21;
    s14 += carry13;
    s13 -= carry13 << 21;
    carry15 = (s15 + (1 << 20)) >> 21;
    s16 += carry15;
    s15 -= carry15 << 21;

    s5 += s17 * 666643;
    s6 += s17 * 470296;
    s7 += s17 * 654183;
    s8 -= s17 * 997805;
    s9 += s17 * 136657;
    s10 -= s17 * 683901;
    // s17 = 0;

    s4 += s16 * 666643;
    s5 += s16 * 470296;
    s6 += s16 * 654183;
    s7 -= s16 * 997805;
    s8 += s16 * 136657;
    s9 -= s16 * 683901;
    // s16 = 0;

    s3 += s15 * 666643;
    s4 += s15 * 470296;
    s5 += s15 * 654183;
    s6 -= s15 * 997805;
    s7 += s15 * 136657;
    s8 -= s15 * 683901;
    // s15 = 0;

    s2 += s14 * 666643;
    s3 += s14 * 470296;
    s4 += s14 * 654183;
    s5 -= s14 * 997805;
    s6 += s14 * 136657;
    s7 -= s14 * 683901;
    // s14 = 0;

    s1 += s13 * 666643;
    s2 += s13 * 470296;
    s3 += s13 * 654183;
    s4 -= s13 * 997805;
    s5 += s13 * 136657;
    s6 -= s13 * 683901;
    // s13 = 0;

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    carry0 = (s0 + (1 << 20)) >> 21;
    s1 += carry0;
    s0 -= carry0 << 21;
    carry2 = (s2 + (1 << 20)) >> 21;
    s3 += carry2;
    s2 -= carry2 << 21;
    carry4 = (s4 + (1 << 20)) >> 21;
    s5 += carry4;
    s4 -= carry4 << 21;
    carry6 = (s6 + (1 << 20)) >> 21;
    s7 += carry6;
    s6 -= carry6 << 21;
    carry8 = (s8 + (1 << 20)) >> 21;
    s9 += carry8;
    s8 -= carry8 << 21;
    carry10 = (s10 + (1 << 20)) >> 21;
    s11 += carry10;
    s10 -= carry10 << 21;

    carry1 = (s1 + (1 << 20)) >> 21;
    s2 += carry1;
    s1 -= carry1 << 21;
    carry3 = (s3 + (1 << 20)) >> 21;
    s4 += carry3;
    s3 -= carry3 << 21;
    carry5 = (s5 + (1 << 20)) >> 21;
    s6 += carry5;
    s5 -= carry5 << 21;
    carry7 = (s7 + (1 << 20)) >> 21;
    s8 += carry7;
    s7 -= carry7 << 21;
    carry9 = (s9 + (1 << 20)) >> 21;
    s10 += carry9;
    s9 -= carry9 << 21;
    carry11 = (s11 + (1 << 20)) >> 21;
    s12 += carry11;
    s11 -= carry11 << 21;

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    carry0 = s0 >> 21;
    s1 += carry0;
    s0 -= carry0 << 21;
    carry1 = s1 >> 21;
    s2 += carry1;
    s1 -= carry1 << 21;
    carry2 = s2 >> 21;
    s3 += carry2;
    s2 -= carry2 << 21;
    carry3 = s3 >> 21;
    s4 += carry3;
    s3 -= carry3 << 21;
    carry4 = s4 >> 21;
    s5 += carry4;
    s4 -= carry4 << 21;
    carry5 = s5 >> 21;
    s6 += carry5;
    s5 -= carry5 << 21;
    carry6 = s6 >> 21;
    s7 += carry6;
    s6 -= carry6 << 21;
    carry7 = s7 >> 21;
    s8 += carry7;
    s7 -= carry7 << 21;
    carry8 = s8 >> 21;
    s9 += carry8;
    s8 -= carry8 << 21;
    carry9 = s9 >> 21;
    s10 += carry9;
    s9 -= carry9 << 21;
    carry10 = s10 >> 21;
    s11 += carry10;
    s10 -= carry10 << 21;
    carry11 = s11 >> 21;
    s12 += carry11;
    s11 -= carry11 << 21;

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    // s12 = 0;

    carry0 = s0 >> 21;
    s1 += carry0;
    s0 -= carry0 << 21;
    carry1 = s1 >> 21;
    s2 += carry1;
    s1 -= carry1 << 21;
    carry2 = s2 >> 21;
    s3 += carry2;
    s2 -= carry2 << 21;
    carry3 = s3 >> 21;
    s4 += carry3;
    s3 -= carry3 << 21;
    carry4 = s4 >> 21;
    s5 += carry4;
    s4 -= carry4 << 21;
    carry5 = s5 >> 21;
    s6 += carry5;
    s5 -= carry5 << 21;
    carry6 = s6 >> 21;
    s7 += carry6;
    s6 -= carry6 << 21;
    carry7 = s7 >> 21;
    s8 += carry7;
    s7 -= carry7 << 21;
    carry8 = s8 >> 21;
    s9 += carry8;
    s8 -= carry8 << 21;
    carry9 = s9 >> 21;
    s10 += carry9;
    s9 -= carry9 << 21;
    carry10 = s10 >> 21;
    s11 += carry10;
    s10 -= carry10 << 21;

    s[0] = (s0 >> 0) as u8;
    s[1] = (s0 >> 8) as u8;
    s[2] = ((s0 >> 16) | (s1 << 5)) as u8;
    s[3] = (s1 >> 3) as u8;
    s[4] = (s1 >> 11) as u8;
    s[5] = ((s1 >> 19) | (s2 << 2)) as u8;
    s[6] = (s2 >> 6) as u8;
    s[7] = ((s2 >> 14) | (s3 << 7)) as u8;
    s[8] = (s3 >> 1) as u8;
    s[9] = (s3 >> 9) as u8;
    s[10] = ((s3 >> 17) | (s4 << 4)) as u8;
    s[11] = (s4 >> 4) as u8;
    s[12] = (s4 >> 12) as u8;
    s[13] = ((s4 >> 20) | (s5 << 1)) as u8;
    s[14] = (s5 >> 7) as u8;
    s[15] = ((s5 >> 15) | (s6 << 6)) as u8;
    s[16] = (s6 >> 2) as u8;
    s[17] = (s6 >> 10) as u8;
    s[18] = ((s6 >> 18) | (s7 << 3)) as u8;
    s[19] = (s7 >> 5) as u8;
    s[20] = (s7 >> 13) as u8;
    s[21] = (s8 >> 0) as u8;
    s[22] = (s8 >> 8) as u8;
    s[23] = ((s8 >> 16) | (s9 << 5)) as u8;
    s[24] = (s9 >> 3) as u8;
    s[25] = (s9 >> 11) as u8;
    s[26] = ((s9 >> 19) | (s10 << 2)) as u8;
    s[27] = (s10 >> 6) as u8;
    s[28] = ((s10 >> 14) | (s11 << 7)) as u8;
    s[29] = (s11 >> 1) as u8;
    s[30] = (s11 >> 9) as u8;
    s[31] = (s11 >> 17) as u8;
}

fn sc_reduce(s: &mut [u8; 64]) {
    let mut s0 = 2097151 & load_3(s) as i64;
    let mut s1 = 2097151 & (load_4(&s[2..]) >> 5) as i64;
    let mut s2 = 2097151 & (load_3(&s[5..]) >> 2) as i64;
    let mut s3 = 2097151 & (load_4(&s[7..]) >> 7) as i64;
    let mut s4 = 2097151 & (load_4(&s[10..]) >> 4) as i64;
    let mut s5 = 2097151 & (load_3(&s[13..]) >> 1) as i64;
    let mut s6 = 2097151 & (load_4(&s[15..]) >> 6) as i64;
    let mut s7 = 2097151 & (load_3(&s[18..]) >> 3) as i64;
    let mut s8 = 2097151 & load_3(&s[21..]) as i64;
    let mut s9 = 2097151 & (load_4(&s[23..]) >> 5) as i64;
    let mut s10 = 2097151 & (load_3(&s[26..]) >> 2) as i64;
    let mut s11 = 2097151 & (load_4(&s[28..]) >> 7) as i64;
    let mut s12 = 2097151 & (load_4(&s[31..]) >> 4) as i64;
    let mut s13 = 2097151 & (load_3(&s[34..]) >> 1) as i64;
    let mut s14 = 2097151 & (load_4(&s[36..]) >> 6) as i64;
    let mut s15 = 2097151 & (load_3(&s[39..]) >> 3) as i64;
    let mut s16 = 2097151 & load_3(&s[42..]) as i64;
    let mut s17 = 2097151 & (load_4(&s[44..]) >> 5) as i64;
    let s18 = 2097151 & (load_3(&s[47..]) >> 2) as i64;
    let s19 = 2097151 & (load_4(&s[49..]) >> 7) as i64;
    let s20 = 2097151 & (load_4(&s[52..]) >> 4) as i64;
    let s21 = 2097151 & (load_3(&s[55..]) >> 1) as i64;
    let s22 = 2097151 & (load_4(&s[57..]) >> 6) as i64;
    let s23 = (load_4(&s[60..]) >> 3) as i64;
    let mut carry0;
    let mut carry1;
    let mut carry2;
    let mut carry3;
    let mut carry4;
    let mut carry5;
    let mut carry6;
    let mut carry7;
    let mut carry8;
    let mut carry9;
    let mut carry10;
    let mut carry11;
    let carry12;
    let carry13;
    let carry14;
    let carry15;
    let carry16;

    s11 += s23 * 666643;
    s12 += s23 * 470296;
    s13 += s23 * 654183;
    s14 -= s23 * 997805;
    s15 += s23 * 136657;
    s16 -= s23 * 683901;
    // s23 = 0;

    s10 += s22 * 666643;
    s11 += s22 * 470296;
    s12 += s22 * 654183;
    s13 -= s22 * 997805;
    s14 += s22 * 136657;
    s15 -= s22 * 683901;
    // s22 = 0;

    s9 += s21 * 666643;
    s10 += s21 * 470296;
    s11 += s21 * 654183;
    s12 -= s21 * 997805;
    s13 += s21 * 136657;
    s14 -= s21 * 683901;
    // s21 = 0;

    s8 += s20 * 666643;
    s9 += s20 * 470296;
    s10 += s20 * 654183;
    s11 -= s20 * 997805;
    s12 += s20 * 136657;
    s13 -= s20 * 683901;
    // s20 = 0;

    s7 += s19 * 666643;
    s8 += s19 * 470296;
    s9 += s19 * 654183;
    s10 -= s19 * 997805;
    s11 += s19 * 136657;
    s12 -= s19 * 683901;
    // s19 = 0;

    s6 += s18 * 666643;
    s7 += s18 * 470296;
    s8 += s18 * 654183;
    s9 -= s18 * 997805;
    s10 += s18 * 136657;
    s11 -= s18 * 683901;
    // s18 = 0;

    carry6 = (s6 + (1 << 20)) >> 21;
    s7 += carry6;
    s6 -= carry6 << 21;
    carry8 = (s8 + (1 << 20)) >> 21;
    s9 += carry8;
    s8 -= carry8 << 21;
    carry10 = (s10 + (1 << 20)) >> 21;
    s11 += carry10;
    s10 -= carry10 << 21;
    carry12 = (s12 + (1 << 20)) >> 21;
    s13 += carry12;
    s12 -= carry12 << 21;
    carry14 = (s14 + (1 << 20)) >> 21;
    s15 += carry14;
    s14 -= carry14 << 21;
    carry16 = (s16 + (1 << 20)) >> 21;
    s17 += carry16;
    s16 -= carry16 << 21;

    carry7 = (s7 + (1 << 20)) >> 21;
    s8 += carry7;
    s7 -= carry7 << 21;
    carry9 = (s9 + (1 << 20)) >> 21;
    s10 += carry9;
    s9 -= carry9 << 21;
    carry11 = (s11 + (1 << 20)) >> 21;
    s12 += carry11;
    s11 -= carry11 << 21;
    carry13 = (s13 + (1 << 20)) >> 21;
    s14 += carry13;
    s13 -= carry13 << 21;
    carry15 = (s15 + (1 << 20)) >> 21;
    s16 += carry15;
    s15 -= carry15 << 21;

    s5 += s17 * 666643;
    s6 += s17 * 470296;
    s7 += s17 * 654183;
    s8 -= s17 * 997805;
    s9 += s17 * 136657;
    s10 -= s17 * 683901;
    // s17 = 0;

    s4 += s16 * 666643;
    s5 += s16 * 470296;
    s6 += s16 * 654183;
    s7 -= s16 * 997805;
    s8 += s16 * 136657;
    s9 -= s16 * 683901;
    // s16 = 0;

    s3 += s15 * 666643;
    s4 += s15 * 470296;
    s5 += s15 * 654183;
    s6 -= s15 * 997805;
    s7 += s15 * 136657;
    s8 -= s15 * 683901;
    // s15 = 0;

    s2 += s14 * 666643;
    s3 += s14 * 470296;
    s4 += s14 * 654183;
    s5 -= s14 * 997805;
    s6 += s14 * 136657;
    s7 -= s14 * 683901;
    // s14 = 0;

    s1 += s13 * 666643;
    s2 += s13 * 470296;
    s3 += s13 * 654183;
    s4 -= s13 * 997805;
    s5 += s13 * 136657;
    s6 -= s13 * 683901;
    // s13 = 0;

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    carry0 = (s0 + (1 << 20)) >> 21;
    s1 += carry0;
    s0 -= carry0 << 21;
    carry2 = (s2 + (1 << 20)) >> 21;
    s3 += carry2;
    s2 -= carry2 << 21;
    carry4 = (s4 + (1 << 20)) >> 21;
    s5 += carry4;
    s4 -= carry4 << 21;
    carry6 = (s6 + (1 << 20)) >> 21;
    s7 += carry6;
    s6 -= carry6 << 21;
    carry8 = (s8 + (1 << 20)) >> 21;
    s9 += carry8;
    s8 -= carry8 << 21;
    carry10 = (s10 + (1 << 20)) >> 21;
    s11 += carry10;
    s10 -= carry10 << 21;

    carry1 = (s1 + (1 << 20)) >> 21;
    s2 += carry1;
    s1 -= carry1 << 21;
    carry3 = (s3 + (1 << 20)) >> 21;
    s4 += carry3;
    s3 -= carry3 << 21;
    carry5 = (s5 + (1 << 20)) >> 21;
    s6 += carry5;
    s5 -= carry5 << 21;
    carry7 = (s7 + (1 << 20)) >> 21;
    s8 += carry7;
    s7 -= carry7 << 21;
    carry9 = (s9 + (1 << 20)) >> 21;
    s10 += carry9;
    s9 -= carry9 << 21;
    carry11 = (s11 + (1 << 20)) >> 21;
    s12 += carry11;
    s11 -= carry11 << 21;

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    carry0 = s0 >> 21;
    s1 += carry0;
    s0 -= carry0 << 21;
    carry1 = s1 >> 21;
    s2 += carry1;
    s1 -= carry1 << 21;
    carry2 = s2 >> 21;
    s3 += carry2;
    s2 -= carry2 << 21;
    carry3 = s3 >> 21;
    s4 += carry3;
    s3 -= carry3 << 21;
    carry4 = s4 >> 21;
    s5 += carry4;
    s4 -= carry4 << 21;
    carry5 = s5 >> 21;
    s6 += carry5;
    s5 -= carry5 << 21;
    carry6 = s6 >> 21;
    s7 += carry6;
    s6 -= carry6 << 21;
    carry7 = s7 >> 21;
    s8 += carry7;
    s7 -= carry7 << 21;
    carry8 = s8 >> 21;
    s9 += carry8;
    s8 -= carry8 << 21;
    carry9 = s9 >> 21;
    s10 += carry9;
    s9 -= carry9 << 21;
    carry10 = s10 >> 21;
    s11 += carry10;
    s10 -= carry10 << 21;
    carry11 = s11 >> 21;
    s12 += carry11;
    s11 -= carry11 << 21;

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    // s12 = 0;

    carry0 = s0 >> 21;
    s1 += carry0;
    s0 -= carry0 << 21;
    carry1 = s1 >> 21;
    s2 += carry1;
    s1 -= carry1 << 21;
    carry2 = s2 >> 21;
    s3 += carry2;
    s2 -= carry2 << 21;
    carry3 = s3 >> 21;
    s4 += carry3;
    s3 -= carry3 << 21;
    carry4 = s4 >> 21;
    s5 += carry4;
    s4 -= carry4 << 21;
    carry5 = s5 >> 21;
    s6 += carry5;
    s5 -= carry5 << 21;
    carry6 = s6 >> 21;
    s7 += carry6;
    s6 -= carry6 << 21;
    carry7 = s7 >> 21;
    s8 += carry7;
    s7 -= carry7 << 21;
    carry8 = s8 >> 21;
    s9 += carry8;
    s8 -= carry8 << 21;
    carry9 = s9 >> 21;
    s10 += carry9;
    s9 -= carry9 << 21;
    carry10 = s10 >> 21;
    s11 += carry10;
    s10 -= carry10 << 21;

    s[0] = (s0 >> 0) as u8;
    s[1] = (s0 >> 8) as u8;
    s[2] = ((s0 >> 16) | (s1 << 5)) as u8;
    s[3] = (s1 >> 3) as u8;
    s[4] = (s1 >> 11) as u8;
    s[5] = ((s1 >> 19) | (s2 << 2)) as u8;
    s[6] = (s2 >> 6) as u8;
    s[7] = ((s2 >> 14) | (s3 << 7)) as u8;
    s[8] = (s3 >> 1) as u8;
    s[9] = (s3 >> 9) as u8;
    s[10] = ((s3 >> 17) | (s4 << 4)) as u8;
    s[11] = (s4 >> 4) as u8;
    s[12] = (s4 >> 12) as u8;
    s[13] = ((s4 >> 20) | (s5 << 1)) as u8;
    s[14] = (s5 >> 7) as u8;
    s[15] = ((s5 >> 15) | (s6 << 6)) as u8;
    s[16] = (s6 >> 2) as u8;
    s[17] = (s6 >> 10) as u8;
    s[18] = ((s6 >> 18) | (s7 << 3)) as u8;
    s[19] = (s7 >> 5) as u8;
    s[20] = (s7 >> 13) as u8;
    s[21] = (s8 >> 0) as u8;
    s[22] = (s8 >> 8) as u8;
    s[23] = ((s8 >> 16) | (s9 << 5)) as u8;
    s[24] = (s9 >> 3) as u8;
    s[25] = (s9 >> 11) as u8;
    s[26] = ((s9 >> 19) | (s10 << 2)) as u8;
    s[27] = (s10 >> 6) as u8;
    s[28] = ((s10 >> 14) | (s11 << 7)) as u8;
    s[29] = (s11 >> 1) as u8;
    s[30] = (s11 >> 9) as u8;
    s[31] = (s11 >> 17) as u8;
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
    x3.copy_from(x1);
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

fn load_3(x: &[u8]) -> u64 {
    let mut result = u64::from(x[0]);
    result |= u64::from(x[1]) << 8;
    result |= u64::from(x[2]) << 16;
    result
}

fn load_4(x: &[u8]) -> u64 {
    let mut result = u64::from(x[0]);
    result |= u64::from(x[1]) << 8;
    result |= u64::from(x[2]) << 16;
    result |= u64::from(x[3]) << 24;
    result
}

#[derive(Clone, Copy, Default)]
struct Fe([i32; 10]);

impl From<[i32; 10]> for Fe {
    fn from(x: [i32; 10]) -> Self {
        Fe(x)
    }
}

impl Fe {
    fn assign_zero(&mut self) {
        for l in &mut self.0 {
            *l = 0;
        }
    }

    fn assign_one(&mut self) {
        let h = &mut self.0;
        h[0] = 1;
        for l in h.iter_mut().skip(1) {
            *l = 0;
        }
    }

    fn assign_sum(&mut self, f: &Fe, g: &Fe) {
        for (l, r) in self.0.iter_mut().zip(
            f.0.iter().zip(&g.0).map(|(x, y)| x + y),
        )
        {
            *l = r;
        }
    }

    fn copy_from(&mut self, f: &Fe) {
        for (l, &r) in self.0.iter_mut().zip(&f.0) {
            *l = r;
        }
    }

    fn cmov_from(&mut self, g: &Fe, b: u32) {
        let f = &mut self.0;
        let g = g.0;
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

    fn assign_from_bytes(&mut self, s: &[u8]) {
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

    fn inverse(&self) -> Self {
        let mut inv = Self::default();
        fe_invert!(&mut inv, self);
        inv
    }

    fn invert(&mut self) {
        fe_invert!(self, self);
    }

    fn is_negative(&self) -> i32 {
        let s = &mut [0; 32];
        self.write_bytes(s);
        (s[0] & 1) as i32
    }

    fn is_nonzero(&self) -> i32 {
        let s = &mut [0; 32];
        self.write_bytes(s);
        verify_32(s, &ZERO)
    }

    fn assign_product(&mut self, f: &Fe, g: &Fe) {
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

    fn assign_neg(&mut self, f: &Fe) {
        for (l, &r) in self.0.iter_mut().zip(&f.0) {
            *l = -r;
        }
    }

    fn neg(&mut self) {
        for l in &mut self.0 {
            *l = -*l;
        }
    }

    fn pow22523(&mut self) {
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

    fn assign_square(&mut self, f: &Fe) {
        fe_sq!(&mut self.0, f.0);
    }

    fn square(&mut self) {
        fe_sq!(&mut self.0, self.0);
    }

    fn assign_twice_square(&mut self, f: &Fe) {
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

        h0 += h0;
        h1 += h1;
        h2 += h2;
        h3 += h3;
        h4 += h4;
        h5 += h5;
        h6 += h6;
        h7 += h7;
        h8 += h8;
        h9 += h9;

        let carry0 = (h0 + (1 << 25)) >> 26;
        h1 += carry0;
        h0 -= carry0 << 26;
        let carry4 = (h4 + (1 << 25)) >> 26;
        h5 += carry4;
        h4 -= carry4 << 26;

        let carry1 = (h1 + (1 << 24)) >> 25;
        h2 += carry1;
        h1 -= carry1 << 25;
        let carry5 = (h5 + (1 << 24)) >> 25;
        h6 += carry5;
        h5 -= carry5 << 25;

        let carry2 = (h2 + (1 << 25)) >> 26;
        h3 += carry2;
        h2 -= carry2 << 26;
        let carry6 = (h6 + (1 << 25)) >> 26;
        h7 += carry6;
        h6 -= carry6 << 26;

        let carry3 = (h3 + (1 << 24)) >> 25;
        h4 += carry3;
        h3 -= carry3 << 25;
        let carry7 = (h7 + (1 << 24)) >> 25;
        h8 += carry7;
        h7 -= carry7 << 25;

        let carry4 = (h4 + (1 << 25)) >> 26;
        h5 += carry4;
        h4 -= carry4 << 26;
        let carry8 = (h8 + (1 << 25)) >> 26;
        h9 += carry8;
        h8 -= carry8 << 26;

        let carry9 = (h9 + (1 << 24)) >> 25;
        h0 += carry9 * 19;
        h9 -= carry9 << 25;

        let carry0 = (h0 + (1 << 25)) >> 26;
        h1 += carry0;
        h0 -= carry0 << 26;
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

    fn assign_difference(&mut self, f: &Fe, g: &Fe) {
        for (l, r) in self.0.iter_mut().zip(
            f.0.iter().zip(&g.0).map(|(x, y)| x - y),
        )
        {
            *l = r;
        }
    }

    fn subtract_from(&mut self, f: &Fe) {
        for (l, r) in self.0.iter_mut().zip(&f.0) {
            *l = r - *l;
        }
    }

    fn write_bytes(&self, s: &mut [u8]) {
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

        s[0] = (h0 >> 0) as u8;
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
        s[16] = (h5 >> 0) as u8;
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
        for (l, &r) in self.0.iter_mut().zip(&rhs.0) {
            *l += r;
        }
    }
}

impl<'a, 'b> AddAssign<&'a Fe> for &'b mut Fe {
    fn add_assign(&mut self, rhs: &'a Fe) {
        for (l, &r) in self.0.iter_mut().zip(&rhs.0) {
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
        for (l, &r) in self.0.iter_mut().zip(&rhs.0) {
            *l -= r;
        }
    }
}

impl<'a, 'b> SubAssign<&'a Fe> for &'b mut Fe {
    fn sub_assign(&mut self, rhs: &'a Fe) {
        for (l, &r) in self.0.iter_mut().zip(&rhs.0) {
            *l -= r;
        }
    }
}

#[derive(Default)]
struct GeP2 {
    x: Fe,
    y: Fe,
    z: Fe,
}

impl<'a> From<&'a GeP3> for GeP2 {
    fn from(p: &GeP3) -> Self {
        Self {
            x: p.x,
            y: p.y,
            z: p.z,
        }
    }
}

impl GeP2 {
    fn from_double_scalarmult_vartime(a: &[u8; 64], ga: &GeP3, b: &[u8]) -> Self {
        assert_eq!(32, b.len());
        let aslide = &mut [0; 256];
        let bslide = &mut [0; 256];
        let mut ai = [GeCached::default(); 8];
        let t = &mut GeP1p1::default();
        let u = &mut GeP3::default();
        let a2 = &mut GeP3::default();
        let mut i: i16 = 255;

        slide(aslide, a);
        slide(bslide, b);

        ge_p3_to_cached(&mut ai[0], ga);
        ge_p3_dbl(t, ga);
        ge_p1p1_to_p3(a2, t);
        ge_add(t, a2, &ai[0]);
        ge_p1p1_to_p3(u, t);
        ge_p3_to_cached(&mut ai[1], u);
        ge_add(t, a2, &ai[1]);
        ge_p1p1_to_p3(u, t);
        ge_p3_to_cached(&mut ai[2], u);
        ge_add(t, a2, &ai[2]);
        ge_p1p1_to_p3(u, t);
        ge_p3_to_cached(&mut ai[3], u);
        ge_add(t, a2, &ai[3]);
        ge_p1p1_to_p3(u, t);
        ge_p3_to_cached(&mut ai[4], u);
        ge_add(t, a2, &ai[4]);
        ge_p1p1_to_p3(u, t);
        ge_p3_to_cached(&mut ai[5], u);
        ge_add(t, a2, &ai[5]);
        ge_p1p1_to_p3(u, t);
        ge_p3_to_cached(&mut ai[6], u);
        ge_add(t, a2, &ai[6]);
        ge_p1p1_to_p3(u, t);
        ge_p3_to_cached(&mut ai[7], u);

        let mut r = Self::zero();

        while i >= 0 {
            if aslide[i as usize] != 0 || bslide[i as usize] != 0 {
                break;
            }
            i -= 1;
        }

        while i >= 0 {
            ge_p2_dbl(t, &r);

            if aslide[i as usize] > 0 {
                ge_p1p1_to_p3(u, t);
                ge_add(t, u, &ai[aslide[i as usize] as usize / 2]);
            } else if aslide[i as usize] < 0 {
                ge_p1p1_to_p3(u, t);
                ge_sub(t, u, &ai[(-aslide[i as usize]) as usize / 2]);
            }

            if bslide[i as usize] > 0 {
                ge_p1p1_to_p3(u, t);
                ge_madd(t, u, &GePrecomp::from(BI[bslide[i as usize] as usize / 2]));
            } else if bslide[i as usize] < 0 {
                ge_p1p1_to_p3(u, t);
                ge_msub(
                    t,
                    u,
                    &GePrecomp::from(BI[(-bslide[i as usize]) as usize / 2]),
                );
            }

            ge_p1p1_to_p2(&mut r, t);
            i -= 1;
        }
        r
    }

    fn to_bytes(&self) -> [u8; 32] {
        let mut s = [0; 32];
        let x = &mut Fe::default();
        let y = &mut Fe::default();

        let recip = &self.z.inverse();
        x.assign_product(&self.x, recip);
        y.assign_product(&self.y, recip);
        y.write_bytes(&mut s);
        s[31] ^= (x.is_negative() << 7) as u8;
        s
    }

    fn zero() -> Self {
        let mut h = GeP2::default();
        h.x.assign_zero();
        h.y.assign_one();
        h.z.assign_one();
        h
    }
}

#[derive(Default)]
struct GeP3 {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

impl GeP3 {
    fn from_bytes_negate_vartime(s: &[u8]) -> Option<Self> {
        let mut h = Self::default();
        let mut u = &mut Fe::default();
        let mut v = &mut Fe::default();
        let mut v3 = &mut Fe::default();
        let mut vxx = &mut Fe::default();
        let check = &mut Fe::default();

        h.y.assign_from_bytes(s);
        h.z.assign_one();
        u.assign_square(&h.y);
        v.assign_product(u, &Fe::from(D));
        u -= &h.z;
        v += &h.z;

        v3.assign_square(v);
        v3 *= v;
        h.x.assign_square(v3);
        h.x *= v;
        h.x *= u;

        h.x.pow22523();
        h.x *= v3;
        h.x *= u;

        vxx.assign_square(&h.x);
        vxx *= v;
        check.assign_difference(vxx, u);
        if check.is_nonzero() != 0 {
            check.assign_sum(vxx, u);
            if check.is_nonzero() != 0 {
                return None;
            }
            h.x *= &Fe::from(SQRTM1);
        }

        if h.x.is_negative() == i32::from(s[31] >> 7) {
            h.x.neg();
        }

        h.t.assign_product(&h.x, &h.y);
        Some(h)
    }
}

#[derive(Default)]
struct GeP1p1 {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

#[derive(Default)]
struct GePrecomp {
    yplusx: Fe,
    yminusx: Fe,
    xy2d: Fe,
}

impl From<[[i32; 10]; 3]> for GePrecomp {
    fn from(x: [[i32; 10]; 3]) -> Self {
        Self {
            yplusx: Fe::from(x[0]),
            yminusx: Fe::from(x[1]),
            xy2d: Fe::from(x[2]),
        }
    }
}

#[derive(Clone, Copy, Default)]
struct GeCached {
    yplusx: Fe,
    yminusx: Fe,
    z: Fe,
    t2d: Fe,
}

fn ge_add(r: &mut GeP1p1, p: &GeP3, q: &GeCached) {
    let t0 = &mut Fe::default();
    r.x.assign_sum(&p.y, &p.x);

    r.y.assign_difference(&p.y, &p.x);

    r.z.assign_product(&r.x, &q.yplusx);

    r.y *= &q.yminusx;

    r.t.assign_product(&q.t2d, &p.t);

    r.x.assign_product(&p.z, &q.z);

    t0.assign_sum(&r.x, &r.x);

    r.x.assign_difference(&r.z, &r.y);

    r.y += &r.z;

    r.z.assign_sum(t0, &r.t);

    r.t.subtract_from(t0);
}

fn slide(r: &mut [i8; 256], a: &[u8]) {
    let mut b;

    for i in 0..256 {
        r[i] = 1 & (a[i >> 3] >> (i & 7)) as i8;
    }

    for i in 0..256 {
        if r[i] != 0 {

            b = 1;
            while b <= 6 && i + b < 256 {
                if r[i + b] != 0 {
                    if r[i] + (r[i + b] << b) <= 15 {
                        r[i] += r[i + b] << b;
                        r[i + b] = 0;
                    } else if r[i] - (r[i + b] << b) >= -15 {
                        r[i] -= r[i + b] << b;
                        for k in (i + b)..256 {
                            if r[k] == 0 {
                                r[k] = 1;
                                break;
                            }
                            r[k] = 0;
                        }
                    } else {
                        break;
                    }
                }
                b += 1;
            }
        }
    }
}

fn ge_madd(r: &mut GeP1p1, p: &GeP3, q: &GePrecomp) {
    let t0 = &mut Fe::default();
    r.x.assign_sum(&p.y, &p.x);

    r.y.assign_difference(&p.y, &p.x);

    r.z.assign_product(&r.x, &q.yplusx);

    r.y *= &q.yminusx;

    r.t.assign_product(&q.xy2d, &p.t);

    t0.assign_sum(&p.z, &p.z);

    r.x.assign_difference(&r.z, &r.y);

    r.y += &r.z;

    r.z.assign_sum(t0, &r.t);

    r.t.subtract_from(t0);
}

fn ge_msub(r: &mut GeP1p1, p: &GeP3, q: &GePrecomp) {
    let t0 = &mut Fe::default();
    r.x.assign_sum(&p.y, &p.x);

    r.y.assign_difference(&p.y, &p.x);

    r.z.assign_product(&r.x, &q.yminusx);

    r.y *= &q.yplusx;

    r.t.assign_product(&q.xy2d, &p.t);

    t0.assign_sum(&p.z, &p.z);

    r.x.assign_difference(&r.z, &r.y);

    r.y += &r.z;

    r.z.assign_difference(t0, &r.t);

    r.t += t0;
}

fn ge_p1p1_to_p2(r: &mut GeP2, p: &GeP1p1) {
    r.x.assign_product(&p.x, &p.t);
    r.y.assign_product(&p.y, &p.z);
    r.z.assign_product(&p.z, &p.t);
}

fn ge_p1p1_to_p3(r: &mut GeP3, p: &GeP1p1) {
    r.x.assign_product(&p.x, &p.t);
    r.y.assign_product(&p.y, &p.z);
    r.z.assign_product(&p.z, &p.t);
    r.t.assign_product(&p.x, &p.y);
}

fn ge_p2_dbl(r: &mut GeP1p1, p: &GeP2) {
    let t0 = &mut Fe::default();
    r.x.assign_square(&p.x);

    r.z.assign_square(&p.y);

    r.t.assign_twice_square(&p.z);

    r.y.assign_sum(&p.x, &p.y);

    t0.assign_square(&r.y);

    r.y.assign_sum(&r.z, &r.x);

    r.z -= &r.x;

    r.x.assign_difference(t0, &r.y);

    r.t -= &r.z;
}

fn ge_p3_dbl(r: &mut GeP1p1, p: &GeP3) {
    let q = &GeP2::from(p);
    ge_p2_dbl(r, q);
}

fn ge_p3_tobytes(s: &mut [u8], h: &GeP3) {
    let x = &mut Fe::default();
    let y = &mut Fe::default();
    let recip = &h.z.inverse();
    x.assign_product(&h.x, recip);
    y.assign_product(&h.y, recip);
    y.write_bytes(s);
    s[31] ^= (x.is_negative() << 7) as u8;
}

fn ge_p3_to_cached(r: &mut GeCached, p: &GeP3) {
    r.yplusx.assign_sum(&p.y, &p.x);
    r.yminusx.assign_difference(&p.y, &p.x);
    r.z.copy_from(&p.z);
    r.t2d.assign_product(&p.t, &Fe::from(D2));
}

fn ge_p3_0(h: &mut GeP3) {
    h.x.assign_zero();
    h.y.assign_one();
    h.z.assign_one();
    h.t.assign_zero();
}

fn ge_precomp_0(h: &mut GePrecomp) {
    h.yplusx.assign_one();
    h.yminusx.assign_one();
    h.xy2d.assign_zero();
}
fn equal(b: i8, c: i8) -> u8 {
    let ub = b as u8;
    let uc = c as u8;
    let x = ub ^ uc;
    let mut y = x as u32;
    y = y.wrapping_sub(1);
    y >>= 31;
    y as u8
}

fn negative(b: i8) -> u8 {
    let mut x = b as u64;
    x >>= 63;
    x as u8
}

fn cmov(t: &mut GePrecomp, u: &GePrecomp, b: u8) {
    t.yplusx.cmov_from(&u.yplusx, u32::from(b));
    t.yminusx.cmov_from(&u.yminusx, u32::from(b));
    t.xy2d.cmov_from(&u.xy2d, u32::from(b));
}

fn select(t: &mut GePrecomp, pos: usize, b: i8) {
    let mut minust = GePrecomp::default();
    let bnegative = negative(b);
    let babs = b - ((bnegative.wrapping_neg() as i8 & b) << 1);

    ge_precomp_0(t);
    cmov(t, &GePrecomp::from(BASE[pos][0]), equal(babs, 1));
    cmov(t, &GePrecomp::from(BASE[pos][1]), equal(babs, 2));
    cmov(t, &GePrecomp::from(BASE[pos][2]), equal(babs, 3));
    cmov(t, &GePrecomp::from(BASE[pos][3]), equal(babs, 4));
    cmov(t, &GePrecomp::from(BASE[pos][4]), equal(babs, 5));
    cmov(t, &GePrecomp::from(BASE[pos][5]), equal(babs, 6));
    cmov(t, &GePrecomp::from(BASE[pos][6]), equal(babs, 7));
    cmov(t, &GePrecomp::from(BASE[pos][7]), equal(babs, 8));
    minust.yplusx.copy_from(&t.yminusx);
    minust.yminusx.copy_from(&t.yplusx);
    minust.xy2d.assign_neg(&t.xy2d);
    cmov(t, &minust, bnegative);
}

fn ge_scalarmult_base(h: &mut GeP3, a: &[u8; 64]) {
    let mut e = [0; 64];
    let r = &mut GeP1p1::default();
    let s = &mut GeP2::default();
    let t = &mut GePrecomp::default();

    for i in 0..32 {
        e[2 * i + 0] = (a[i] >> 0) as i8 & 15;
        e[2 * i + 1] = (a[i] >> 4) as i8 & 15;
    }

    let mut carry = 0;
    for i in 0..63 {
        e[i] += carry;
        carry = e[i] + 8;
        carry >>= 4;
        e[i] -= carry << 4;
    }
    e[63] += carry;

    ge_p3_0(h);
    let mut i = 1;
    while i < 64 {
        select(t, i / 2, e[i]);
        ge_madd(r, h, t);
        ge_p1p1_to_p3(h, r);
        i += 2;
    }

    ge_p3_dbl(r, h);
    ge_p1p1_to_p2(s, r);
    ge_p2_dbl(r, s);
    ge_p1p1_to_p2(s, r);
    ge_p2_dbl(r, s);
    ge_p1p1_to_p2(s, r);
    ge_p2_dbl(r, s);
    ge_p1p1_to_p3(h, r);

    i = 0;
    while i < 64 {
        select(t, i / 2, e[i]);
        ge_madd(r, h, t);
        ge_p1p1_to_p3(h, r);
        i += 2;
    }
}

fn ge_sub(r: &mut GeP1p1, p: &GeP3, q: &GeCached) {
    let t0 = &mut Fe::default();
    r.x.assign_sum(&p.y, &p.x);

    r.y.assign_difference(&p.y, &p.x);

    r.z.assign_product(&r.x, &q.yminusx);

    r.y *= &q.yplusx;

    r.t.assign_product(&q.t2d, &p.t);

    r.x.assign_product(&p.z, &q.z);

    t0.assign_sum(&r.x, &r.x);

    r.x.assign_difference(&r.z, &r.y);

    r.y += &r.z;

    r.z.assign_difference(t0, &r.t);

    r.t += t0;
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_helpers::*;

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
                    &h2b(
                        "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
                    ),
                    x
                );
            } else if i == 999 {
                assert_eq!(
                    &h2b(
                        "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51",
                    ),
                    x
                );
            } else if i == 999999 {
                assert_eq!(
                    &h2b(
                        "7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424",
                    ),
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

    fn check_edsa(sk: &str, pk: &str, msg: &str, sig: &str) {
        let sk = &h2b(sk);
        let pk = &h2b(pk);
        let msg = &h2b(msg);
        let sig = h2b(sig);
        let signature = sign(msg, sk, pk);
        assert_eq!(sig, signature.to_vec());
        assert!(verify(msg, &signature, pk))
        // TODO: check that a bad signature causes verification to fail
    }

    #[test]
    fn test_edsa() {
        let sk = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        let pk = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let msg = "";
        let sig = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
                   5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
        check_edsa(sk, pk, msg, sig);

        let sk = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
        let pk = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
        let msg = "72";
        let sig = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
                   085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";
        check_edsa(sk, pk, msg, sig);

        let sk = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7";
        let pk = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";
        let msg = "af82";
        let sig = "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac\
                   18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a";
        check_edsa(sk, pk, msg, sig);

        let sk = "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5";
        let pk = "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e";
        let msg = "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98\
                   fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8\
                   79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d\
                   658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc\
                   1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe\
                   ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e\
                   06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef\
                   efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7\
                   aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1\
                   85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2\
                   d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24\
                   554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270\
                   88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc\
                   2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07\
                   07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba\
                   b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a\
                   ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e\
                   c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7\
                   51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c\
                   42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8\
                   ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df\
                   f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08\
                   d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649\
                   de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4\
                   88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3\
                   2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e\
                   6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f\
                   b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5\
                   0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1\
                   369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d\
                   b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c\
                   0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0";
        let sig = "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350\
                   aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03";
        check_edsa(sk, pk, msg, sig);

        let sk = "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42";
        let pk = "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf";
        let msg = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                   2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
        let sig = "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589\
                   09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704";
        check_edsa(sk, pk, msg, sig);
    }
}
