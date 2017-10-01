use num::{BigUint, Integer, One, Zero};

const BITS: usize = 255;
const A24: u32 = 121665;

/// This is horrible
/// and insecure
pub fn x_25519(k: &[u8], u: &[u8]) -> Vec<u8> {
    assert_eq!(32, k.len());
    assert_eq!((BITS + 7) / 8, u.len());
    let k = decode_scalar(k);
    let x_1 = decode_u_coordinate(u);
    let mut x_2 = One::one();
    let mut z_2 = Zero::zero();
    let mut x_3 = x_1.clone();
    let mut z_3 = One::one();
    let mut swap = Zero::zero();
    let a24: BigUint = A24.into();
    let p: BigUint = (BigUint::from(1u8) << 255) - BigUint::from(19u8);

    for t in (0..BITS).rev() {
        let k_t = (&k >> t) & BigUint::from(1u8);
        swap = swap ^ &k_t;
        cswap(&swap, &mut x_2, &mut x_3);
        cswap(&swap, &mut z_2, &mut z_3);
        swap = k_t;

        let a = (&x_2 + &z_2).mod_floor(&p);
        let aa = (&a * &a).mod_floor(&p);
        let b = (&p + &x_2 - &z_2).mod_floor(&p);
        let bb = (&b * &b).mod_floor(&p);
        let e = (&p + &aa - &bb).mod_floor(&p);
        let c = (&x_3 + &z_3).mod_floor(&p);
        let d = (&p + &x_3 - &z_3).mod_floor(&p);
        let da = (d * a).mod_floor(&p);
        let cb = (c * b).mod_floor(&p);
        x_3 = (&da + &cb).mod_floor(&p);
        x_3 = (&x_3 * &x_3).mod_floor(&p);
        z_3 = (&p + da - cb).mod_floor(&p);
        z_3 = (&x_1 * &z_3 * &z_3).mod_floor(&p);
        x_2 = (&aa * bb).mod_floor(&p);
        z_2 = (&e * (aa + &a24 * &e)).mod_floor(&p);
    }
    cswap(&swap, &mut x_2, &mut x_3);
    cswap(&swap, &mut z_2, &mut z_3);
    (x_2 * pow(z_2, &p)).mod_floor(&p).to_bytes_le()
}

fn decode_u_coordinate(u: &[u8]) -> BigUint {
    let mut u_vec = u.to_vec();
    if BITS % 8 != 0 {
        if let Some(last) = u_vec.last_mut() {
            *last &= (1 << (BITS % 8)) - 1;
        }
    }
    BigUint::from_bytes_le(&u_vec)
}

fn decode_scalar(k: &[u8]) -> BigUint {
    let mut k_vec = k.to_vec();
    k_vec[0] &= 248;
    k_vec[31] &= 127;
    k_vec[31] |= 64;
    BigUint::from_bytes_le(&k_vec)
}

fn cswap(swap: &BigUint, x_2: &mut BigUint, x_3: &mut BigUint) {
    let dummy = mask(swap) & (&*x_2 ^ &*x_3);
    *x_2 = &*x_2 ^ &dummy;
    *x_3 = &*x_3 ^ &dummy;
}

fn mask(swap: &BigUint) -> BigUint {
    (BigUint::from(1u8) << 255) - swap
}

fn pow(z: BigUint, p: &BigUint) -> BigUint {
    let two: BigUint = 2u8.into();
    let mut res: BigUint = One::one();
    let mut base = z;
    let mut exponent = p - &two;
    while exponent > Zero::zero() {
        if exponent.mod_floor(&two) == One::one() {
            res = (res * &base).mod_floor(p);
        }
        exponent = exponent >> 1;
        base = (&base * &base).mod_floor(p);
    }
    res
}

#[cfg(test)]
mod tests {
    use curve25519::*;

    #[test]
    fn test_x_25519() {
        let k = [
            0xa5,
            0x46,
            0xe3,
            0x6b,
            0xf0,
            0x52,
            0x7c,
            0x9d,
            0x_3b,
            0x_16,
            0x_15,
            0x4b,
            0x82,
            0x46,
            0x5e,
            0xdd,
            0x62,
            0x_14,
            0x4c,
            0x0a,
            0xc1,
            0xfc,
            0x5a,
            0x_18,
            0x50,
            0x6a,
            0x_22,
            0x44,
            0xba,
            0x44,
            0x9a,
            0xc4,
        ];
        let u = [
            0xe6,
            0xdb,
            0x68,
            0x67,
            0x58,
            0x_30,
            0x_30,
            0xdb,
            0x_35,
            0x94,
            0xc1,
            0xa4,
            0x_24,
            0xb1,
            0x5f,
            0x7c,
            0x72,
            0x66,
            0x_24,
            0xec,
            0x_26,
            0xb3,
            0x_35,
            0x_3b,
            0x_10,
            0xa9,
            0x03,
            0xa6,
            0xd0,
            0xab,
            0x_1c,
            0x4c,
        ];
        let x = vec![
            0xc3,
            0xda,
            0x55,
            0x_37,
            0x9d,
            0xe9,
            0xc6,
            0x90,
            0x8e,
            0x94,
            0xea,
            0x4d,
            0xf2,
            0x8d,
            0x08,
            0x4f,
            0x_32,
            0xec,
            0xcf,
            0x03,
            0x49,
            0x_1c,
            0x71,
            0xf7,
            0x54,
            0xb4,
            0x07,
            0x55,
            0x77,
            0xa2,
            0x85,
            0x52,
        ];
        assert_eq!(x, x_25519(&k, &u));
    }
}
