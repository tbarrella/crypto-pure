use num::{BigUint, One, Zero};

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

        let a = (&x_2 + &z_2) % &p;
        let aa = &a * &a % &p;
        let b = (&p + &x_2 - &z_2) % &p;
        let bb = &b * &b % &p;
        let e = (&p + &aa - &bb) % &p;
        let c = (&x_3 + &z_3) % &p;
        let d = (&p + &x_3 - &z_3) % &p;
        let da = d * a % &p;
        let cb = c * b % &p;
        x_3 = (&da + &cb) % &p;
        x_3 = &x_3 * &x_3 % &p;
        z_3 = (&p + da - cb) % &p;
        z_3 = &x_1 * &z_3 * &z_3 % &p;
        x_2 = &aa * bb % &p;
        z_2 = &e * (aa + &a24 * &e) % &p;
    }
    cswap(&swap, &mut x_2, &mut x_3);
    cswap(&swap, &mut z_2, &mut z_3);
    (x_2 * pow(z_2, &p) % &p).to_bytes_le()
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
        if &exponent % &two == One::one() {
            res = res * &base % p;
        }
        exponent = exponent >> 1;
        base = &base * &base % p;
    }
    res
}

#[cfg(test)]
mod tests {
    use curve25519::*;
    use test_helpers::*;

    #[test]
    fn test_x_25519() {
        let k = h2b(
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        );
        let u = h2b(
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        );
        let x = h2b(
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
        );
        assert_eq!(x, x_25519(&k, &u));
    }
}
