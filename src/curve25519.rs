use num::{BigUint, One, Zero};

const BITS: usize = 255;
const A24: u32 = 121665;

pub fn gen_pk(sk: &[u8]) -> Vec<u8> {
    let mut u = [0; 32];
    u[0] = 9;
    x25519(sk, &u)
}

/// This is horrible
/// and insecure
pub fn x25519(k: &[u8], u: &[u8]) -> Vec<u8> {
    let len = (BITS + 7) / 8;
    assert_eq!(32, k.len());
    assert_eq!(len, u.len());
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
    let mut x = (x_2 * pow(z_2, &p) % &p).to_bytes_le();
    while x.len() < len {
        x.push(0);
    }
    x
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

    fn check(x: &str, k: &str, u: &str) {
        assert_eq!(h2b(x), x25519(&h2b(k), &h2b(u)));
    }

    fn check_decode(k: &str, u: &str, k10: &str, u10: &str) {
        assert_eq!(
            BigUint::parse_bytes(k10.as_bytes(), 10).unwrap(),
            decode_scalar(&h2b(k))
        );
        assert_eq!(
            BigUint::parse_bytes(u10.as_bytes(), 10).unwrap(),
            decode_u_coordinate(&h2b(u))
        );
    }

    #[test]
    fn test_x25519() {
        let mut k = "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4";
        let mut u = "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c";
        let mut x = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552";
        check(x, k, u);

        let mut k10;
        let mut u10;
        k10 = "31029842492115040904895560451863089656472772604678260265531221036453811406496";
        u10 = "34426434033919594451155107781188821651316167215306631574996226621102155684838";
        check_decode(k, u, k10, u10);

        k = "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d";
        u = "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493";
        x = "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957";
        check(x, k, u);

        k10 = "35156891815674817266734212754503633747128614016119564763269015315466259359304";
        u10 = "8883857351183929894090759386610649319417338800022198945255395922347792736741";
        check_decode(k, u, k10, u10);

        let mut k = h2b(
            "0900000000000000000000000000000000000000000000000000000000000000",
        );
        let mut u = k.clone();
        // too slow to do 1 mil iterations right now, or 1000 without --release
        for i in 0..1 {
            let x = x25519(&k, &u);
            if i == 0 {
                assert_eq!(
                    h2b(
                        "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
                    ),
                    x
                );
            } else if i == 999 {
                assert_eq!(
                    h2b(
                        "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
                    ),
                    x
                );
            } else if i == 999999 {
                assert_eq!(
                    h2b(
                        "7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424",
                    ),
                    x
                );
            }
            u = k;
            k = x;
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
