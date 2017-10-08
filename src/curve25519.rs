use std::io;
use std::ops::{Add, BitAnd, BitXor, Div, Mul, Neg, Shr, Sub};
use std::str;
use num::cast::ToPrimitive;
use num::{BigUint, One, Zero};
use key;
use sha;

const BITS: usize = 255;
const BYTES: usize = (BITS + 7) / 8;
/// coding length for EdwardsPoint
const BASE: usize = 256;
/// highest set bit for EdwardsPoint
const N: usize = 254;
/// logarithm of cofactor for EdwardsPoint
const C: usize = 3;

lazy_static! {
    static ref P: BigUint = (BigUint::from(1u8) << BITS) - BigUint::from(19u8);
    static ref A24: Field = Field::new(121665u32.into());
    static ref D: Field = -&((&*A24) / &(&*A24 + &One::one()));
    static ref F0: Field = Zero::zero();
    static ref F1: Field = One::one();
    /// order of basepoint for EdwardsPoint
    static ref L: BigUint = hexi(
        "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"
    );
    static ref STD_BASE: EdwardsPoint = {
        let xb = hexi("216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A");
        let yb = hexi("6666666666666666666666666666666666666666666666666666666666666658");
        EdwardsPoint::new(&Field::new(xb), &Field::new(yb))
    };
}

/// After geting a shared secret, make sure to abort if it's 0
pub fn gen_pk(sk: &[u8]) -> Vec<u8> {
    let mut u = [0; 32];
    u[0] = 9;
    x25519(sk, &u)
}

/// This is horrible
/// and insecure
pub fn x25519(k: &[u8], u: &[u8]) -> Vec<u8> {
    assert_eq!(BYTES, k.len());
    assert_eq!(BYTES, u.len());
    let k = decode_scalar(k);
    let x_1 = decode_u_coordinate(u);
    let mut x_2 = One::one();
    let mut z_2 = Zero::zero();
    let mut x_3 = x_1.clone();
    let mut z_3 = One::one();
    let mut swap = Zero::zero();

    for t in (0..BITS).rev() {
        let k_t = &(&k >> t) & &One::one();
        swap = &swap ^ &k_t;
        cswap(&swap, &mut x_2, &mut x_3);
        cswap(&swap, &mut z_2, &mut z_3);
        swap = k_t;

        let a = &x_2 + &z_2;
        let aa = &a * &a;
        let b = &x_2 - &z_2;
        let bb = &b * &b;
        let e = &aa - &bb;
        let c = &x_3 + &z_3;
        let d = &x_3 - &z_3;
        let da = d * a;
        let cb = c * b;
        x_3 = &da + &cb;
        x_3 = &x_3 * &x_3;
        z_3 = &da - &cb;
        z_3 = &x_1 * &(&z_3 * &z_3);
        x_2 = &aa * &bb;
        z_2 = &e * &(aa + &*A24 * &e);
    }
    cswap(&swap, &mut x_2, &mut x_3);
    cswap(&swap, &mut z_2, &mut z_3);
    (&x_2 / &z_2).to_bytes()
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct Field {
    x: BigUint,
}


impl Field {
    fn new(x: BigUint) -> Self {
        Self { x: x % &*P }
    }

    fn inv(&self) -> Self {
        Self::new(pow(&self.x, &*P - BigUint::from(2u8), &*P))
    }

    fn sqrt(&self) -> Self {
        let y = Self::new(sqrt8k5(&self.x, &*P));
        assert_eq!(*self, &y * &y);
        y
    }

    fn sign(&self) -> u8 {
        (&self.x % BigUint::from(2u8)).to_u8().unwrap()
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        Field::new(
            BigUint::from_bytes_le(bytes) % (BigUint::from(1u8) << (BASE - 1)),
        )
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut x = self.x.to_bytes_le();
        while x.len() < BYTES {
            x.push(0);
        }
        x
    }
}

impl Add for Field {
    type Output = Field;

    fn add(self, rhs: Self) -> Self::Output {
        Self::new(self.x + rhs.x)
    }
}

impl Mul for Field {
    type Output = Field;

    fn mul(self, rhs: Self) -> Self::Output {
        Self::new(self.x * rhs.x)
    }
}

impl<'a, 'b> Add<&'a Field> for &'b Field {
    type Output = Field;

    fn add(self, rhs: &'a Field) -> Self::Output {
        Field::new(&self.x + &rhs.x)
    }
}

impl<'a, 'b> Sub<&'a Field> for &'b Field {
    type Output = Field;

    fn sub(self, rhs: &'a Field) -> Self::Output {
        Field::new(&*P + &self.x - &rhs.x)
    }
}

impl<'a, 'b> Mul<&'a Field> for &'b Field {
    type Output = Field;

    fn mul(self, rhs: &'a Field) -> Self::Output {
        Field::new(&self.x * &rhs.x)
    }
}

impl<'a, 'b> Div<&'a Field> for &'b Field {
    type Output = Field;

    fn div(self, rhs: &'a Field) -> Self::Output {
        self * &rhs.inv()
    }
}

impl<'a, 'b> BitAnd<&'a Field> for &'b Field {
    type Output = Field;

    fn bitand(self, rhs: &'a Field) -> Self::Output {
        Field::new(&self.x & &rhs.x)
    }
}

impl<'a, 'b> BitXor<&'a Field> for &'b Field {
    type Output = Field;

    fn bitxor(self, rhs: &'a Field) -> Self::Output {
        Field::new(&self.x ^ &rhs.x)
    }
}

impl<'a> Shr<usize> for &'a Field {
    type Output = Field;

    fn shr(self, rhs: usize) -> Self::Output {
        Field::new(&self.x >> rhs)
    }
}

impl<'a> Neg for &'a Field {
    type Output = Field;

    fn neg(self) -> Self::Output {
        Field::new(&*P - &self.x)
    }
}

impl One for Field {
    fn one() -> Self {
        Field::new(One::one())
    }
}

impl Zero for Field {
    fn zero() -> Self {
        Self::new(Zero::zero())
    }

    fn is_zero(&self) -> bool {
        self.x.is_zero()
    }
}

fn decode_u_coordinate(u: &[u8]) -> Field {
    let mut u_vec = u.to_vec();
    if BITS % 8 != 0 {
        if let Some(last) = u_vec.last_mut() {
            *last &= (1 << (BITS % 8)) - 1;
        }
    }
    Field::from_bytes(&u_vec)
}

fn decode_scalar(k: &[u8]) -> Field {
    let mut k_vec = k.to_vec();
    k_vec[0] &= 248;
    k_vec[31] &= 127;
    k_vec[31] |= 64;
    Field::from_bytes(&k_vec)
}

fn cswap(swap: &Field, x_2: &mut Field, x_3: &mut Field) {
    let dummy = Field::new(mask(&swap.x) & (&x_2.x ^ &x_3.x));
    *x_2 = &*x_2 ^ &dummy;
    *x_3 = &*x_3 ^ &dummy;
}

fn mask(swap: &BigUint) -> BigUint {
    (BigUint::from(1u8) << 255) - swap
}

fn pow(z: &BigUint, e: BigUint, p: &BigUint) -> BigUint {
    let zero = Zero::zero();
    let one: BigUint = One::one();
    let two: BigUint = 2u8.into();
    let mut res = One::one();
    let mut base = z.clone();
    let mut exponent = e;
    while exponent > zero {
        if &exponent % &two == one {
            res = res * &base % p;
        }
        exponent = exponent >> 1;
        base = &base * &base % p;
    }
    res
}

fn sqrt8k5(x: &BigUint, p: &BigUint) -> BigUint {
    let y = pow(x, (p + BigUint::from(3u8)) / BigUint::from(8u8), p);
    if &y * &y % p == x % p {
        y
    } else {
        let z = pow(
            &2u8.into(),
            (p - BigUint::from(1u8)) / BigUint::from(4u8),
            p,
        );
        y * z % p
    }
}

pub struct PureEDSA {}

// only supports BASE % 8 == 0
impl PureEDSA {
    pub fn key_gen() -> io::Result<([u8; BASE / 8], Vec<u8>)> {
        let priv_key: [u8; BASE / 8] = key::gen()?;
        Ok((priv_key, Self::pub_key_gen(&priv_key)))
    }

    pub fn pub_key_gen(priv_key: &[u8]) -> Vec<u8> {
        let khash = Self::h(&priv_key);
        let a = BigUint::from_bytes_le(&Self::clamp(&khash[..BASE / 8]));
        (&*STD_BASE * &a).encode()
    }

    pub fn sign(priv_key: &[u8], pub_key: &[u8], msg: &[u8]) -> Vec<u8> {
        let khash = Self::h(&priv_key);
        let a = BigUint::from_bytes_le(&Self::clamp(&khash[..BASE / 8]));
        let mut seed = khash[BASE / 8..].to_vec();
        seed.extend_from_slice(&msg);
        let r = BigUint::from_bytes_le(&Self::h(&seed)) % &*L;
        let mut r_vec = (&*STD_BASE * &r).encode();
        let mut r_ext = r_vec.clone();
        r_ext.extend_from_slice(&pub_key);
        r_ext.extend_from_slice(&msg);
        let h = BigUint::from_bytes_le(&Self::h(&r_ext)) % &*L;
        let mut s = ((r + h * a) % &*L).to_bytes_le();
        while s.len() < BASE / 8 {
            s.push(0);
        }
        r_vec.extend(s.iter());
        r_vec
    }

    pub fn verify(pub_key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        if sig.len() != BASE / 4 || pub_key.len() != BASE / 8 {
            return false;
        }
        let mut r_raw = sig[..BASE / 8].to_vec();
        let r = EdwardsPoint::decode(&r_raw);
        let s = BigUint::from_bytes_le(&sig[BASE / 8..]);
        let a = EdwardsPoint::decode(pub_key);
        // if r.is_err() or a.is_err() or s >= *L { return False; }
        r_raw.extend_from_slice(pub_key);
        r_raw.extend_from_slice(msg);
        let h = BigUint::from_bytes_le(&Self::h(&r_raw)) % &*L;
        let mut rhs = r + &a * &h;
        let mut lhs = &*STD_BASE * &s;
        for _ in 0..C {
            lhs.double();
            rhs.double();
        }
        lhs == rhs
    }

    fn clamp(a: &[u8]) -> Vec<u8> {
        let mut a = a.to_vec();
        for i in 0..C {
            a[i / 8] &= !(1 << (i % 8));
        }
        a[N / 8] |= 1 << (N % 8);
        for i in (N + 1)..BASE {
            a[i / 8] &= !(1 << (i % 8));
        }
        a
    }

    fn h(data: &[u8]) -> [u8; 64] {
        sha::SHA512::digest(&data)
    }
}

#[derive(Clone)]
struct EdwardsPoint {
    x: Field,
    y: Field,
    z: Field,
    t: Field,
}

impl EdwardsPoint {
    fn new(x: &Field, y: &Field) -> Self {
        Self {
            x: x.clone(),
            y: y.clone(),
            z: One::one(),
            t: x * y,
        }
    }

    fn decode(s: &[u8]) -> Self {
        assert_eq!(BASE / 8, s.len());
        let xs = s[(BASE - 1) / 8] >> ((BASE - 1) & 7);
        // check if < P before mod?
        let y = Field::from_bytes(s);
        let mut x = Self::solve_x2(&y).sqrt();
        assert!(!x.is_zero() || xs == x.sign());
        if x.sign() != xs {
            x = -&x;
        }
        Self::new(&x, &y)
    }

    fn encode(&self) -> Vec<u8> {
        let xp = &self.x / &self.z;
        let yp = &self.y / &self.z;
        let mut s = yp.to_bytes();
        if xp.sign() != 0 {
            s[(BASE - 1) / 8] |= 1 << (BASE - 1) % 8;
        }
        s
    }

    fn solve_x2(y: &Field) -> Field {
        &(&(y * y) - &*F1) / &(&(&*D * &(y * y)) + &*F1)
    }

    fn double(&mut self) {
        let a = &self.x * &self.x;
        let b = &self.y * &self.y;
        let ch = &self.z * &self.z;
        let c = &ch + &ch;
        let h = &a + &b;
        let xys = &self.x + &self.y;
        let e = &h - &(&xys * &xys);
        let g = &a - &b;
        let f = &c + &g;
        self.x = &e * &f;
        self.y = &g * &h;
        self.z = &f * &g;
        self.t = &e * &h;
    }
}

impl Add for EdwardsPoint {
    type Output = EdwardsPoint;

    fn add(self, rhs: EdwardsPoint) -> Self::Output {
        &self + &rhs
    }
}

impl<'a, 'b> Add<&'a EdwardsPoint> for &'b EdwardsPoint {
    type Output = EdwardsPoint;

    fn add(self, rhs: &'a EdwardsPoint) -> Self::Output {
        let zcp = &self.z * &rhs.z;
        let a = (&self.y - &self.x) * (&rhs.y - &rhs.x);
        let b = (&self.y + &self.x) * (&rhs.y + &rhs.x);
        let c = (&*D + &*D) * (&self.t * &rhs.t);
        let d = &zcp + &zcp;
        let e = &b - &a;
        let f = &d - &c;
        let g = d + c;
        let h = b + a;
        Self::Output {
            x: &e * &f,
            y: &g * &h,
            z: &f * &g,
            t: &e * &h,
        }
    }
}

impl<'a, 'b> Mul<&'a BigUint> for &'b EdwardsPoint {
    type Output = EdwardsPoint;

    fn mul(self, rhs: &'a BigUint) -> Self::Output {
        let zero = Zero::zero();
        let two = BigUint::from(2u8);
        let mut r = Zero::zero();
        let mut s = self.clone();
        let mut x = rhs.clone();
        while x > zero {
            if &x % &two > zero {
                r = &r + &s;
            }
            s.double();
            x = x / &two;
        }
        r
    }
}

impl PartialEq for EdwardsPoint {
    /// not constant time
    fn eq(&self, other: &Self) -> bool {
        let xn1 = &self.x * &other.z;
        let xn2 = &other.x * &self.z;
        let yn1 = &self.y * &other.z;
        let yn2 = &other.y * &self.z;
        xn1 == xn2 && yn1 == yn2
    }
}

impl Zero for EdwardsPoint {
    fn zero() -> Self {
        Self::new(&*F0, &*F1)
    }

    /// not constant time
    fn is_zero(&self) -> bool {
        self.x == *F0 && self.y == *F1
    }
}

// ew
fn hexi(s: &str) -> BigUint {
    let bytes: Vec<_> = s.as_bytes()
        .chunks(2)
        .map(|x| {
            u8::from_str_radix(str::from_utf8(x).unwrap(), 16).unwrap()
        })
        .collect();
    BigUint::from_bytes_be(&bytes)
}

#[cfg(test)]
mod tests {
    use curve25519::*;
    use test_helpers::*;

    impl EdwardsPoint {
        fn is_valid_point(&self) {
            let x = self.x.clone();
            let y = self.y.clone();
            let z = self.z.clone();
            let t = self.t.clone();
            let x2 = &x * &x;
            let y2 = &y * &y;
            let z2 = &z * &z;
            let lhs = &(&y2 - &x2) * &z2;
            let rhs = &z2 * &z2 + &*D * &(x2 * y2);
            assert_eq!(lhs, rhs);
            assert_eq!(&t * &z, &x * &y);
        }
    }

    fn curve_self_check(point: &EdwardsPoint) {
        let one: BigUint = One::one();
        let mut p = point.clone();
        let mut q: EdwardsPoint = Zero::zero();
        let z = q.clone();
        let l: BigUint = &*L + &one;
        p.is_valid_point();
        q.is_valid_point();
        for i in 0..BASE {
            if &l >> i & &one != Zero::zero() {
                q = &q + &p;
                q.is_valid_point();
            }
            p.double();
            p.is_valid_point()
        }
        assert_eq!(q.encode(), point.encode());
        assert_ne!(q.encode(), p.encode());
        assert_ne!(q.encode(), z.encode());
    }

    fn check(x: &str, k: &str, u: &str) {
        assert_eq!(h2b(x), x25519(&h2b(k), &h2b(u)));
    }

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

    #[test]
    fn test_self_check_curves() {
        curve_self_check(&*STD_BASE);
    }

    #[test]
    fn test_edsa() {
        let sk = h2b(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        );
        let pk = h2b(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        );
        let msg = [];
        let sig = h2b(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        );
        assert_eq!(sig, PureEDSA::sign(&sk, &pk, &msg));
        assert!(PureEDSA::verify(&pk, &msg, &sig));

        let sk = h2b(
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        );
        let pk = h2b(
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        );
        let msg = [0x72];
        let sig = h2b(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
             085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        );
        assert_eq!(sig, PureEDSA::sign(&sk, &pk, &msg));
        assert!(PureEDSA::verify(&pk, &msg, &sig));
    }
}
