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

pub struct PureEDSA {}

// only supports BASE % 8 == 0
impl PureEDSA {
    pub fn key_gen() -> io::Result<([u8; BASE / 8], Vec<u8>)> {
        let priv_key: [u8; BASE / 8] = key::gen()?;
        Ok((priv_key, Self::pub_key_gen(&priv_key)))
    }

    pub fn pub_key_gen(priv_key: &[u8]) -> Vec<u8> {
        let khash = Self::h(priv_key);
        let a = BigUint::from_bytes_le(&Self::clamp(&khash[..BASE / 8]));
        (&*STD_BASE * &a).encode()
    }

    pub fn sign(priv_key: &[u8], pub_key: &[u8], msg: &[u8]) -> Vec<u8> {
        let khash = Self::h(priv_key);
        let a = BigUint::from_bytes_le(&Self::clamp(&khash[..BASE / 8]));
        let mut seed = khash[BASE / 8..].to_vec();
        seed.extend_from_slice(msg);
        let r = BigUint::from_bytes_le(&Self::h(&seed)) % &*L;
        let mut r_vec = (&*STD_BASE * &r).encode();
        let mut r_ext = r_vec.clone();
        r_ext.extend_from_slice(pub_key);
        r_ext.extend_from_slice(msg);
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
        for _ in 0..EdwardsPoint::C {
            lhs.double();
            rhs.double();
        }
        lhs == rhs
    }

    fn clamp(a: &[u8]) -> Vec<u8> {
        let mut a = a.to_vec();
        for i in 0..EdwardsPoint::C {
            a[i / 8] &= !(1 << (i % 8));
        }
        a[EdwardsPoint::N / 8] |= 1 << (EdwardsPoint::N % 8);
        for i in (EdwardsPoint::N + 1)..BASE {
            a[i / 8] &= !(1 << (i % 8));
        }
        a
    }

    fn h(data: &[u8]) -> [u8; 64] {
        sha::SHA512::digest(data)
    }
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

#[derive(Clone)]
struct EdwardsPoint {
    x: Field,
    y: Field,
    z: Field,
    t: Field,
}

impl EdwardsPoint {
    /// highest set bit
    const N: usize = 254;
    /// logarithm of cofactor
    const C: usize = 3;

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

    fn check_edsa(sk: &str, pk: &str, msg: &str, sig: &str) {
        let sk = h2b(sk);
        let pk = h2b(pk);
        let msg = h2b(msg);
        let sig = h2b(sig);
        assert_eq!(sig, PureEDSA::sign(&sk, &pk, &msg));
        assert!(PureEDSA::verify(&pk, &msg, &sig));
        // TODO: check that a bad signature causes verification to fail
    }

    #[test]
    fn test_edsa() {
        let mut sk = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        let mut pk = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let mut msg = "";
        let mut sig = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
                       5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
        check_edsa(sk, pk, msg, sig);

        sk = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
        pk = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
        msg = "72";
        sig = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
               085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";
        check_edsa(sk, pk, msg, sig);

        sk = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7";
        pk = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";
        msg = "af82";
        sig = "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac\
               18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a";
        check_edsa(sk, pk, msg, sig);

        sk = "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5";
        pk = "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e";
        msg = "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98\
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
        sig = "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350\
               aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03";
        check_edsa(sk, pk, msg, sig);

        sk = "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42";
        pk = "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf";
        msg = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
               2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
        sig = "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589\
               09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704";
        check_edsa(sk, pk, msg, sig);
    }
}
