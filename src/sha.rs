use std::iter;
use byteorder::{BigEndian, ByteOrder};

pub const K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

pub struct SHA512 {}

impl SHA512 {
    pub fn digest(message: &[u8]) -> [u8; 64] {
        let mut sha = SHA(
            [
                0x6a09e667f3bcc908,
                0xbb67ae8584caa73b,
                0x3c6ef372fe94f82b,
                0xa54ff53a5f1d36f1,
                0x510e527fade682d1,
                0x9b05688c2b3e6c1f,
                0x1f83d9abfb41bd6b,
                0x5be0cd19137e2179,
            ],
        );
        sha.process(message);
        sha.digest()
    }
}

struct SHA([u64; 8]);

impl SHA {
    fn process(&mut self, message: &[u8]) {
        let mut message = message.to_vec();
        Self::pad(&mut message);
        let mut w = [0; 80];
        for chunk in message.chunks(128) {
            for (wt, long) in w.iter_mut().zip(chunk.chunks(8)) {
                *wt = BigEndian::read_u64(long);
            }
            for t in 16..80 {
                w[t] = Self::ssig1(w[t - 2])
                    .wrapping_add(w[t - 7])
                    .wrapping_add(Self::ssig0(w[t - 15]))
                    .wrapping_add(w[t - 16]);
            }
            let mut a = self.0[0];
            let mut b = self.0[1];
            let mut c = self.0[2];
            let mut d = self.0[3];
            let mut e = self.0[4];
            let mut f = self.0[5];
            let mut g = self.0[6];
            let mut h = self.0[7];
            for (&kt, &wt) in K.iter().zip(w.iter()) {
                let t1 = h.wrapping_add(Self::bsig1(e))
                    .wrapping_add(Self::ch(e, f, g))
                    .wrapping_add(kt)
                    .wrapping_add(wt);
                let t2 = Self::bsig0(a).wrapping_add(Self::maj(a, b, c));
                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(t1);
                d = c;
                c = b;
                b = a;
                a = t1.wrapping_add(t2);
            }
            self.0[0] = self.0[0].wrapping_add(a);
            self.0[1] = self.0[1].wrapping_add(b);
            self.0[2] = self.0[2].wrapping_add(c);
            self.0[3] = self.0[3].wrapping_add(d);
            self.0[4] = self.0[4].wrapping_add(e);
            self.0[5] = self.0[5].wrapping_add(f);
            self.0[6] = self.0[6].wrapping_add(g);
            self.0[7] = self.0[7].wrapping_add(h);
        }
    }

    fn digest(self) -> [u8; 64] {
        let mut digest = [0; 64];
        for (chunk, &long) in digest.chunks_mut(8).zip(&self.0) {
            BigEndian::write_u64(chunk, long);
        }
        digest
    }
    fn ch(x: u64, y: u64, z: u64) -> u64 {
        (x & y) ^ (!x & z)
    }

    fn maj(x: u64, y: u64, z: u64) -> u64 {
        (x & y) ^ (x & z) ^ (y & z)
    }

    fn bsig0(x: u64) -> u64 {
        x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
    }

    fn bsig1(x: u64) -> u64 {
        x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
    }

    fn ssig0(x: u64) -> u64 {
        x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
    }

    fn ssig1(x: u64) -> u64 {
        x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
    }

    /// Only supports messages with at most 2^64 - 1 bits for now
    fn pad(bytes: &mut Vec<u8>) {
        let len = len(bytes);
        bytes.push(0x80);
        let padding = (128 + 112 - bytes.len() % 128) % 128;
        bytes.extend(iter::repeat(0).take(padding));
        bytes.extend_from_slice(&[0; 8]);
        bytes.extend_from_slice(&len);
    }
}

fn len(bytes: &[u8]) -> [u8; 8] {
    let mut len = [0; 8];
    BigEndian::write_u64(&mut len, 8 * bytes.len() as u64);
    len
}

#[cfg(test)]
mod tests {
    use sha::*;
    use test_helpers::*;

    #[test]
    fn test_pad() {
        let mut message = vec![0b01100001, 0b01100010, 0b01100011, 0b01100100, 0b01100101];
        let expected = h2b(
            "6162636465800000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000028",
        );
        SHA::pad(&mut message);
        assert_eq!(expected, message);
    }

    #[test]
    fn test_digest() {
        let expected = h2b(
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
             47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        );
        let actual = SHA512::digest(&[]);
        assert_eq!(64, actual.len());
        for (lhs, rhs) in expected.iter().zip(actual.iter()) {
            assert_eq!(lhs, rhs);
        }
    }
}
