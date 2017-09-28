use std::iter;
use std::ops::{BitXorAssign, MulAssign, ShrAssign};
use byteorder::{BigEndian, ByteOrder};

const R: GFBlock = GFBlock([0xe1 << 56, 0]);

#[derive(Clone, Copy)]
struct GFBlock([u64; 2]);

pub fn ghash(key: &[u8], data: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut bytes = data.to_vec();
    pad(&mut bytes);
    bytes.extend_from_slice(ciphertext);
    pad(&mut bytes);
    bytes.extend_from_slice(&len(data));
    bytes.extend_from_slice(&len(ciphertext));
    h_xpoly(key, &bytes)
}

fn h_xpoly(key: &[u8], bytes: &[u8]) -> [u8; 16] {
    let h = GFBlock::new(key);
    let mut y = GFBlock([0; 2]);
    for chunk in bytes.chunks(16) {
        y ^= GFBlock::new(chunk);
        y *= h;
    }
    y.into()
}

fn pad(bytes: &mut Vec<u8>) {
    let padding = (16 - bytes.len() % 16) % 16;
    bytes.extend(iter::repeat(0).take(padding));
}

fn len(bytes: &[u8]) -> [u8; 8] {
    let mut len = [0; 8];
    BigEndian::write_u64(&mut len, 8 * bytes.len() as u64);
    len
}

impl GFBlock {
    fn new(bytes: &[u8]) -> Self {
        assert_eq!(16, bytes.len());
        let mut longs = [0; 2];
        for (long, chunk) in longs.iter_mut().zip(bytes.chunks(8)) {
            *long = BigEndian::read_u64(chunk);
        }
        GFBlock(longs)
    }
}

impl From<GFBlock> for [u8; 16] {
    fn from(block: GFBlock) -> Self {
        let mut bytes = [0; 16];
        for (chunk, &long) in bytes.chunks_mut(8).zip(&block.0) {
            BigEndian::write_u64(chunk, long);
        }
        bytes
    }
}

impl BitXorAssign for GFBlock {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.0[0] ^= rhs.0[0];
        self.0[1] ^= rhs.0[1];
    }
}

impl MulAssign for GFBlock {
    fn mul_assign(&mut self, rhs: Self) {
        let mut z = GFBlock([0; 2]);
        let mut v = rhs;
        for xp in self.0.iter_mut() {
            for _ in 0..64 {
                if *xp & (1 << 63) != 0 {
                    z ^= v;
                }
                *xp <<= 1;
                let h = v.0[1] & 1;
                v >>= 1;
                if h == 1 {
                    v ^= R;
                }
            }
        }
        self.0 = z.0;
    }
}

impl ShrAssign<usize> for GFBlock {
    fn shr_assign(&mut self, rhs: usize) {
        if rhs < 64 {
            self.0[1] >>= rhs;
            self.0[1] |= self.0[0] << (64 - rhs);
            self.0[0] >>= rhs;
        } else {
            self.0[1] = self.0[0] >> (rhs - 64);
            self.0[0] = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use ghash::*;

    #[test]
    fn test_ghash() {
        let h = [
            0x66,
            0xe9,
            0x4b,
            0xd4,
            0xef,
            0x8a,
            0x2c,
            0x3b,
            0x88,
            0x4c,
            0xfa,
            0x59,
            0xca,
            0x34,
            0x2b,
            0x2e,
        ];
        assert_eq!([0; 16], h_xpoly(&h, &[0; 16]));
        assert_eq!([0; 16], ghash(&h, &[], &[]));

        let c = [
            0x03,
            0x88,
            0xda,
            0xce,
            0x60,
            0xb6,
            0xa3,
            0x92,
            0xf3,
            0x28,
            0xc2,
            0xb9,
            0x71,
            0xb2,
            0xfe,
            0x78,
        ];
        let mut bytes = [0; 32];
        bytes[..16].copy_from_slice(&c);
        bytes[31] = 0x80;
        let expected = [
            0xf3,
            0x8c,
            0xbb,
            0x1a,
            0xd6,
            0x92,
            0x23,
            0xdc,
            0xc3,
            0x45,
            0x7a,
            0xe5,
            0xb6,
            0xb0,
            0xf8,
            0x85,
        ];
        assert_eq!(expected, h_xpoly(&h, &bytes));
        assert_eq!(expected, ghash(&h, &[], &c));
    }
}
