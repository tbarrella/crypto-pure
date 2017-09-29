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
    fn test_case_1_2() {
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

    #[test]
    fn test_case_15_16_17_18() {
        let h = [
            0xac,
            0xbe,
            0xf2,
            0x05,
            0x79,
            0xb4,
            0xb8,
            0xeb,
            0xce,
            0x88,
            0x9b,
            0xac,
            0x87,
            0x32,
            0xda,
            0xd7,
        ];

        let c = [
            0x52,
            0x2d,
            0xc1,
            0xf0,
            0x99,
            0x56,
            0x7d,
            0x07,
            0xf4,
            0x7f,
            0x37,
            0xa3,
            0x2a,
            0x84,
            0x42,
            0x7d,
            0x64,
            0x3a,
            0x8c,
            0xdc,
            0xbf,
            0xe5,
            0xc0,
            0xc9,
            0x75,
            0x98,
            0xa2,
            0xbd,
            0x25,
            0x55,
            0xd1,
            0xaa,
            0x8c,
            0xb0,
            0x8e,
            0x48,
            0x59,
            0x0d,
            0xbb,
            0x3d,
            0xa7,
            0xb0,
            0x8b,
            0x10,
            0x56,
            0x82,
            0x88,
            0x38,
            0xc5,
            0xf6,
            0x1e,
            0x63,
            0x93,
            0xba,
            0x7a,
            0x0a,
            0xbc,
            0xc9,
            0xf6,
            0x62,
            0x89,
            0x80,
            0x15,
            0xad,
        ];
        let mut bytes = [0; 80];
        bytes[..64].copy_from_slice(&c);
        bytes[78] = 0x02;
        let expected = [
            0x4d,
            0xb8,
            0x70,
            0xd3,
            0x7c,
            0xb7,
            0x5f,
            0xcb,
            0x46,
            0x09,
            0x7c,
            0x36,
            0x23,
            0x0d,
            0x16,
            0x12,
        ];
        assert_eq!(expected, h_xpoly(&h, &bytes));
        assert_eq!(expected, ghash(&h, &[], &c));

        let mut bytes = [0; 112];
        let a = [
            0xfe,
            0xed,
            0xfa,
            0xce,
            0xde,
            0xad,
            0xbe,
            0xef,
            0xfe,
            0xed,
            0xfa,
            0xce,
            0xde,
            0xad,
            0xbe,
            0xef,
            0xab,
            0xad,
            0xda,
            0xd2,
        ];
        bytes[..20].copy_from_slice(&a);
        bytes[32..92].copy_from_slice(&c[..60]);
        bytes[103] = 0xa0;
        bytes[110..].copy_from_slice(&[0x01, 0xe0]);
        let expected = [
            0x8b,
            0xd0,
            0xc4,
            0xd8,
            0xaa,
            0xcd,
            0x39,
            0x1e,
            0x67,
            0xcc,
            0xa4,
            0x47,
            0xe8,
            0xc3,
            0x8f,
            0x65,
        ];
        assert_eq!(expected, h_xpoly(&h, &bytes));
        assert_eq!(expected, ghash(&h, &a, &c[..60]));

        let c = [
            0xc3,
            0x76,
            0x2d,
            0xf1,
            0xca,
            0x78,
            0x7d,
            0x32,
            0xae,
            0x47,
            0xc1,
            0x3b,
            0xf1,
            0x98,
            0x44,
            0xcb,
            0xaf,
            0x1a,
            0xe1,
            0x4d,
            0x0b,
            0x97,
            0x6a,
            0xfa,
            0xc5,
            0x2f,
            0xf7,
            0xd7,
            0x9b,
            0xba,
            0x9d,
            0xe0,
            0xfe,
            0xb5,
            0x82,
            0xd3,
            0x39,
            0x34,
            0xa4,
            0xf0,
            0x95,
            0x4c,
            0xc2,
            0x36,
            0x3b,
            0xc7,
            0x3f,
            0x78,
            0x62,
            0xac,
            0x43,
            0x0e,
            0x64,
            0xab,
            0xe4,
            0x99,
            0xf4,
            0x7c,
            0x9b,
            0x1f,
        ];
        bytes[32..92].copy_from_slice(&c);
        let expected = [
            0x75,
            0xa3,
            0x42,
            0x88,
            0xb8,
            0xc6,
            0x8f,
            0x81,
            0x1c,
            0x52,
            0xb2,
            0xe9,
            0xa2,
            0xf9,
            0x7f,
            0x63,
        ];
        assert_eq!(expected, h_xpoly(&h, &bytes));
        assert_eq!(expected, ghash(&h, &a, &c));

        let c = [
            0x5a,
            0x8d,
            0xef,
            0x2f,
            0x0c,
            0x9e,
            0x53,
            0xf1,
            0xf7,
            0x5d,
            0x78,
            0x53,
            0x65,
            0x9e,
            0x2a,
            0x20,
            0xee,
            0xb2,
            0xb2,
            0x2a,
            0xaf,
            0xde,
            0x64,
            0x19,
            0xa0,
            0x58,
            0xab,
            0x4f,
            0x6f,
            0x74,
            0x6b,
            0xf4,
            0x0f,
            0xc0,
            0xc3,
            0xb7,
            0x80,
            0xf2,
            0x44,
            0x45,
            0x2d,
            0xa3,
            0xeb,
            0xf1,
            0xc5,
            0xd8,
            0x2c,
            0xde,
            0xa2,
            0x41,
            0x89,
            0x97,
            0x20,
            0x0e,
            0xf8,
            0x2e,
            0x44,
            0xae,
            0x7e,
            0x3f,
        ];
        bytes[32..92].copy_from_slice(&c);
        let expected = [
            0xd5,
            0xff,
            0xcf,
            0x6f,
            0xc5,
            0xac,
            0x4d,
            0x69,
            0x72,
            0x21,
            0x87,
            0x42,
            0x1a,
            0x7f,
            0x17,
            0x0b,
        ];
        assert_eq!(expected, h_xpoly(&h, &bytes));
        assert_eq!(expected, ghash(&h, &a, &c));
    }
}
