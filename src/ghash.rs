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
        let mut block = GFBlock([0; 2]);
        BigEndian::read_u64_into(bytes, &mut block.0);
        block
    }
}

impl From<GFBlock> for [u8; 16] {
    fn from(block: GFBlock) -> Self {
        let mut bytes = [0; 16];
        BigEndian::write_u64_into(&block.0, &mut bytes);
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
        for xp in &mut self.0 {
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
    use test_helpers::*;

    #[test]
    fn test_case_1_2() {
        let h = h2b("66e94bd4ef8a2c3b884cfa59ca342b2e");
        assert_eq!([0; 16], h_xpoly(&h, &[0; 16]));
        assert_eq!([0; 16], ghash(&h, &[], &[]));

        let c = h2b("0388dace60b6a392f328c2b971b2fe78");
        let mut bytes = [0; 32];
        bytes[..16].copy_from_slice(&c);
        bytes[31] = 0x80;
        let expected = h2b("f38cbb1ad69223dcc3457ae5b6b0f885");
        assert_eq!(expected, h_xpoly(&h, &bytes));
        assert_eq!(expected, ghash(&h, &[], &c));
    }

    #[test]
    fn test_case_15_16_17_18() {
        let h = h2b("acbef20579b4b8ebce889bac8732dad7");

        let mut c = h2b(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
             8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
        );
        let mut bytes = [0; 80];
        bytes[..64].copy_from_slice(&c);
        bytes[78] = 0x02;
        let mut expected = h2b("4db870d37cb75fcb46097c36230d1612");
        assert_eq!(expected, h_xpoly(&h, &bytes));
        assert_eq!(expected, ghash(&h, &[], &c));

        let mut bytes = [0; 112];
        let a = h2b("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        bytes[..20].copy_from_slice(&a);
        bytes[32..92].copy_from_slice(&c[..60]);
        bytes[103] = 0xa0;
        bytes[110..].copy_from_slice(&[0x01, 0xe0]);
        expected = h2b("8bd0c4d8aacd391e67cca447e8c38f65");
        assert_eq!(expected, h_xpoly(&h, &bytes));
        assert_eq!(expected, ghash(&h, &a, &c[..60]));

        c = h2b(
            "c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0\
             feb582d33934a4f0954cc2363bc73f7862ac430e64abe499f47c9b1f",
        );
        bytes[32..92].copy_from_slice(&c);
        expected = h2b("75a34288b8c68f811c52b2e9a2f97f63");
        assert_eq!(expected, h_xpoly(&h, &bytes));
        assert_eq!(expected, ghash(&h, &a, &c));

        c = h2b(
            "5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf4\
             0fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f",
        );
        bytes[32..92].copy_from_slice(&c);
        expected = h2b("d5ffcf6fc5ac4d69722187421a7f170b");
        assert_eq!(expected, h_xpoly(&h, &bytes));
        assert_eq!(expected, ghash(&h, &a, &c));
    }
}
