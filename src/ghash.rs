use core::ops::{BitXorAssign, MulAssign};
use byteorder::{BigEndian, ByteOrder};

pub(crate) fn ghash(key: &[u8; 16], data: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut digest = [0; 16];
    let mut mac = GHash::new(key, data);
    mac.update(ciphertext);
    mac.write_digest(&mut digest);
    digest
}

const R0: u64 = 0xe1 << 56;

struct GHash(PolyFunction);

impl GHash {
    fn new(key: &[u8; 16], data: &[u8]) -> Self {
        let mut poly_function = PolyFunction::new(key);
        poly_function.update(data);
        poly_function.data_len = data.len() as u64;
        GHash(poly_function)
    }

    fn update(&mut self, input: &[u8]) {
        self.0.update(input);
        self.0.ciphertext_len += input.len() as u64;
    }

    fn write_digest(self, output: &mut [u8]) {
        self.0.write_digest(output);
    }
}

#[derive(Clone, Copy)]
struct GFBlock([u64; 2]);

struct PolyFunction {
    key_block: GFBlock,
    state: GFBlock,
    data_len: u64,
    ciphertext_len: u64,
}

impl PolyFunction {
    fn new(key: &[u8; 16]) -> Self {
        Self {
            key_block: GFBlock::new(key),
            state: GFBlock([0; 2]),
            data_len: 0,
            ciphertext_len: 0,
        }
    }

    fn write_digest(mut self, output: &mut [u8]) {
        assert_eq!(16, output.len());
        let buffer = &mut [0; 16];
        BigEndian::write_u64(&mut buffer[..8], 8 * self.data_len);
        BigEndian::write_u64(&mut buffer[8..], 8 * self.ciphertext_len);
        self.process(buffer);
        let state: [u8; 16] = self.state.into();
        output.copy_from_slice(&state)
    }

    fn update(&mut self, input: &[u8]) {
        for chunk in input.chunks(16) {
            if chunk.len() < 16 {
                let buffer = &mut [0; 16];
                buffer[..chunk.len()].copy_from_slice(chunk);
                self.process(buffer);
            } else {
                self.process(chunk);
            }
        }
    }

    fn process(&mut self, input: &[u8]) {
        self.state ^= GFBlock::new(input);
        self.state *= self.key_block;
    }
}

impl GFBlock {
    fn new(bytes: &[u8]) -> Self {
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
        for (l, &r) in self.0.iter_mut().zip(rhs.0.iter()) {
            *l ^= r;
        }
    }
}

impl MulAssign for GFBlock {
    fn mul_assign(&mut self, rhs: Self) {
        let mut z = GFBlock([0; 2]);
        let mut v = rhs;
        for xp in &mut self.0 {
            for _ in 0..64 {
                let mut h = *xp & (1 << 63);
                let mut m = (h as i64 >> 63) as u64;
                for (l, &r) in z.0.iter_mut().zip(v.0.iter()) {
                    *l ^= r & m;
                }

                h = v.0[1] << 63;
                m = (h as i64 >> 7) as u64;
                v.0[1] >>= 1;
                v.0[1] |= v.0[0] << 63;
                v.0[0] >>= 1;
                v.0[0] ^= R0 & m;
                *xp <<= 1;
            }
        }
        self.0 = z.0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_helpers::*;

    #[test]
    fn test_case_1_2() {
        let h = &mut [0; 16];
        h.copy_from_slice(&h2b("66e94bd4ef8a2c3b884cfa59ca342b2e"));
        assert_eq!([0; 16], ghash(h, &[], &[]));

        let c = &h2b("0388dace60b6a392f328c2b971b2fe78");
        let expected = h2b("f38cbb1ad69223dcc3457ae5b6b0f885");
        assert_eq!(expected, ghash(h, &[], c));
    }

    #[test]
    fn test_case_15_16_17_18() {
        let h = &mut [0; 16];
        h.copy_from_slice(&h2b("acbef20579b4b8ebce889bac8732dad7"));

        let c = &h2b(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
             8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
        );
        let expected = h2b("4db870d37cb75fcb46097c36230d1612");
        assert_eq!(expected, ghash(h, &[], c));

        let a = &h2b("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let c = &c[..60];
        let expected = h2b("8bd0c4d8aacd391e67cca447e8c38f65");
        assert_eq!(expected, ghash(h, a, c));

        let c = &h2b(
            "c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0\
             feb582d33934a4f0954cc2363bc73f7862ac430e64abe499f47c9b1f",
        );
        let expected = h2b("75a34288b8c68f811c52b2e9a2f97f63");
        assert_eq!(expected, ghash(h, a, c));

        let c = &h2b(
            "5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf4\
             0fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f",
        );
        let expected = h2b("d5ffcf6fc5ac4d69722187421a7f170b");
        assert_eq!(expected, ghash(h, a, c));
    }
}
