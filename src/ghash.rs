use byteorder::{BigEndian, ByteOrder};

pub(crate) fn ghash(key: &[u8; 16], data: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut tag = [0; 16];
    let mut mac = GHash::new(key, data);
    mac.update(ciphertext);
    mac.write_tag(&mut tag);
    tag
}

const R0: u128 = 0xe1 << 120;

struct GHash {
    function: PolyFunction,
    data_len: u64,
    ciphertext_len: u64,
}

impl GHash {
    fn new(key: &[u8; 16], data: &[u8]) -> Self {
        let mut ghash = Self {
            function: PolyFunction::new(key),
            data_len: data.len() as u64,
            ciphertext_len: 0,
        };
        ghash.process(data);
        ghash
    }

    fn update(&mut self, input: &[u8]) {
        self.ciphertext_len += input.len() as u64;
        self.process(input);
    }

    fn write_tag(mut self, output: &mut [u8; 16]) {
        BigEndian::write_u64(&mut output[..8], 8 * self.data_len);
        BigEndian::write_u64(&mut output[8..], 8 * self.ciphertext_len);
        self.function.process(output);
        self.function.write_value(output);
    }

    fn process(&mut self, input: &[u8]) {
        for chunk in input.chunks(16) {
            if chunk.len() < 16 {
                let buffer = &mut [0; 16];
                buffer[..chunk.len()].copy_from_slice(chunk);
                self.function.process(buffer);
            } else {
                self.function.process(chunk);
            }
        }
    }
}

type GFBlock = u128;

struct PolyFunction {
    key_block: GFBlock,
    state: GFBlock,
}

impl PolyFunction {
    fn new(key: &[u8; 16]) -> Self {
        Self {
            key_block: BigEndian::read_u128(key),
            state: 0,
        }
    }

    fn process(&mut self, input: &[u8]) {
        self.state ^= BigEndian::read_u128(input);

        let mut x = self.state;
        let mut v = self.key_block;
        self.state = 0;
        for _ in 0..128 {
            let mut h = x & (1 << 127);
            let mut m = (h as i128 >> 127) as u128;
            self.state ^= v & m;
            h = v << 127;
            m = (h as i128 >> 127) as u128;
            v >>= 1;
            v ^= R0 & m;
            x <<= 1;
        }
    }

    fn write_value(self, output: &mut [u8; 16]) {
        BigEndian::write_u128(output, self.state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_helpers::*;

    fn check(expected: &str, h: &str, a: &str, c: &str) {
        let h_vec = &h2b(h);
        let h = &mut [0; 16];
        h.copy_from_slice(h_vec);
        let a = &h2b(a);
        let c = &h2b(c);
        let expected = h2b(expected);
        assert_eq!(expected, ghash(h, a, c));
    }

    #[test]
    fn test_case_1_2() {
        let h = "66e94bd4ef8a2c3b884cfa59ca342b2e";
        let a = "";
        let c = "";
        let expected = "00000000000000000000000000000000";
        check(expected, h, a, c);

        let c = "0388dace60b6a392f328c2b971b2fe78";
        let expected = "f38cbb1ad69223dcc3457ae5b6b0f885";
        check(expected, h, a, c);
    }

    #[test]
    fn test_case_3_4_5_6() {
        let h = "b83b533708bf535d0aa6e52980d53b78";
        let a = "";
        let c = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
                 21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985";
        let expected = "7f1b32b81b820d02614f8895ac1d4eac";
        check(expected, h, a, c);

        let a = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
        let c = &c[..120];
        let expected = "698e57f70e6ecc7fd9463b7260a9ae5f";
        check(expected, h, a, c);

        let c = "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c7423\
                 73806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598";
        let expected = "df586bb4c249b92cb6922877e444d37b";
        check(expected, h, a, c);

        let c = "8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca7\
                 01e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5";
        let expected = "1c5afe9760d3932f3c9a878aac3dc3de";
        check(expected, h, a, c);
    }

    #[test]
    fn test_case_7_8() {
        let h = "aae06992acbf52a3e8f4a96ec9300bd7";
        let a = "";
        let c = "";
        let expected = "00000000000000000000000000000000";
        check(expected, h, a, c);

        let c = "98e7247c07f0fe411c267e4384b0f600";
        let expected = "e2c63f0ac44ad0e02efa05ab6743d4ce";
        check(expected, h, a, c);
    }

    #[test]
    fn test_case_9_10_11_12() {
        let h = "466923ec9ae682214f2c082badb39249";
        let a = "";
        let c = "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c\
                 7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710acade256";
        let expected = "51110d40f6c8fff0eb1ae33445a889f0";
        check(expected, h, a, c);

        let a = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
        let c = &c[..120];
        let expected = "ed2ce3062e4a8ec06db8b4c490e8a268";
        check(expected, h, a, c);

        let c = "0f10f599ae14a154ed24b36e25324db8c566632ef2bbb34f8347280fc4507057\
                 fddc29df9a471f75c66541d4d4dad1c9e93a19a58e8b473fa0f062f7";
        let expected = "1e6a133806607858ee80eaf237064089";
        check(expected, h, a, c);

        let c = "d27e88681ce3243c4830165a8fdcf9ff1de9a1d8e6b447ef6ef7b79828666e45\
                 81e79012af34ddd9e2f037589b292db3e67c036745fa22e7e9b7373b";
        let expected = "82567fb0b4cc371801eadec005968e94";
        check(expected, h, a, c);
    }

    #[test]
    fn test_case_13_14() {
        let h = "dc95c078a2408989ad48a21492842087";
        let a = "";
        let c = "";
        let expected = "00000000000000000000000000000000";
        check(expected, h, a, c);

        let c = "cea7403d4d606b6e074ec5d3baf39d18";
        let expected = "83de425c5edc5d498f382c441041ca92";
        check(expected, h, a, c);
    }

    #[test]
    fn test_case_15_16_17_18() {
        let h = "acbef20579b4b8ebce889bac8732dad7";
        let a = "";
        let c = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
                 8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad";
        let expected = "4db870d37cb75fcb46097c36230d1612";
        check(expected, h, a, c);

        let a = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
        let c = &c[..120];
        let expected = "8bd0c4d8aacd391e67cca447e8c38f65";
        check(expected, h, a, c);

        let c = "c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0\
                 feb582d33934a4f0954cc2363bc73f7862ac430e64abe499f47c9b1f";
        let expected = "75a34288b8c68f811c52b2e9a2f97f63";
        check(expected, h, a, c);

        let c = "5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf4\
                 0fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f";
        let expected = "d5ffcf6fc5ac4d69722187421a7f170b";
        check(expected, h, a, c);
    }
}
