use chacha20::ChaCha20;
use gcm::AeadCipher;
use util;
use byteorder::{ByteOrder, LittleEndian};

pub struct ChaCha20Poly1305 {
    key: [u8; 32],
}

impl AeadCipher for ChaCha20Poly1305 {
    fn new(key: &[u8]) -> Self {
        assert_eq!(32, key.len());
        let mut key_copy = [0; 32];
        key_copy.copy_from_slice(key);
        Self { key: key_copy }
    }

    fn encrypt(&self, input: &[u8], nonce: &[u8], data: &[u8], output: &mut [u8]) -> [u8; 16] {
        assert_eq!(input.len(), output.len());
        let cipher = &ChaCha20::new(&self.key, nonce);
        self.process(cipher, input, output);
        self.tag(cipher, output, data)
    }

    fn decrypt(
        &self,
        input: &[u8],
        nonce: &[u8],
        data: &[u8],
        tag: &[u8],
        output: &mut [u8],
    ) -> bool {
        assert_eq!(output.len(), input.len());
        let cipher = &ChaCha20::new(&self.key, nonce);
        let expected_tag = self.tag(cipher, input, data);
        if util::verify_16(&expected_tag, tag) {
            self.process(cipher, input, output);
            true
        } else {
            false
        }
    }
}

impl ChaCha20Poly1305 {
    fn process(&self, cipher: &ChaCha20, input: &[u8], output: &mut [u8]) {
        for (i, (input_chunk, output_chunk)) in
            (1..).zip(input.chunks(64).zip(output.chunks_mut(64)))
        {
            let block = cipher.block(i);
            for (block_byte, (input_byte, output_byte)) in
                block.iter().zip(input_chunk.iter().zip(output_chunk))
            {
                *output_byte = input_byte ^ block_byte;
            }
        }
    }

    fn tag(&self, cipher: &ChaCha20, ciphertext: &[u8], data: &[u8]) -> [u8; 16] {
        let poly_key = &Self::poly_key_gen(cipher);
        poly1305(poly_key, data, ciphertext)
    }

    fn poly_key_gen(cipher: &ChaCha20) -> [u8; 32] {
        let mut poly_key = [0; 32];
        let block = cipher.block(0);
        poly_key.copy_from_slice(&block[..32]);
        poly_key
    }
}

fn poly1305(key: &[u8; 32], data: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut tag = [0; 16];
    let mut mac = Poly1305::new(key, data);
    mac.update(ciphertext);
    mac.write_tag(&mut tag);
    tag
}

struct Poly1305 {
    function: PolyFunction,
    data_len: u64,
    ciphertext_len: u64,
}

impl Poly1305 {
    fn new(key: &[u8; 32], data: &[u8]) -> Self {
        let mut poly1305 = Self {
            function: PolyFunction::new(key),
            data_len: data.len() as u64,
            ciphertext_len: 0,
        };
        poly1305.process(data);
        poly1305
    }

    fn update(&mut self, input: &[u8]) {
        self.ciphertext_len += input.len() as u64;
        self.process(input);
    }

    fn write_tag(mut self, output: &mut [u8; 16]) {
        LittleEndian::write_u64(&mut output[..8], self.data_len);
        LittleEndian::write_u64(&mut output[8..], self.ciphertext_len);
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

struct PolyFunction {
    r: [u8; 17],
    h: [u32; 17],
    constant_term: [u8; 16],
}

impl PolyFunction {
    fn new(key: &[u8; 32]) -> Self {
        let mut constant_term = [0; 16];
        constant_term.copy_from_slice(&key[16..]);
        Self {
            r: load_r(key),
            h: [0; 17],
            constant_term: constant_term,
        }
    }

    fn write_value(mut self, output: &mut [u8; 16]) {
        self.freeze();
        add(&mut self.h, &self.constant_term, 0);
        for (&h_j, output_j) in self.h.iter().zip(output) {
            *output_j = h_j as u8;
        }
    }

    fn process(&mut self, input: &[u8]) {
        add(&mut self.h, input, 1);
        self.mulmod();
    }

    fn mulmod(&mut self) {
        let h_r = &mut [0; 17];
        for i in 0..17 {
            let mut u = 0;
            for j in 0..i + 1 {
                u += self.h[j] * u32::from(self.r[i - j]);
            }
            for j in i + 1..17 {
                u += 320 * self.h[j] * u32::from(self.r[i + 17 - j]);
            }
            h_r[i] = u;
        }
        self.h.copy_from_slice(h_r);
        self.squeeze();
    }

    fn squeeze(&mut self) {
        let mut u = 0;
        for h_j in self.h.iter_mut().take(16) {
            u += *h_j;
            *h_j = u & 255;
            u >>= 8;
        }
        u += self.h[16];
        self.h[16] = u & 3;
        u = 5 * (u >> 2);
        for h_j in self.h.iter_mut().take(16) {
            u += *h_j;
            *h_j = u & 255;
            u >>= 8;
        }
        self.h[16] += u;
    }

    fn freeze(&mut self) {
        let h_orig = self.h;
        add(
            &mut self.h,
            &[5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            252,
        );
        let negative = (self.h[16] >> 7).wrapping_neg();
        for (h_j, &h_orig_j) in self.h.iter_mut().zip(h_orig.iter()) {
            *h_j ^= negative & (h_orig_j ^ *h_j);
        }
    }
}

fn add(h: &mut [u32; 17], c: &[u8], last_byte: u8) {
    let mut u = 0;
    for (h_j, &c_j) in h.iter_mut().zip(c) {
        u += *h_j + u32::from(c_j);
        *h_j = u & 255;
        u >>= 8;
    }
    h[16] += u + u32::from(last_byte);
}

fn load_r(key: &[u8; 32]) -> [u8; 17] {
    let mut r = [0; 17];
    r[0] = key[0];
    r[1] = key[1];
    r[2] = key[2];
    r[3] = key[3] & 15;
    r[4] = key[4] & 252;
    r[5] = key[5];
    r[6] = key[6];
    r[7] = key[7] & 15;
    r[8] = key[8] & 252;
    r[9] = key[9];
    r[10] = key[10];
    r[11] = key[11] & 15;
    r[12] = key[12] & 252;
    r[13] = key[13];
    r[14] = key[14];
    r[15] = key[15] & 15;
    r
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;
    use super::*;
    use test_helpers::*;

    fn check_poly_key_gen(expected: &str, key: &[u8], nonce: &[u8]) {
        let expected = h2b(expected);
        let chacha = &ChaCha20::new(key, nonce);
        let poly_key = ChaCha20Poly1305::poly_key_gen(chacha);
        assert_eq!(expected, poly_key);
    }

    fn check_encrypt(
        key: &[u8],
        nonce: &str,
        data: &str,
        message: &str,
        ciphertext: &str,
        tag: &str,
        poly_key: &str,
    ) {
        let nonce = &h2b(nonce);
        let data = &h2b(data);
        let tag = &h2b(tag);
        let ciphertext = &h2b(ciphertext);
        let chacha_poly = ChaCha20Poly1305::new(key);
        let encrypted_message = &mut vec![0; message.len()];
        let decrypted_ciphertext = &mut vec![0; ciphertext.len()];
        let actual_tag = chacha_poly.encrypt(message.as_bytes(), nonce, data, encrypted_message);
        assert_eq!(ciphertext, encrypted_message);
        assert_eq!(tag, &actual_tag);
        assert!(chacha_poly.decrypt(
            ciphertext,
            nonce,
            data,
            tag,
            decrypted_ciphertext,
        ));
        assert_eq!(message.as_bytes(), decrypted_ciphertext.as_slice());
        // TODO: check that bad tags cause decryption to fail

        check_poly_key_gen(poly_key, key, nonce);
    }

    #[test]
    fn test_encrypt() {
        let key: &Vec<_> = &(0x80..0xa0).collect();
        let nonce = "070000004041424344454647";
        let data = "50515253c0c1c2c3c4c5c6c7";
        let message = "Ladies and Gentlemen of the class of '99: If I could offer you only one \
            tip for the future, sunscreen would be it.";
        let ciphertext = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
                          3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
                          92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
                          3ff4def08e4b7a9de576d26586cec64b6116";
        let tag = "1ae10b594f09e26a7e902ecbd0600691";
        let poly_key = "7bac2b252db447af09b67a55a4e955840ae1d6731075d9eb2a9375783ed553ff";
        check_encrypt(key, nonce, data, message, ciphertext, tag, poly_key);

        let key = &h2b(
            "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
        );
        let nonce = "000000000102030405060708";
        let data = "f33388860000000000004e91";
        let message = "Internet-Drafts are draft documents valid for a maximum of six months and \
                       may be updated, replaced, or obsoleted by other documents at any time. It \
                       is inappropriate to use Internet-Drafts as reference material or to cite \
                       them other than as /“work in progress./”";
        let ciphertext = "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb2\
                          4c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf\
                          332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c855\
                          9797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4\
                          b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523e\
                          af4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a\
                          0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a10\
                          49e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29\
                          a6ad5cb4022b02709b";
        let tag = "eead9d67890cbb22392336fea1851f38";
        let poly_key = "bdf04aa95ce4de8995b14bb6a18fecaf26478f50c054f563dbc0a21e261572aa";
        check_encrypt(key, nonce, data, message, ciphertext, tag, poly_key);
    }

    #[test]
    fn test_poly_key_gen() {
        let key: &Vec<_> = &(0x80..0xa0).collect();
        let nonce = &[0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7];
        let expected = "8ad5a08b905f81cc815040274ab29471a833b637e3fd0da508dbb8e2fdd1a646";
        check_poly_key_gen(expected, key, nonce);

        let key = &[0; 32];
        let nonce = &[0; 12];
        let expected = "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7";
        check_poly_key_gen(expected, key, nonce);

        let key = &mut [0; 32];
        key[31] = 1;
        let nonce = &mut [0; 12];
        nonce[11] = 2;
        let expected = "ecfa254f845f647473d3cb140da9e87606cb33066c447b87bc2666dde3fbb739";
        check_poly_key_gen(expected, key, nonce);

        let key = &h2b(
            "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
        );
        let expected = "965e3bc6f9ec7ed9560808f4d229f94b137ff275ca9b3fcbdd59deaad23310ae";
        check_poly_key_gen(expected, key, nonce);
    }

    #[test]
    fn test_poly() {
        let key = &mut [0; 32];
        key.copy_from_slice(&h2b(
            "7bac2b252db447af09b67a55a4e955840ae1d6731075d9eb2a9375783ed553ff",
        ));
        let data = &h2b("50515253c0c1c2c3c4c5c6c7");
        let ciphertext = &h2b(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
             3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
             92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
             3ff4def08e4b7a9de576d26586cec64b6116",
        );
        let tag = &h2b("1ae10b594f09e26a7e902ecbd0600691");
        let actual = poly1305(key, data, ciphertext);
        assert_eq!(tag, &actual);

        let input = h2b(
            "50515253c0c1c2c3c4c5c6c700000000d31a8d34648e60db7b86afbc53ef7ec2\
             a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b\
             1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58\
             fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b\
             611600000000000000000000000000000c000000000000007200000000000000",
        );
        let mut poly_function = PolyFunction::new(key);
        for chunk in input.chunks(16) {
            poly_function.process(chunk);
        }
        let actual = &mut [0; 16];
        poly_function.write_value(actual);
        assert_eq!(tag, actual);
    }
}
