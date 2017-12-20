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
        assert_eq!(12, nonce.len());
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
        assert_eq!(12, nonce.len());
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
            let chunk_len = output_chunk.len();
            output_chunk.copy_from_slice(&block[..chunk_len]);
            for (input_byte, output_byte) in input_chunk.iter().zip(output_chunk) {
                *output_byte ^= input_byte;
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
    let mut digest = [0; 16];
    let mut mac = Poly1305::new(key, data);
    mac.update(ciphertext);
    mac.write_digest(&mut digest);
    digest
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

    fn write_digest(mut self, output: &mut [u8; 16]) {
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

    #[test]
    fn test_encrypt() {
        let key: &Vec<_> = &(0x80..0xa0).collect();
        let nonce = &h2b("070000004041424344454647");
        let data = &h2b("50515253c0c1c2c3c4c5c6c7");
        let message = "Ladies and Gentlemen of the class of '99: If I could offer you only one \
            tip for the future, sunscreen would be it.";
        let ciphertext = &h2b(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
             3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
             92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
             3ff4def08e4b7a9de576d26586cec64b6116",
        );
        let tag = &h2b("1ae10b594f09e26a7e902ecbd0600691");
        let encrypted_message = &mut vec![0; message.len()];
        let decrypted_ciphertext = &mut vec![0; ciphertext.len()];

        let chacha_poly = ChaCha20Poly1305::new(key);
        let expected_poly_key = "7bac2b252db447af09b67a55a4e955840ae1d6731075d9eb2a9375783ed553ff";
        check_poly_key_gen(expected_poly_key, key, nonce);

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
    }

    #[test]
    fn test_poly_key_gen() {
        let key: &Vec<_> = &(0x80..0xa0).collect();
        let nonce = &[0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7];
        let expected = "8ad5a08b905f81cc815040274ab29471a833b637e3fd0da508dbb8e2fdd1a646";
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
