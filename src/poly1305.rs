use chacha20;
use util;
use byteorder::{ByteOrder, LittleEndian};

pub struct ChaCha20Poly1305 {
    cipher: chacha20::ChaCha20,
    mac_key: [u8; 32],
}

impl ChaCha20Poly1305 {
    pub fn new(key: &[u8], nonce: &[u8]) -> Self {
        let mut chacha_poly = Self {
            cipher: chacha20::ChaCha20::new(key, nonce),
            mac_key: [0; 32],
        };
        chacha_poly.key_gen();
        chacha_poly
    }

    pub fn encrypt(self, message: &[u8], data: &[u8], ciphertext: &mut [u8]) -> [u8; 16] {
        assert_eq!(message.len(), ciphertext.len());
        self.counter_mode(message, ciphertext);
        self.tag(ciphertext, data)
    }

    pub fn decrypt(self, ciphertext: &[u8], data: &[u8], tag: &[u8], message: &mut [u8]) -> bool {
        assert_eq!(message.len(), ciphertext.len());
        let expected_tag = self.tag(ciphertext, data);
        if util::verify_16(&expected_tag, tag) {
            self.counter_mode(ciphertext, message);
            true
        } else {
            false
        }
    }

    fn key_gen(&mut self) {
        self.mac_key.copy_from_slice(&self.cipher.block(0)[..32]);
    }

    fn counter_mode(&self, input: &[u8], output: &mut [u8]) {
        for (i, (mi, oi)) in (1..).zip(input.chunks(64).zip(output.chunks_mut(64))) {
            for (o, (x, y)) in oi.iter_mut().zip(
                mi.iter().zip(self.cipher.block(i).iter()),
            )
            {
                *o = x ^ y;
            }
        }
    }

    fn tag(&self, ciphertext: &[u8], data: &[u8]) -> [u8; 16] {
        poly1305(&self.mac_key, data, ciphertext)
    }
}

fn poly1305(key: &[u8; 32], data: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut digest = [0; 16];
    let mut hash_function = Poly1305::new(key, data);
    hash_function.update(ciphertext);
    hash_function.write_digest(&mut digest);
    digest
}

struct Poly1305(Processor);

impl Poly1305 {
    fn new(key: &[u8; 32], data: &[u8]) -> Self {
        let mut processor = Processor::new(key);
        processor.update(data);
        processor.data_len = data.len() as u64;
        Poly1305(processor)
    }

    fn update(&mut self, input: &[u8]) {
        self.0.update(input);
        self.0.ciphertext_len += input.len() as u64;
    }

    fn write_digest(self, output: &mut [u8; 16]) {
        self.0.write_digest(output);
    }
}

struct Processor {
    r: [u8; 17],
    h: [u32; 17],
    pad: [u8; 17],
    data_len: u64,
    ciphertext_len: u64,
}

impl Processor {
    fn new(key: &[u8; 32]) -> Self {
        let mut processor = Self {
            r: load_r(key),
            h: [0; 17],
            pad: [0; 17],
            data_len: 0,
            ciphertext_len: 0,
        };
        processor.pad[..16].copy_from_slice(&key[16..]);
        processor
    }

    fn write_digest(mut self, output: &mut [u8; 16]) {
        let buffer = &mut [0; 16];
        LittleEndian::write_u64(&mut buffer[..8], self.data_len);
        LittleEndian::write_u64(&mut buffer[8..], self.ciphertext_len);
        self.update(buffer);
        freeze(&mut self.h);
        add(&mut self.h, &self.pad);
        for (&h_j, output_j) in self.h.iter().zip(output) {
            *output_j = h_j as u8;
        }
    }

    fn update(&mut self, input: &[u8]) {
        let buffer = &mut [0; 17];
        for chunk in input.chunks(16) {
            buffer[..chunk.len()].copy_from_slice(chunk);
            for c_j in buffer.iter_mut().take(16).skip(chunk.len()) {
                *c_j = 0;
            }
            buffer[16] = 1;
            self.process(buffer);
        }
    }

    fn process(&mut self, input: &[u8; 17]) {
        add(&mut self.h, input);
        mulmod(&mut self.h, &self.r);
    }
}

fn add(h: &mut [u32; 17], c: &[u8; 17]) {
    let mut u = 0;
    for (&c_j, h_j) in c.iter().zip(h) {
        u += *h_j + u32::from(c_j);
        *h_j = u & 255;
        u >>= 8;
    }
}

fn mulmod(h: &mut [u32; 17], r: &[u8; 17]) {
    let h_r = &mut [0; 17];
    for i in 0..17 {
        let mut u = 0;
        for j in 0..i + 1 {
            u += h[j] * u32::from(r[i - j]);
        }
        for j in i + 1..17 {
            u += 320 * h[j] * u32::from(r[i + 17 - j]);
        }
        h_r[i] = u;
    }
    h.copy_from_slice(h_r);
    squeeze(h);
}

/// Carries coefficients in the expansion of `h` so that each one is less than 256.
fn squeeze(h: &mut [u32; 17]) {
    let mut u = 0;
    for h_j in h.iter_mut().take(16) {
        u += *h_j;
        *h_j = u & 255;
        u >>= 8;
    }
    u += h[16];
    h[16] = u & 3;
    u = 5 * (u >> 2);
    for h_j in h.iter_mut().take(16) {
        u += *h_j;
        *h_j = u & 255;
        u >>= 8;
    }
    u += h[16];
    h[16] = u;
}

fn freeze(h: &mut [u32; 17]) {
    let h_orig = *h;
    add(h, &[5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252]);
    let negative = (h[16] >> 7).wrapping_neg();
    for (&h_orig_j, h_j) in h_orig.iter().zip(h) {
        *h_j ^= negative & (h_orig_j ^ *h_j);
    }
}

fn load_r(key: &[u8]) -> [u8; 17] {
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
    r[16] = 0;
    r
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;
    use super::*;
    use test_helpers::*;

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

        let chacha_poly = ChaCha20Poly1305::new(key, nonce);
        let actual_tag = chacha_poly.encrypt(message.as_bytes(), data, encrypted_message);
        assert_eq!(ciphertext, encrypted_message);
        assert_eq!(tag, &actual_tag);

        let chacha_poly = ChaCha20Poly1305::new(key, nonce);
        assert!(chacha_poly.decrypt(
            ciphertext,
            data,
            tag,
            decrypted_ciphertext,
        ));
        assert_eq!(message.as_bytes(), decrypted_ciphertext.as_slice());
        // TODO: check that bad tags cause decryption to fail
    }

    #[test]
    fn test_key_gen() {
        let key: &Vec<_> = &(0x80..0xa0).collect();
        let nonce = &[0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7];
        let expected = h2b(
            "8ad5a08b905f81cc815040274ab29471a833b637e3fd0da508dbb8e2fdd1a646",
        );
        let chacha_poly = ChaCha20Poly1305::new(key, nonce);
        assert_eq!(expected, chacha_poly.mac_key.to_vec());
    }

    /*
    #[test]
    fn test_digest() {
        let key = &h2b(
            "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
        );
        let message = b"Cryptographic Forum Research Group";
        let tag = h2b("a8061dc1305136c6c22b8baf0c0127a9");
        let actual = &mut [0; 16];
        poly1305(key, message, actual);
        assert_eq!(tag, actual.to_vec());
    }
    */
}
