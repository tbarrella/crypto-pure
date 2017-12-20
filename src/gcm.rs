use byteorder::{BigEndian, ByteOrder};
use aes::{Aes, Aes256};
use ghash;
use util;

pub trait Aead {
    fn new(key: &[u8]) -> Self;

    fn encrypt(&self, input: &[u8], nonce: &[u8], data: &[u8], output: &mut [u8]) -> [u8; 16];

    fn decrypt(
        &self,
        input: &[u8],
        nonce: &[u8],
        data: &[u8],
        tag: &[u8],
        output: &mut [u8],
    ) -> bool;
}

pub struct AesGcm256(Processor<Aes256>);

impl Aead for AesGcm256 {
    fn new(key: &[u8]) -> Self {
        AesGcm256(Processor::<Aes256>::new(key))
    }

    fn encrypt(&self, input: &[u8], nonce: &[u8], data: &[u8], output: &mut [u8]) -> [u8; 16] {
        check_bounds(input, output, nonce, data);
        let counter = &mut counter(nonce);
        let mut tag = self.0.init_tag(counter);
        self.0.process(counter, input, output);
        self.0.update_tag(output, data, &mut tag);
        tag
    }

    fn decrypt(
        &self,
        input: &[u8],
        nonce: &[u8],
        data: &[u8],
        tag: &[u8],
        output: &mut [u8],
    ) -> bool {
        check_bounds(output, input, nonce, data);
        let counter = &mut counter(nonce);
        let expected_tag = self.0.tag(input, data, counter);
        if util::verify_16(&expected_tag, tag) {
            self.0.process(counter, input, output);
            true
        } else {
            false
        }
    }
}

struct Processor<A> {
    aes: A,
}

impl<A: Aes> Processor<A> {
    fn new(key: &[u8]) -> Self {
        Self { aes: A::new(key) }
    }

    fn cipher(&self, input: &[u8; 16]) -> [u8; 16] {
        self.aes.cipher(input)
    }

    fn process(&self, counter: &mut [u8; 16], input: &[u8], output: &mut [u8]) {
        for (input_chunk, output_chunk) in input.chunks(16).zip(output.chunks_mut(16)) {
            Self::incr(counter);
            let block = self.cipher(counter);
            let chunk_len = output_chunk.len();
            output_chunk.copy_from_slice(&block[..chunk_len]);
            for (input_byte, output_byte) in input_chunk.iter().zip(output_chunk) {
                *output_byte ^= input_byte;
            }
        }
    }

    fn tag(&self, ciphertext: &[u8], data: &[u8], counter: &[u8; 16]) -> [u8; 16] {
        let mut tag = self.init_tag(counter);
        self.update_tag(ciphertext, data, &mut tag);
        tag
    }

    fn init_tag(&self, counter: &[u8; 16]) -> [u8; 16] {
        self.cipher(counter)
    }

    fn update_tag(&self, ciphertext: &[u8], data: &[u8], tag: &mut [u8; 16]) {
        let hash = self.ghash(data, ciphertext);
        for (h, t) in hash.iter().zip(tag) {
            *t ^= h;
        }
    }

    fn incr(counter: &mut [u8; 16]) {
        let count = BigEndian::read_u32(&counter[12..]);
        BigEndian::write_u32(&mut counter[12..], count.wrapping_add(1));
    }

    fn ghash(&self, a: &[u8], c: &[u8]) -> [u8; 16] {
        let key = &self.cipher(&[0; 16]);
        ghash::ghash(key, a, c)
    }
}

fn counter(nonce: &[u8]) -> [u8; 16] {
    let mut counter = [0; 16];
    counter[..12].copy_from_slice(nonce);
    counter[15] = 1;
    counter
}

fn check_bounds(message: &[u8], ciphertext: &[u8], nonce: &[u8], data: &[u8]) {
    assert_eq!(12, nonce.len());
    assert_eq!(message.len(), ciphertext.len());
    assert!(1 << 36 > message.len() + 32);
    assert!(1 << 61 > data.len());
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_helpers::*;

    fn check(key: &str, message: &str, data: &str, nonce: &str, ciphertext: &str, tag: &str) {
        let key = &h2b(key);
        let message = &h2b(message);
        let data = &h2b(data);
        let nonce = &h2b(nonce);
        let ciphertext = &h2b(ciphertext);
        let tag = &h2b(tag);
        let gcm = AesGcm256::new(key);
        let encrypted_message = &mut vec![0; message.len()];
        let decrypted_ciphertext = &mut vec![0; ciphertext.len()];
        let actual_tag = gcm.encrypt(message, nonce, data, encrypted_message);
        assert_eq!(ciphertext, encrypted_message);
        assert_eq!(tag, &actual_tag);
        assert!(gcm.decrypt(
            ciphertext,
            nonce,
            data,
            tag,
            decrypted_ciphertext,
        ));
        assert_eq!(message, decrypted_ciphertext);
        // TODO: check that bad tags cause decryption to fail
    }

    #[test]
    fn test_case_13_14() {
        let key = "0000000000000000000000000000000000000000000000000000000000000000";
        let nonce = "000000000000000000000000";
        let tag = "530f8afbc74536b9a963b4f1c4cb738b";
        check(key, "", "", nonce, "", tag);

        let message = "00000000000000000000000000000000";
        let ciphertext = "cea7403d4d606b6e074ec5d3baf39d18";
        let tag = "d0d1c8a799996bf0265b98b5d48ab919";
        check(key, message, "", nonce, ciphertext, tag);
    }

    #[test]
    fn test_case_15_16() {
        let key = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";
        let message = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
                       1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255";
        let nonce = "cafebabefacedbaddecaf888";
        let ciphertext = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
                          8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad";
        let tag = "b094dac5d93471bdec1a502270e3cc6c";
        check(key, message, "", nonce, ciphertext, tag);

        let message = &message[..120];
        let ciphertext = &ciphertext[..120];
        let data = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
        let tag = "76fc6ece0f4e1768cddf8853bb2d551b";
        check(key, message, data, nonce, ciphertext, tag);
    }
}
