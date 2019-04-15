//! Module for the Galois/Counter Mode (GCM) mode of operation for block ciphers.
use crate::aes::BlockCipher;
use crate::ghash;
use crate::util;
use byteorder::{BigEndian, ByteOrder as _};

pub trait AeadCipher {
    /// Initializes an AEAD Cipher given a key.
    fn new(key: &[u8]) -> Self;

    /// Encrypts a message into a ciphertext and outputs a tag authenticating it and provided data.
    fn encrypt(&self, input: &[u8], nonce: &[u8], data: &[u8], output: &mut [u8]) -> [u8; 16];

    /// Decrypts a ciphertext into a message if tag verification passes.
    fn decrypt(
        &self,
        input: &[u8],
        nonce: &[u8],
        data: &[u8],
        tag: &[u8],
        output: &mut [u8],
    ) -> bool;
}

/// An AEAD cipher in GCM mode.
pub struct Gcm<E>(Processor<E>);

impl<E: BlockCipher> AeadCipher for Gcm<E> {
    /// Initializes an AEAD block cipher in GCM mode given a key.
    ///
    /// # Panics
    ///
    /// Panics if `key.len()` is not appropriate for the block cipher.
    fn new(key: &[u8]) -> Self {
        Gcm::<E>(Processor::<E>::new(key))
    }

    /// Encrypts a message into a ciphertext and outputs a tag authenticating it and provided data.
    ///
    /// # Panics
    ///
    /// Panics if `input.len()` is not equal to `output.len()`, `nonce.len()` is not equal to 12,
    /// `message.len()` is not less than 2^36 - 32, or `data.len()` is not less than 2^61.
    fn encrypt(&self, input: &[u8], nonce: &[u8], data: &[u8], output: &mut [u8]) -> [u8; 16] {
        check_bounds(input, output, nonce, data);
        let counter = &mut counter(nonce);
        self.0.process(counter, input, output);
        self.0.tag(output, data, counter)
    }

    /// Decrypts a ciphertext into a message if tag verification passes.
    ///
    /// # Panics
    ///
    /// Panics if `input.len()` is not equal to `output.len()`, `nonce.len()` is not equal to 12,
    /// `message.len()` is not less than 2^36 - 32, or `data.len()` is not less than 2^61.
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

struct Processor<E> {
    block_cipher: E,
}

impl<E: BlockCipher> Processor<E> {
    fn new(key: &[u8]) -> Self {
        Self {
            block_cipher: E::new(key),
        }
    }

    fn process(&self, counter: &mut [u8; 16], input: &[u8], output: &mut [u8]) {
        for (i, (input_chunk, output_chunk)) in
            (2..).zip(input.chunks(16).zip(output.chunks_mut(16)))
        {
            let block = self.block(counter, i);
            for (block_byte, (input_byte, output_byte)) in
                block.iter().zip(input_chunk.iter().zip(output_chunk))
            {
                *output_byte = input_byte ^ block_byte;
            }
        }
    }

    fn block(&self, counter: &mut [u8; 16], i: u32) -> [u8; 16] {
        BigEndian::write_u32(&mut counter[12..], i);
        self.block_cipher.permute(counter)
    }

    fn tag(&self, ciphertext: &[u8], data: &[u8], counter: &mut [u8; 16]) -> [u8; 16] {
        let mut tag = self.block(counter, 1);
        let hash = self.ghash(data, ciphertext);
        for (t, h) in tag.iter_mut().zip(&hash) {
            *t ^= h;
        }
        tag
    }

    fn ghash(&self, a: &[u8], c: &[u8]) -> [u8; 16] {
        let key = &self.block_cipher.permute(&[0; 16]);
        ghash::ghash(key, a, c)
    }
}

fn counter(nonce: &[u8]) -> [u8; 16] {
    let mut counter = [0; 16];
    counter[..12].copy_from_slice(nonce);
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
    use crate::aes::{Aes128, Aes192, Aes256};
    use crate::test_helpers::*;

    fn check<E: BlockCipher>(key: &str, msg: &str, nonce: &str, data: &str, tag: &str, ct: &str) {
        let key = &h2b(key);
        let message = &h2b(msg);
        let nonce = &h2b(nonce);
        let data = &h2b(data);
        let tag = &h2b(tag);
        let ciphertext = &h2b(ct);
        let gcm = Gcm::<E>::new(key);
        let encrypted_message = &mut vec![0; message.len()];
        let decrypted_ciphertext = &mut vec![0; ciphertext.len()];
        let actual_tag = gcm.encrypt(message, nonce, data, encrypted_message);
        assert_eq!(ciphertext, encrypted_message);
        assert_eq!(tag, &actual_tag);
        assert!(gcm.decrypt(ciphertext, nonce, data, tag, decrypted_ciphertext));
        assert_eq!(message, decrypted_ciphertext);
        // TODO: check that bad tags cause decryption to fail
    }

    #[test]
    fn test_case_1_2() {
        let key = "00000000000000000000000000000000";
        let nonce = "000000000000000000000000";
        let tag = "58e2fccefa7e3061367f1d57a4e7455a";
        check::<Aes128>(key, "", nonce, "", tag, "");

        let message = "00000000000000000000000000000000";
        let ciphertext = "0388dace60b6a392f328c2b971b2fe78";
        let tag = "ab6e47d42cec13bdf53a67b21257bddf";
        check::<Aes128>(key, message, nonce, "", tag, ciphertext);
    }

    #[test]
    fn test_case_3_4() {
        let key = "feffe9928665731c6d6a8f9467308308";
        let message = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
                       1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255";
        let nonce = "cafebabefacedbaddecaf888";
        let ciphertext = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
                          21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985";
        let tag = "4d5c2af327cd64a62cf35abd2ba6fab4";
        check::<Aes128>(key, message, nonce, "", tag, ciphertext);

        let message = &message[..120];
        let ciphertext = &ciphertext[..120];
        let data = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
        let tag = "5bc94fbc3221a5db94fae95ae7121a47";
        check::<Aes128>(key, message, nonce, data, tag, ciphertext);
    }

    #[test]
    fn test_case_7_8() {
        let key = "000000000000000000000000000000000000000000000000";
        let nonce = "000000000000000000000000";
        let tag = "cd33b28ac773f74ba00ed1f312572435";
        check::<Aes192>(key, "", nonce, "", tag, "");

        let message = "00000000000000000000000000000000";
        let ciphertext = "98e7247c07f0fe411c267e4384b0f600";
        let tag = "2ff58d80033927ab8ef4d4587514f0fb";
        check::<Aes192>(key, message, nonce, "", tag, ciphertext);
    }

    #[test]
    fn test_case_9_10() {
        let key = "feffe9928665731c6d6a8f9467308308feffe9928665731c";
        let message = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
                       1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255";
        let nonce = "cafebabefacedbaddecaf888";
        let ciphertext = "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c\
                          7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710acade256";
        let tag = "9924a7c8587336bfb118024db8674a14";
        check::<Aes192>(key, message, nonce, "", tag, ciphertext);

        let message = &message[..120];
        let ciphertext = &ciphertext[..120];
        let data = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
        let tag = "2519498e80f1478f37ba55bd6d27618c";
        check::<Aes192>(key, message, nonce, data, tag, ciphertext);
    }

    #[test]
    fn test_case_13_14() {
        let key = "0000000000000000000000000000000000000000000000000000000000000000";
        let nonce = "000000000000000000000000";
        let tag = "530f8afbc74536b9a963b4f1c4cb738b";
        check::<Aes256>(key, "", nonce, "", tag, "");

        let message = "00000000000000000000000000000000";
        let ciphertext = "cea7403d4d606b6e074ec5d3baf39d18";
        let tag = "d0d1c8a799996bf0265b98b5d48ab919";
        check::<Aes256>(key, message, nonce, "", tag, ciphertext);
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
        check::<Aes256>(key, message, nonce, "", tag, ciphertext);

        let message = &message[..120];
        let ciphertext = &ciphertext[..120];
        let data = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
        let tag = "76fc6ece0f4e1768cddf8853bb2d551b";
        check::<Aes256>(key, message, nonce, data, tag, ciphertext);
    }
}
