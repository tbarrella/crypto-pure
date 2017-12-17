use byteorder::{BigEndian, ByteOrder};
use aes::{Aes, Aes256};
use ghash;
use util;

pub struct AesGcm256 {
    aes: Aes256,
}

impl AesGcm256 {
    pub fn new(key: &[u8]) -> Self {
        Self { aes: Aes256::new(key) }
    }

    pub fn encrypt(
        &self,
        message: &[u8],
        data: &[u8],
        nonce: &[u8],
        ciphertext: &mut [u8],
    ) -> [u8; 16] {
        Self::check_bounds(message, ciphertext, nonce, data);
        let counter = &mut self.counter(nonce);
        let mut tag = self.init_tag(counter);
        self.process(counter, message, ciphertext);
        self.update_tag(ciphertext, data, &mut tag);
        tag
    }

    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        data: &[u8],
        tag: &[u8],
        nonce: &[u8],
        message: &mut [u8],
    ) -> bool {
        Self::check_bounds(message, ciphertext, nonce, data);
        let counter = &mut self.counter(nonce);
        let expected_tag = self.tag(ciphertext, data, counter);
        if util::verify_16(&expected_tag, tag) {
            self.process(counter, ciphertext, message);
            true
        } else {
            false
        }
    }

    fn counter(&self, nonce: &[u8]) -> [u8; 16] {
        if nonce.len() == 12 {
            let mut counter = [0; 16];
            counter[..12].copy_from_slice(nonce);
            counter[15] = 1;
            counter
        } else {
            self.ghash(&[], nonce)
        }
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

    fn cipher(&self, input: &[u8; 16]) -> [u8; 16] {
        self.aes.cipher(input)
    }

    fn check_bounds(message: &[u8], ciphertext: &[u8], nonce: &[u8], data: &[u8]) {
        assert!(1 << 36 > message.len() + 32);
        assert!(1 << 61 > data.len());
        assert!(1 << 61 > nonce.len());
        assert!(0 < nonce.len());
        assert_eq!(message.len(), ciphertext.len());
    }
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
        let actual_tag = gcm.encrypt(message, data, nonce, encrypted_message);
        assert_eq!(ciphertext, encrypted_message);
        assert_eq!(tag, &actual_tag);
        assert!(gcm.decrypt(
            ciphertext,
            data,
            tag,
            nonce,
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
    fn test_case_15_16_17_18() {
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

        let nonce = "cafebabefacedbad";
        let ciphertext = "c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0\
                          feb582d33934a4f0954cc2363bc73f7862ac430e64abe499f47c9b1f";
        let tag = "3a337dbf46a792c45e454913fe2ea8f2";
        check(key, message, data, nonce, ciphertext, tag);

        let nonce = "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728\
                     c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b";
        let ciphertext = "5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf4\
                          0fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f";
        let tag = "a44a8266ee1c8eb0c8b5d4cf5ae9f19a";
        check(key, message, data, nonce, ciphertext, tag);
    }
}
