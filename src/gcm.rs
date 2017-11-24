use byteorder::{BigEndian, ByteOrder};
use aes;
use ghash;
use util;

pub struct GCM {
    cipher: aes::AES,
}

impl GCM {
    pub fn new(key: &[u8]) -> Self {
        Self { cipher: aes::AES::new(key) }
    }

    pub fn encrypt(
        &self,
        message: &[u8],
        data: &[u8],
        nonce: &[u8],
        ciphertext: &mut [u8],
    ) -> [u8; 16] {
        Self::check_bounds(message, ciphertext, nonce, data);
        let counter = self.counter(nonce);
        self.counter_mode(&counter, message, ciphertext);
        self.tag(ciphertext, data, &counter)
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
        let counter = self.counter(nonce);
        let expected_tag = self.tag(ciphertext, data, &counter);
        if util::verify_16(&expected_tag, tag) {
            self.counter_mode(&counter, ciphertext, message);
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

    fn counter_mode(&self, counter: &[u8; 16], input: &[u8], output: &mut [u8]) {
        let x0 = (&counter[..12], BigEndian::read_u32(&counter[12..]));
        for (i, (mi, oi)) in (1..).zip(input.chunks(16).zip(output.chunks_mut(16))) {
            let xi = Self::incr(x0, i);
            for (o, (x, y)) in oi.iter_mut().zip(mi.iter().zip(&self.cipher.cipher(&xi))) {
                *o = x ^ y;
            }
        }
    }

    fn tag(&self, ciphertext: &[u8], data: &[u8], counter: &[u8; 16]) -> [u8; 16] {
        let mut tag = self.ghash(data, ciphertext);
        for (t, &x) in tag.iter_mut().zip(&self.cipher.cipher(counter)) {
            *t ^= x;
        }
        tag
    }

    fn incr((f, w): (&[u8], u32), i: u32) -> [u8; 16] {
        let mut y = [0; 16];
        y[..12].copy_from_slice(f);
        BigEndian::write_u32(&mut y[12..], w.wrapping_add(i));
        y
    }

    fn ghash(&self, a: &[u8], c: &[u8]) -> [u8; 16] {
        ghash::ghash(&self.cipher.cipher(&[0; 16]), a, c)
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
        let key = h2b(key);
        let message = h2b(message);
        let data = h2b(data);
        let nonce = h2b(nonce);
        let ciphertext = h2b(ciphertext);
        let tag = h2b(tag);
        let gcm = GCM::new(&key);
        let encrypted_message = &mut vec![0; message.len()];
        let decrypted_ciphertext = &mut vec![0; ciphertext.len()];
        let actual_tag = gcm.encrypt(&message, &data, &nonce, encrypted_message);
        assert_eq!(&ciphertext, encrypted_message);
        assert_eq!(tag, actual_tag);
        assert!(gcm.decrypt(
            &ciphertext,
            &data,
            &tag,
            &nonce,
            decrypted_ciphertext,
        ));
        assert_eq!(&message, decrypted_ciphertext);
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
        let mut message = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
                           1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255";
        let mut nonce = "cafebabefacedbaddecaf888";
        let mut ciphertext = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
                              8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad";
        let mut tag = "b094dac5d93471bdec1a502270e3cc6c";
        check(key, message, "", nonce, ciphertext, tag);

        message = &message[..120];
        ciphertext = &ciphertext[..120];
        let data = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
        tag = "76fc6ece0f4e1768cddf8853bb2d551b";
        check(key, message, data, nonce, ciphertext, tag);

        nonce = "cafebabefacedbad";
        ciphertext = "c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0\
                      feb582d33934a4f0954cc2363bc73f7862ac430e64abe499f47c9b1f";
        tag = "3a337dbf46a792c45e454913fe2ea8f2";
        check(key, message, data, nonce, ciphertext, tag);

        nonce = "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728\
                 c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b";
        ciphertext = "5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf4\
                      0fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f";
        tag = "a44a8266ee1c8eb0c8b5d4cf5ae9f19a";
        check(key, message, data, nonce, ciphertext, tag);
    }
}
