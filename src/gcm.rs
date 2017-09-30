use byteorder::{BigEndian, ByteOrder};
use aes;
use ghash;

pub struct GCM {
    cipher: aes::AES,
}

impl GCM {
    pub fn new(key: &[u8]) -> Self {
        Self { cipher: aes::AES::new(key) }
    }

    pub fn auth_encrypt(&self, message: &[u8], data: &[u8], nonce: &[u8]) -> (Vec<u8>, [u8; 16]) {
        assert!(1 << 39 >= message.len() + 256);
        let y0 = self.get_y0(nonce);
        let ciphertext = self.counter_mode(&message, &y0);
        let tag = self.tag(&ciphertext, data, &y0);
        (ciphertext, tag)
    }

    pub fn auth_decrypt(
        &self,
        ciphertext: &[u8],
        tag: &[u8],
        data: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>, ()> {
        assert_eq!(16, tag.len());
        let y0 = self.get_y0(nonce);
        let expected_tag = self.tag(ciphertext, data, &y0);
        self.check_tag(&expected_tag, tag)?;
        let message = self.counter_mode(&ciphertext, &y0);
        Ok(message)
    }

    fn get_y0(&self, nonce: &[u8]) -> [u8; 16] {
        if nonce.len() == 12 {
            let mut y0 = [0; 16];
            y0[..12].copy_from_slice(nonce);
            y0[15] = 1;
            y0
        } else {
            self.ghash(&[], nonce)
        }
    }

    fn counter_mode(&self, input: &[u8], y0: &[u8; 16]) -> Vec<u8> {
        let mut output = vec![];
        let y = (&y0[..12], BigEndian::read_u32(&y0[12..]));
        for (i, mi) in (1..).zip(input.chunks(16)) {
            let yi = Self::incr(y, i);
            output.extend(mi.iter().zip(&self.cipher.cipher(&yi)).map(|(x, y)| x ^ y));
        }
        output.truncate(input.len());
        output
    }

    fn tag(&self, ciphertext: &[u8], data: &[u8], y0: &[u8; 16]) -> [u8; 16] {
        let mut tag = self.ghash(data, ciphertext);
        for (t, &x) in tag.iter_mut().zip(&self.cipher.cipher(y0)) {
            *t ^= x;
        }
        tag
    }

    /// Meant to check tag without early returns
    fn check_tag(&self, expected: &[u8], tag: &[u8]) -> Result<(), ()> {
        let valid = expected.iter().zip(tag).fold(
            true,
            |acc, (x, y)| acc && x == y,
        );
        if valid { Ok(()) } else { Err(()) }
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
}

#[cfg(test)]
mod tests {
    use gcm::*;

    fn check(k: &[u8], m: &Vec<u8>, a: &[u8], n: &[u8], c: &Vec<u8>, t: &[u8]) {
        let gcm = GCM::new(&k);
        let actual = gcm.auth_encrypt(&m, &a, &n);
        assert_eq!(c, &actual.0);
        assert_eq!(t, actual.1);
        assert_eq!(m, &gcm.auth_decrypt(&c, &t, &a, &n).unwrap());
    }

    #[test]
    fn test_case_13_14() {
        let key = [0; 32];
        let nonce = [0; 12];
        let tag = [
            0x53,
            0x0f,
            0x8a,
            0xfb,
            0xc7,
            0x45,
            0x36,
            0xb9,
            0xa9,
            0x63,
            0xb4,
            0xf1,
            0xc4,
            0xcb,
            0x73,
            0x8b,
        ];
        check(&key, &vec![], &[], &nonce, &vec![], &tag);

        let message = vec![0; 16];
        let ciphertext = vec![
            0xce,
            0xa7,
            0x40,
            0x3d,
            0x4d,
            0x60,
            0x6b,
            0x6e,
            0x07,
            0x4e,
            0xc5,
            0xd3,
            0xba,
            0xf3,
            0x9d,
            0x18,
        ];
        let tag = [
            0xd0,
            0xd1,
            0xc8,
            0xa7,
            0x99,
            0x99,
            0x6b,
            0xf0,
            0x26,
            0x5b,
            0x98,
            0xb5,
            0xd4,
            0x8a,
            0xb9,
            0x19,
        ];
        check(&key, &message, &[], &nonce, &ciphertext, &tag);
    }

    #[test]
    fn test_case_15_16_17_18() {
        let key = [
            0xfe,
            0xff,
            0xe9,
            0x92,
            0x86,
            0x65,
            0x73,
            0x1c,
            0x6d,
            0x6a,
            0x8f,
            0x94,
            0x67,
            0x30,
            0x83,
            0x08,
            0xfe,
            0xff,
            0xe9,
            0x92,
            0x86,
            0x65,
            0x73,
            0x1c,
            0x6d,
            0x6a,
            0x8f,
            0x94,
            0x67,
            0x30,
            0x83,
            0x08,
        ];
        let mut message = vec![
            0xd9,
            0x31,
            0x32,
            0x25,
            0xf8,
            0x84,
            0x06,
            0xe5,
            0xa5,
            0x59,
            0x09,
            0xc5,
            0xaf,
            0xf5,
            0x26,
            0x9a,
            0x86,
            0xa7,
            0xa9,
            0x53,
            0x15,
            0x34,
            0xf7,
            0xda,
            0x2e,
            0x4c,
            0x30,
            0x3d,
            0x8a,
            0x31,
            0x8a,
            0x72,
            0x1c,
            0x3c,
            0x0c,
            0x95,
            0x95,
            0x68,
            0x09,
            0x53,
            0x2f,
            0xcf,
            0x0e,
            0x24,
            0x49,
            0xa6,
            0xb5,
            0x25,
            0xb1,
            0x6a,
            0xed,
            0xf5,
            0xaa,
            0x0d,
            0xe6,
            0x57,
            0xba,
            0x63,
            0x7b,
            0x39,
            0x1a,
            0xaf,
            0xd2,
            0x55,
        ];
        let nonce = [
            0xca,
            0xfe,
            0xba,
            0xbe,
            0xfa,
            0xce,
            0xdb,
            0xad,
            0xde,
            0xca,
            0xf8,
            0x88,
        ];
        let mut ciphertext = vec![
            0x52,
            0x2d,
            0xc1,
            0xf0,
            0x99,
            0x56,
            0x7d,
            0x07,
            0xf4,
            0x7f,
            0x37,
            0xa3,
            0x2a,
            0x84,
            0x42,
            0x7d,
            0x64,
            0x3a,
            0x8c,
            0xdc,
            0xbf,
            0xe5,
            0xc0,
            0xc9,
            0x75,
            0x98,
            0xa2,
            0xbd,
            0x25,
            0x55,
            0xd1,
            0xaa,
            0x8c,
            0xb0,
            0x8e,
            0x48,
            0x59,
            0x0d,
            0xbb,
            0x3d,
            0xa7,
            0xb0,
            0x8b,
            0x10,
            0x56,
            0x82,
            0x88,
            0x38,
            0xc5,
            0xf6,
            0x1e,
            0x63,
            0x93,
            0xba,
            0x7a,
            0x0a,
            0xbc,
            0xc9,
            0xf6,
            0x62,
            0x89,
            0x80,
            0x15,
            0xad,
        ];
        let tag = [
            0xb0,
            0x94,
            0xda,
            0xc5,
            0xd9,
            0x34,
            0x71,
            0xbd,
            0xec,
            0x1a,
            0x50,
            0x22,
            0x70,
            0xe3,
            0xcc,
            0x6c,
        ];
        check(&key, &message, &[], &nonce, &ciphertext, &tag);

        message.truncate(60);
        ciphertext.truncate(60);
        let data = [
            0xfe,
            0xed,
            0xfa,
            0xce,
            0xde,
            0xad,
            0xbe,
            0xef,
            0xfe,
            0xed,
            0xfa,
            0xce,
            0xde,
            0xad,
            0xbe,
            0xef,
            0xab,
            0xad,
            0xda,
            0xd2,
        ];
        let tag = [
            0x76,
            0xfc,
            0x6e,
            0xce,
            0x0f,
            0x4e,
            0x17,
            0x68,
            0xcd,
            0xdf,
            0x88,
            0x53,
            0xbb,
            0x2d,
            0x55,
            0x1b,
        ];
        check(&key, &message, &data, &nonce, &ciphertext, &tag);

        let nonce = [0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad];
        let ciphertext = vec![
            0xc3,
            0x76,
            0x2d,
            0xf1,
            0xca,
            0x78,
            0x7d,
            0x32,
            0xae,
            0x47,
            0xc1,
            0x3b,
            0xf1,
            0x98,
            0x44,
            0xcb,
            0xaf,
            0x1a,
            0xe1,
            0x4d,
            0x0b,
            0x97,
            0x6a,
            0xfa,
            0xc5,
            0x2f,
            0xf7,
            0xd7,
            0x9b,
            0xba,
            0x9d,
            0xe0,
            0xfe,
            0xb5,
            0x82,
            0xd3,
            0x39,
            0x34,
            0xa4,
            0xf0,
            0x95,
            0x4c,
            0xc2,
            0x36,
            0x3b,
            0xc7,
            0x3f,
            0x78,
            0x62,
            0xac,
            0x43,
            0x0e,
            0x64,
            0xab,
            0xe4,
            0x99,
            0xf4,
            0x7c,
            0x9b,
            0x1f,
        ];
        let tag = [
            0x3a,
            0x33,
            0x7d,
            0xbf,
            0x46,
            0xa7,
            0x92,
            0xc4,
            0x5e,
            0x45,
            0x49,
            0x13,
            0xfe,
            0x2e,
            0xa8,
            0xf2,
        ];
        check(&key, &message, &data, &nonce, &ciphertext, &tag);

        let nonce = [
            0x93,
            0x13,
            0x22,
            0x5d,
            0xf8,
            0x84,
            0x06,
            0xe5,
            0x55,
            0x90,
            0x9c,
            0x5a,
            0xff,
            0x52,
            0x69,
            0xaa,
            0x6a,
            0x7a,
            0x95,
            0x38,
            0x53,
            0x4f,
            0x7d,
            0xa1,
            0xe4,
            0xc3,
            0x03,
            0xd2,
            0xa3,
            0x18,
            0xa7,
            0x28,
            0xc3,
            0xc0,
            0xc9,
            0x51,
            0x56,
            0x80,
            0x95,
            0x39,
            0xfc,
            0xf0,
            0xe2,
            0x42,
            0x9a,
            0x6b,
            0x52,
            0x54,
            0x16,
            0xae,
            0xdb,
            0xf5,
            0xa0,
            0xde,
            0x6a,
            0x57,
            0xa6,
            0x37,
            0xb3,
            0x9b,
        ];
        let ciphertext = vec![
            0x5a,
            0x8d,
            0xef,
            0x2f,
            0x0c,
            0x9e,
            0x53,
            0xf1,
            0xf7,
            0x5d,
            0x78,
            0x53,
            0x65,
            0x9e,
            0x2a,
            0x20,
            0xee,
            0xb2,
            0xb2,
            0x2a,
            0xaf,
            0xde,
            0x64,
            0x19,
            0xa0,
            0x58,
            0xab,
            0x4f,
            0x6f,
            0x74,
            0x6b,
            0xf4,
            0x0f,
            0xc0,
            0xc3,
            0xb7,
            0x80,
            0xf2,
            0x44,
            0x45,
            0x2d,
            0xa3,
            0xeb,
            0xf1,
            0xc5,
            0xd8,
            0x2c,
            0xde,
            0xa2,
            0x41,
            0x89,
            0x97,
            0x20,
            0x0e,
            0xf8,
            0x2e,
            0x44,
            0xae,
            0x7e,
            0x3f,
        ];
        let tag = [
            0xa4,
            0x4a,
            0x82,
            0x66,
            0xee,
            0x1c,
            0x8e,
            0xb0,
            0xc8,
            0xb5,
            0xd4,
            0xcf,
            0x5a,
            0xe9,
            0xf1,
            0x9a,
        ];
        check(&key, &message, &data, &nonce, &ciphertext, &tag);
    }
}
