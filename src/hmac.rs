use sha::{HashFunction, Sha384, SHA384_DIGEST_SIZE};

const B: usize = 128;
const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;

pub struct HmacSha384;

impl HmacSha384 {
    pub fn digest(key: &[u8], message: &[u8]) -> [u8; SHA384_DIGEST_SIZE] {
        let mut padded_key = [0; B];
        if key.len() > B {
            let mut hash_function = Self::hash_function();
            hash_function.update(key);
            hash_function.write_digest_into(&mut padded_key[..SHA384_DIGEST_SIZE]);
        } else {
            padded_key[..key.len()].copy_from_slice(key);
        }

        let mut input = Self::xor(&padded_key, IPAD);
        let mut hash_function = Self::hash_function();
        hash_function.update(&input);
        hash_function.update(message);
        let mut digest = [0; SHA384_DIGEST_SIZE];
        hash_function.write_digest_into(&mut digest);

        input = Self::xor(&padded_key, OPAD);
        hash_function = Self::hash_function();
        hash_function.update(&input);
        hash_function.update(&digest);
        hash_function.write_digest_into(&mut digest);
        digest
    }

    fn hash_function() -> Sha384 {
        Sha384::default()
    }

    fn xor(key: &[u8; B], pad: u8) -> [u8; B] {
        let mut xor = [0; B];
        for (x, y) in xor.iter_mut().zip(key.iter()) {
            *x = y ^ pad;
        }
        xor
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_helpers::*;

    fn check(expected: &str, key: &[u8], data: &[u8]) {
        let actual = HmacSha384::digest(key, data);
        assert_eq!(h2b(expected), actual.to_vec());
    }

    #[test]
    fn test_digest() {
        let key = h2b("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let data = b"Hi There";
        let mut expected = "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c\
                            faea9ea9076ede7f4af152e8b2fa9cb6";
        check(expected, &key, data);

        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        expected = "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e\
                    8e2240ca5e69e2c78b3239ecfab21649";
        check(expected, key, data);

        let key = [0xaa; 20];
        let mut data = [0xdd; 50];
        expected = "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b\
                    2a5ab39dc13814b94e3ab6e101a34f27";
        check(expected, &key, &data);

        let key: Vec<_> = (0x01..0x1a).collect();
        data = [0xcd; 50];
        expected = "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e\
                    6801dd23c4a7d679ccf8a386c674cffb";
        check(expected, &key, &data);

        let key = [0xaa; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        expected = "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c6\
                    0c2ef6ab4030fe8296248df163f44952";
        check(expected, &key, data);

        let data =
            b"This is a test using a larger than block-size key and a larger than block-\
              size data. The key needs to be hashed before being used by the HMAC algorithm.";
        expected = "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5\
                    a678cc31e799176d3860e6110c46523e";
        check(expected, &key, data);
    }
}
