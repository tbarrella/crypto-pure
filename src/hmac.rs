use sha2::{HashFunction, MAX_DIGEST_SIZE, Sha384, Sha512};

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;

pub struct Hmac<T> {
    inner_hash_function: T,
    outer_hash_function: T,
}

pub fn hmac_sha512(key: &[u8], message: &[u8]) -> [u8; Sha512::DIGEST_SIZE] {
    let mut digest = [0; Sha512::DIGEST_SIZE];
    let mut hmac = Hmac::<Sha512>::new(key);
    hmac.update(message);
    hmac.write_digest(&mut digest);
    digest
}

pub fn hmac_sha384(key: &[u8], message: &[u8]) -> [u8; Sha384::DIGEST_SIZE] {
    let mut digest = [0; Sha384::DIGEST_SIZE];
    let mut hmac = Hmac::<Sha384>::new(key);
    hmac.update(message);
    hmac.write_digest(&mut digest);
    digest
}

impl<T: HashFunction> Hmac<T> {
    pub fn new(key: &[u8]) -> Self {
        let mut hashed_key;
        let new_key;
        if key.len() > T::BLOCK_SIZE {
            hashed_key = [0; MAX_DIGEST_SIZE];
            let mut hash_function = T::default();
            hash_function.update(key);
            hash_function.write_digest(&mut hashed_key[..T::DIGEST_SIZE]);
            new_key = &hashed_key[..T::DIGEST_SIZE];
        } else {
            new_key = key;
        }

        let mut hmac = Self {
            inner_hash_function: T::default(),
            outer_hash_function: T::default(),
        };
        for byte in new_key {
            hmac.inner_hash_function.update(&[byte ^ IPAD]);
            hmac.outer_hash_function.update(&[byte ^ OPAD]);
        }
        for _ in new_key.len()..T::BLOCK_SIZE {
            hmac.inner_hash_function.update(&[IPAD]);
            hmac.outer_hash_function.update(&[OPAD]);
        }
        hmac
    }

    pub fn update(&mut self, input: &[u8]) {
        self.inner_hash_function.update(input);
    }

    pub fn write_digest(mut self, output: &mut [u8]) {
        self.inner_hash_function.write_digest(output);
        self.outer_hash_function.update(output);
        self.outer_hash_function.write_digest(output);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_helpers::*;

    fn check(exp512: &str, exp384: &str, key: &[u8], data: &[u8]) {
        let expected = h2b(exp512);
        let mut actual = hmac_sha512(key, data);
        assert_eq!(expected, actual.to_vec());

        let mut hmac = Hmac::<Sha512>::new(key);
        for word in data.chunks(4) {
            hmac.update(word);
        }
        hmac.write_digest(&mut actual);
        assert_eq!(expected, actual.to_vec());

        let expected = h2b(exp384);
        let mut actual = hmac_sha384(key, data);
        assert_eq!(expected, actual.to_vec());

        let mut hmac = Hmac::<Sha384>::new(key);
        for word in data.chunks(4) {
            hmac.update(word);
        }
        hmac.write_digest(&mut actual);
        assert_eq!(expected, actual.to_vec());
    }

    #[test]
    fn test_digest() {
        let key = h2b("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let data = b"Hi There";
        let exp512 = "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde\
                      daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854";
        let exp384 = "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c\
                      faea9ea9076ede7f4af152e8b2fa9cb6";
        check(exp512, exp384, &key, data);

        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let exp512 = "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
                      9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737";
        let exp384 = "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e\
                      8e2240ca5e69e2c78b3239ecfab21649";
        check(exp512, exp384, key, data);

        let key = [0xaa; 20];
        let data = [0xdd; 50];
        let exp512 = "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39\
                      bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb";
        let exp384 = "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b\
                      2a5ab39dc13814b94e3ab6e101a34f27";
        check(exp512, exp384, &key, &data);

        let key: Vec<_> = (0x01..0x1a).collect();
        let data = [0xcd; 50];
        let exp512 = "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db\
                      a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd";
        let exp384 = "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e\
                      6801dd23c4a7d679ccf8a386c674cffb";
        check(exp512, exp384, &key, &data);

        let key = [0xaa; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let exp512 = "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352\
                      6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598";
        let exp384 = "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c6\
                      0c2ef6ab4030fe8296248df163f44952";
        check(exp512, exp384, &key, data);

        let data =
            b"This is a test using a larger than block-size key and a larger than block-\
              size data. The key needs to be hashed before being used by the HMAC algorithm.";
        let exp512 = "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944\
                      b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58";
        let exp384 = "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5\
                      a678cc31e799176d3860e6110c46523e";
        check(exp512, exp384, &key, data);
    }
}
