//! Module for creating HMAC digests.
use sha2::{HashFunction, MAX_DIGEST_SIZE, Sha224, Sha256, Sha384, Sha512};

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;

/// A function for creating HMAC digests given a hash function `H`.
///
/// # Examples
///
/// ```
/// use crypto_pure::hmac::Hmac;
/// use crypto_pure::sha2::{HashFunction, Sha512};
/// # let key = b"This should be generated securely.";
/// let mut digest = [0; Sha512::DIGEST_SIZE];
/// let mut hmac = Hmac::<Sha512>::new(key);
/// hmac.update(b"part one");
/// hmac.update(b"part two");
/// hmac.write_digest(&mut digest);
/// ```
pub struct Hmac<H> {
    inner_hash_function: H,
    outer_hash_function: H,
}

macro_rules! impl_wrapper { ($function:ident, $key:expr, $message:expr) => {{
    let mut digest = [0; $function::DIGEST_SIZE];
    let mut hmac = Hmac::<$function>::new($key);
    hmac.update($message);
    hmac.write_digest(&mut digest);
    digest
}}}

/// Wrapper for obtaining the HMAC-SHA-512 digest for a complete message.
pub fn hmac_sha512(key: &[u8], message: &[u8]) -> [u8; Sha512::DIGEST_SIZE] {
    impl_wrapper!(Sha512, key, message)
}

/// Wrapper for obtaining the HMAC-SHA-384 digest for a complete message.
pub fn hmac_sha384(key: &[u8], message: &[u8]) -> [u8; Sha384::DIGEST_SIZE] {
    impl_wrapper!(Sha384, key, message)
}

/// Wrapper for obtaining the HMAC-SHA-256 digest for a complete message.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; Sha256::DIGEST_SIZE] {
    impl_wrapper!(Sha256, key, message)
}

/// Wrapper for obtaining the HMAC-SHA-224 digest for a complete message.
pub fn hmac_sha224(key: &[u8], message: &[u8]) -> [u8; Sha224::DIGEST_SIZE] {
    impl_wrapper!(Sha224, key, message)
}

impl<H: HashFunction> Hmac<H> {
    /// Initializes an HMAC function given a key.
    pub fn new(key: &[u8]) -> Self {
        let mut hashed_key;
        let new_key;
        if key.len() > H::BLOCK_SIZE {
            hashed_key = [0; MAX_DIGEST_SIZE];
            let mut hash_function = H::default();
            hash_function.update(key);
            hash_function.write_digest(&mut hashed_key[..H::DIGEST_SIZE]);
            new_key = &hashed_key[..H::DIGEST_SIZE];
        } else {
            new_key = key;
        }
        Self {
            inner_hash_function: Self::keyed_hash_function(new_key, IPAD),
            outer_hash_function: Self::keyed_hash_function(new_key, OPAD),
        }
    }

    /// Feeds input into the function to update its state.
    pub fn update(&mut self, input: &[u8]) {
        self.inner_hash_function.update(input);
    }

    /// Writes the digest into an output buffer.
    ///
    /// # Panics
    ///
    /// Panics if `output.len()` is not equal to the digest size.
    pub fn write_digest(mut self, output: &mut [u8]) {
        assert_eq!(H::DIGEST_SIZE, output.len());
        self.inner_hash_function.write_digest(output);
        self.outer_hash_function.update(output);
        self.outer_hash_function.write_digest(output);
    }

    fn keyed_hash_function(key: &[u8], pad: u8) -> H {
        let mut hash_function = H::default();
        for byte in key {
            hash_function.update(&[byte ^ pad]);
        }
        for _ in key.len()..H::BLOCK_SIZE {
            hash_function.update(&[pad]);
        }
        hash_function
    }
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;
    use super::*;
    use test_helpers::*;

    fn check(exp512: &str, exp384: &str, exp256: &str, exp224: &str, key: &[u8], data: &[u8]) {
        macro_rules! check { ($function:ident, $wrapper:path, $expected:expr) => (
            let expected = h2b($expected);
            let actual = $wrapper(key, data);
            assert_eq!(expected, actual.to_vec());

            let actual = &mut vec![0; expected.len()];
            let mut hmac = Hmac::<$function>::new(key);
            for word in data.chunks(4) {
                hmac.update(word);
            }
            hmac.write_digest(actual);
            assert_eq!(expected, actual.to_vec());
        )}

        check!(Sha512, hmac_sha512, exp512);
        check!(Sha384, hmac_sha384, exp384);
        check!(Sha256, hmac_sha256, exp256);
        check!(Sha224, hmac_sha224, exp224);
    }

    #[test]
    fn test_digest() {
        let key = h2b("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let data = b"Hi There";
        let exp512 = "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde\
                      daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854";
        let exp384 = "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c\
                      faea9ea9076ede7f4af152e8b2fa9cb6";
        let exp256 = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
        let exp224 = "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22";
        check(exp512, exp384, exp256, exp224, &key, data);

        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let exp512 = "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
                      9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737";
        let exp384 = "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e\
                      8e2240ca5e69e2c78b3239ecfab21649";
        let exp256 = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
        let exp224 = "a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44";
        check(exp512, exp384, exp256, exp224, key, data);

        let key = [0xaa; 20];
        let data = [0xdd; 50];
        let exp512 = "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39\
                      bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb";
        let exp384 = "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b\
                      2a5ab39dc13814b94e3ab6e101a34f27";
        let exp256 = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe";
        let exp224 = "7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea";
        check(exp512, exp384, exp256, exp224, &key, &data);

        let key: Vec<_> = (0x01..0x1a).collect();
        let data = [0xcd; 50];
        let exp512 = "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db\
                      a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd";
        let exp384 = "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e\
                      6801dd23c4a7d679ccf8a386c674cffb";
        let exp256 = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b";
        let exp224 = "6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a";
        check(exp512, exp384, exp256, exp224, &key, &data);

        let key = [0xaa; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let exp512 = "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352\
                      6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598";
        let exp384 = "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c6\
                      0c2ef6ab4030fe8296248df163f44952";
        let exp256 = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54";
        let exp224 = "95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e";
        check(exp512, exp384, exp256, exp224, &key, data);

        let data =
            b"This is a test using a larger than block-size key and a larger than block-\
              size data. The key needs to be hashed before being used by the HMAC algorithm.";
        let exp512 = "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944\
                      b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58";
        let exp384 = "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5\
                      a678cc31e799176d3860e6110c46523e";
        let exp256 = "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2";
        let exp224 = "3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1";
        check(exp512, exp384, exp256, exp224, &key, data);
    }
}
