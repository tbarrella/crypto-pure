//! Module for for the HMAC-based Key Derivation Function (HKDF).
//!
//! # Examples
//!
//! ```
//! use crypto_pure::hkdf::{expand, extract};
//! use crypto_pure::sha2::{HashFunction, Sha512};
//! # let ikm = b"password";
//! # let salt = b"A non-secret random value.";
//! # let info = b"independent of the ikm";
//! let prk = &mut [0; Sha512::DIGEST_SIZE];
//! let okm = &mut [0; 64];
//! extract::<Sha512>(salt, ikm, prk);
//! expand::<Sha512>(prk, info, okm);
//! ```
use crate::hmac::Hmac;
use crate::sha2::HashFunction;

/// Extracts input keying material into a pseudorandom key using a salt.
///
/// # Panics
///
/// Panics if `prk.len()` is not equal to the digest size for `H`.
pub fn extract<H: HashFunction>(salt: &[u8], ikm: &[u8], prk: &mut [u8]) {
    assert_eq!(H::DIGEST_SIZE, prk.len());
    let mut hmac = Hmac::<H>::new(salt);
    hmac.update(ikm);
    let tag = hmac.tag();
    prk.copy_from_slice(&tag);
}

/// Expands a pseudorandom key into output keying material given optional information.
///
/// # Panics
///
/// Panics if `prk.len()` is less than the digest size for `H`, or if `okm.len()` is more than 255
/// times the digest size for `H`.
pub fn expand<H: HashFunction>(prk: &[u8], info: &[u8], okm: &mut [u8]) {
    let digest_size = H::DIGEST_SIZE;
    assert!(digest_size <= prk.len());
    assert!(255 * digest_size >= okm.len());
    let mut hmac: Hmac<H> = Hmac::new(prk);
    for (i, chunk) in (1..).zip(okm.chunks_mut(digest_size)) {
        hmac.update(info);
        hmac.update(&[i]);
        let tag = hmac.tag();
        let chunk_len = chunk.len();
        if chunk_len < digest_size {
            chunk.copy_from_slice(&tag[..chunk_len]);
            return;
        }
        chunk.copy_from_slice(&tag);
        hmac = Hmac::new(prk);
        hmac.update(chunk);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha2::Sha256;
    use crate::test_helpers::*;

    fn check(ikm: &str, salt: &str, info: &str, prk: &str, okm: &str) {
        let ikm = h2b(ikm);
        let salt = h2b(salt);
        let info = h2b(info);
        let prk = h2b(prk);
        let okm = h2b(okm);
        let mut actual = prk.clone();
        extract::<Sha256>(&salt, &ikm, &mut actual);
        assert_eq!(prk, actual);

        let mut actual = okm.clone();
        expand::<Sha256>(&prk, &info, &mut actual);
        assert_eq!(okm, actual);
    }

    #[test]
    fn test() {
        let ikm = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
        let salt = "000102030405060708090a0b0c";
        let info = "f0f1f2f3f4f5f6f7f8f9";
        let prk = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5";
        let okm = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
                   34007208d5b887185865";
        check(ikm, salt, info, prk, okm);

        let ikm = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
                   202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
                   404142434445464748494a4b4c4d4e4f";
        let salt = "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
                    808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
                    a0a1a2a3a4a5a6a7a8a9aaabacadaeaf";
        let info = "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
                    d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef\
                    f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
        let prk = "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244";
        let okm = "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
                   59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
                   cc30c58179ec3e87c14c01d5c1f3434f1d87";
        check(ikm, salt, info, prk, okm);

        let ikm = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
        let salt = "";
        let info = "";
        let prk = "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04";
        let okm = "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
                   9d201395faa4b61a96c8";
        check(ikm, salt, info, prk, okm);
    }
}
