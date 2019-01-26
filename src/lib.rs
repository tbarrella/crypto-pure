#![cfg_attr(not(feature = "std"), no_std)]
#[cfg(feature = "std")]
extern crate core;

#[cfg(not(feature = "std"))]
#[macro_use]
pub(crate) extern crate std;

pub mod aes;
pub mod chacha20;
pub(crate) mod const_curve25519;
pub mod curve25519;
pub mod ed25519;
pub mod gcm;
pub(crate) mod ghash;
pub mod hkdf;
pub mod hmac;
pub mod poly1305;
pub mod sha2;
pub mod util;

#[cfg(test)]
pub mod test_helpers {
    use std::str;
    use std::vec::Vec;

    // ew
    pub fn h2b(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks(2)
            .map(|x| u8::from_str_radix(str::from_utf8(x).unwrap(), 16).unwrap())
            .collect()
    }
}
