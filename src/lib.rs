extern crate byteorder;
#[macro_use]
extern crate lazy_static;
pub mod aes;
pub mod chacha20;
pub mod curve25519;
pub mod gcm;
pub mod ghash;
pub mod hkdf;
pub mod hmac;
pub mod sha2;
pub(crate) mod const_curve25519;

#[cfg(test)]
pub mod test_helpers {
    use std::str;

    // ew
    pub fn h2b(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks(2)
            .map(|x| {
                u8::from_str_radix(str::from_utf8(x).unwrap(), 16).unwrap()
            })
            .collect()
    }
}
