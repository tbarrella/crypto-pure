use std::iter;
use byteorder::{BigEndian, ByteOrder};

pub struct SHA512 {}

impl SHA512 {
    /// Only supports messages with at most 2^64 bytes for now
    pub fn pad(bytes: &mut Vec<u8>) {
        let len = len(bytes);
        bytes.push(0x80);
        let padding = (128 + 112 - bytes.len() % 128) % 128;
        bytes.extend(iter::repeat(0).take(padding));
        bytes.extend_from_slice(&[0; 8]);
        bytes.extend_from_slice(&len);
    }
}

fn len(bytes: &[u8]) -> [u8; 8] {
    let mut len = [0; 8];
    BigEndian::write_u64(&mut len, 8 * bytes.len() as u64);
    len
}

#[cfg(test)]
mod tests {
    use sha::*;
    use test_helpers::*;

    #[test]
    fn test_pad() {
        let mut message = vec![0b01100001, 0b01100010, 0b01100011, 0b01100100, 0b01100101];
        let expected = h2b(
            "6162636465800000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000028",
        );
        SHA512::pad(&mut message);
        assert_eq!(expected, message);
    }
}
