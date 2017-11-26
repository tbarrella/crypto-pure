//! Module for utility functions.

/// Verifies equality between an array of length 16 and a slice of unknown length.
pub fn verify_16(x: &[u8; 16], y: &[u8]) -> bool {
    x.len() == y.len() && verify_inner(x, y) == 0
}

#[inline(never)]
pub(crate) fn verify_inner<A: AsRef<[u8]>>(x: &A, y: &[u8]) -> u8 {
    let x = x.as_ref();
    assert_eq!(x.len(), y.len());
    x.iter().zip(y).fold(0, |acc, (x, y)| acc | (x ^ y))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_16() {
        assert!(verify_16(b"abcdefghijklmnop", b"abcdefghijklmnop"));
        assert!(verify_16(&[0xff; 16], &[0xff; 16]));
        assert!(verify_16(&[0x80; 16], &[0x80; 16]));

        assert!(!verify_16(b"abcdefghijklmnop", b"ponmlkjihgfedcba"));
        assert!(!verify_16(b"abcdefghijklmnop", b""));
        assert!(!verify_16(b"abcdefghijklmnop", b"abcd"));
        assert!(!verify_16(&[0xff; 16], &[0x80; 16]));
        assert!(!verify_16(&[0xff; 16], &[0x80; 4]));
        assert!(!verify_16(&[0x80; 16], &[0xff; 16]));
        assert!(!verify_16(&[0x80; 16], &[0xff; 4]));
    }

    #[test]
    fn test_verify_inner() {
        assert_eq!(0, verify_inner(b"", b""));
        assert_eq!(0, verify_inner(b"Hello!", b"Hello!"));
        assert_eq!(0, verify_inner(&[0x80, 0xff], &[0x80, 0xff]));

        assert_ne!(0, verify_inner(b"ok", b"ko"));
        assert_ne!(0, verify_inner(&[0x80, 0xff], &[0xff, 0x80]));
    }
}
