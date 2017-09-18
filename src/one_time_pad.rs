use std::io;
use key;

/// Currently doesn't accept a key because there should be only one key per message
pub fn encrypt(message: &[u8]) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let key = key::new(message.len())?;
    let ciphertext = xor(&key, &message);
    Ok((key, ciphertext))
}

pub fn decrypt(key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    xor(&key, &ciphertext)
}

fn xor(lhs: &[u8], rhs: &[u8]) -> Vec<u8> {
    lhs.iter().zip(rhs).map(|(x, y)| x ^ y).collect()
}

#[cfg(test)]
mod tests {
    use std::str;
    use one_time_pad::*;

    #[test]
    fn test_xor() {
        assert_eq!(vec![3, 1], xor(&[1, 2], &[2, 3]));
    }

    #[test]
    fn test_encrypt_decrypt() {
        fn check(message: &str) {
            let (key, ciphertext) = encrypt(message.as_bytes()).unwrap();
            assert_eq!(
                message,
                str::from_utf8(&decrypt(&key, &ciphertext)).unwrap()
            );
        }

        check("Hello!");
        check("How are you?");
        check("1 + 1 = 2");
    }
}
