use hmac;
use sha;

const HASH_LEN: usize = sha::SHA384_OUTPUT_LEN;

pub struct HkdfSha384 {}

// TODO: tests
impl HkdfSha384 {
    pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; HASH_LEN] {
        Self::hash(salt, ikm)
    }

    pub fn expand(prk: &[u8], info: &[u8], l: usize) -> Vec<u8> {
        assert!(HASH_LEN <= prk.len());
        assert!(255 * HASH_LEN >= l);
        let n = ((l + HASH_LEN - 1) / HASH_LEN) as u8;
        let mut t = vec![];
        let mut input = vec![];
        for i in 1..(n + 1) {
            input.extend_from_slice(info);
            input.push(i);
            input = Self::hash(prk, &input).to_vec();
            t.extend(&input);
        }
        t.truncate(l);
        t
    }

    fn hash(key: &[u8], message: &[u8]) -> [u8; HASH_LEN] {
        hmac::HmacSha384::digest(key, message)
    }
}
