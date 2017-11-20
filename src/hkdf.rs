use hmac::{hmac_sha384, Hmac};
use sha2::{HashFunction, Sha384};

const HASH_LEN: usize = Sha384::DIGEST_SIZE;

pub struct HkdfSha384;

// TODO: tests
impl HkdfSha384 {
    pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; HASH_LEN] {
        hmac_sha384(salt, ikm)
    }

    pub fn expand(prk: &[u8], info: &[u8], okm: &mut [u8]) {
        assert!(HASH_LEN <= prk.len());
        let l = okm.len();
        assert!(255 * HASH_LEN >= l);
        assert!(0 < l);
        let n = ((l + HASH_LEN - 1) / HASH_LEN) as u8;
        let mut hmac: Hmac<Sha384> = Hmac::new(prk);
        for (i, chunk) in (1..n).zip(okm.chunks_mut(HASH_LEN)) {
            hmac.update(info);
            hmac.update(&[i]);
            hmac.write_digest(chunk);
            hmac = Hmac::new(prk);
            hmac.update(chunk);
        }
        hmac.update(info);
        hmac.update(&[n]);
        let final_chunk = &mut [0; HASH_LEN];
        hmac.write_digest(final_chunk);
        let i = HASH_LEN * (n - 1) as usize;
        okm[i..].copy_from_slice(&final_chunk[..l - i]);
    }
}
