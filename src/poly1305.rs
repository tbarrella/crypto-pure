pub fn poly1305(key: &[u8], input: &[u8], output: &mut [u8]) {
    assert_eq!(32, key.len());
    assert_eq!(16, output.len());
    let r = &load_r(key);
    let h = &mut [0; 17];
    let c = &mut [0; 17];
    for block in input.chunks(16) {
        c[..block.len()].copy_from_slice(block);
        c[block.len()] = 1;
        for c_j in c.iter_mut().skip(block.len() + 1) {
            *c_j = 0;
        }
        add(h, c);
        mulmod(h, r);
    }
    freeze(h);
    c[..16].copy_from_slice(&key[16..]);
    c[16] = 0;
    add(h, c);
    for (&h_j, output_j) in h.iter().zip(output) {
        *output_j = h_j as u8;
    }
}

fn add(h: &mut [u32; 17], c: &[u8; 17]) {
    let mut u = 0;
    for (&c_j, h_j) in c.iter().zip(h) {
        u += *h_j + u32::from(c_j);
        *h_j = u & 255;
        u >>= 8;
    }
}

fn mulmod(h: &mut [u32; 17], r: &[u8; 17]) {
    let h_r = &mut [0; 17];
    for i in 0..17 {
        let mut u = 0;
        for j in 0..i + 1 {
            u += h[j] * u32::from(r[i - j]);
        }
        for j in i + 1..17 {
            u += 320 * h[j] * u32::from(r[i + 17 - j]);
        }
        h_r[i] = u;
    }
    h.copy_from_slice(h_r);
    squeeze(h);
}

/// Carries coefficients in the expansion of `h` so that each one is less than 256.
fn squeeze(h: &mut [u32; 17]) {
    let mut u = 0;
    for h_j in h.iter_mut().take(16) {
        u += *h_j;
        *h_j = u & 255;
        u >>= 8;
    }
    u += h[16];
    h[16] = u & 3;
    u = 5 * (u >> 2);
    for h_j in h.iter_mut().take(16) {
        u += *h_j;
        *h_j = u & 255;
        u >>= 8;
    }
    u += h[16];
    h[16] = u;
}

fn freeze(h: &mut [u32; 17]) {
    let h_orig = *h;
    add(h, &[5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252]);
    let negative = (h[16] >> 7).wrapping_neg();
    for (&h_orig_j, h_j) in h_orig.iter().zip(h) {
        *h_j ^= negative & (h_orig_j ^ *h_j);
    }
}

fn load_r(key: &[u8]) -> [u8; 17] {
    let mut r = [0; 17];
    r[0] = key[0];
    r[1] = key[1];
    r[2] = key[2];
    r[3] = key[3] & 15;
    r[4] = key[4] & 252;
    r[5] = key[5];
    r[6] = key[6];
    r[7] = key[7] & 15;
    r[8] = key[8] & 252;
    r[9] = key[9];
    r[10] = key[10];
    r[11] = key[11] & 15;
    r[12] = key[12] & 252;
    r[13] = key[13];
    r[14] = key[14];
    r[15] = key[15] & 15;
    r[16] = 0;
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_helpers::*;

    #[test]
    fn test_digest() {
        let key = &h2b(
            "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
        );
        let message = b"Cryptographic Forum Research Group";
        let tag = &h2b("a8061dc1305136c6c22b8baf0c0127a9");
        let actual = &mut vec![0; 16];
        poly1305(key, message, actual);
        assert_eq!(tag, actual);
    }
}
