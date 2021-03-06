//! Module for the AES block cipher.
//!
//! Do not use these module directly for encryption. The AES structs should only be used as a
//! parameter for an encryption mode of operation, such as GCM.

/// A trait for block ciphers with a block size of 16 bytes.
pub trait BlockCipher {
    /// Initializes a block cipher given a key.
    fn new(key: &[u8]) -> Self;

    /// Outputs a permutation of the input block.
    fn permute(&self, input: &[u8; 16]) -> [u8; 16];
}

macro_rules! impl_cipher {
    ($cipher:ident, $nk:expr) => {
        pub struct $cipher([u8; 16 * ($nk + 6 + 1)]);

        impl BlockCipher for $cipher {
            fn new(key: &[u8]) -> Self {
                Self(Self::key_expansion(key))
            }

            fn permute(&self, input: &[u8; 16]) -> [u8; 16] {
                let mut output = *input;
                self.add_round_key(&mut output, 0);
                for round in 1..Self::NR {
                    sub_bytes(&mut output);
                    shift_rows(&mut output);
                    mix_columns(&mut output);
                    self.add_round_key(&mut output, round);
                }
                sub_bytes(&mut output);
                shift_rows(&mut output);
                self.add_round_key(&mut output, Self::NR);
                output
            }
        }

        impl $cipher {
            const NK: usize = $nk;
            const NR: usize = Self::NK + 6;

            fn key_expansion(key: &[u8]) -> [u8; 16 * (Self::NR + 1)] {
                assert_eq!(4 * Self::NK, key.len());
                let mut schedule = [0; 16 * (Self::NR + 1)];
                schedule[..4 * Self::NK].copy_from_slice(key);
                let mut rcon = 0x01;
                for i in Self::NK..4 * (Self::NR + 1) {
                    let temp = &mut [0; 4];
                    temp.copy_from_slice(&schedule[4 * (i - 1)..4 * i]);
                    if i % Self::NK == 0 {
                        temp.rotate_left(1);
                        sub_word(temp);
                        temp[0] ^= rcon;
                        rcon = xtime(rcon);
                    } else if Self::NK > 6 && i % Self::NK == 4 {
                        sub_word(temp);
                    }
                    for j in 0..4 {
                        schedule[4 * i + j] = schedule[4 * (i - Self::NK) + j] ^ temp[j];
                    }
                }
                schedule
            }

            fn add_round_key(&self, state: &mut [u8; 16], round: usize) {
                for (byte, k) in state.iter_mut().zip(self.round_key(round)) {
                    *byte ^= k;
                }
            }

            fn round_key(&self, round: usize) -> &[u8] {
                &self.0[16 * round..16 * (round + 1)]
            }
        }
    };
}

impl_cipher!(Aes256, 8);
impl_cipher!(Aes192, 6);
impl_cipher!(Aes128, 4);

fn sub_word(word: &mut [u8; 4]) {
    for byte in word {
        *byte = s_box(*byte);
    }
}

fn sub_bytes(state: &mut [u8; 16]) {
    for byte in state {
        *byte = s_box(*byte);
    }
}

fn shift_rows(state: &mut [u8; 16]) {
    let mut temp = state[1];
    for i in 0..3 {
        state[1 + 4 * i] = state[1 + 4 * (i + 1)];
    }
    state[13] = temp;
    state.swap(2, 10);
    state.swap(6, 14);
    temp = state[15];
    for i in (0..3).rev() {
        state[3 + 4 * (i + 1)] = state[3 + 4 * i];
    }
    state[3] = temp;
}

fn mix_columns(state: &mut [u8; 16]) {
    for column in state.chunks_mut(4) {
        let mut c = [0; 4];
        c.copy_from_slice(column);
        let x2 = xtime_column(c);
        let x3 = xor_column(x2, c);
        column[0] = x2[0] ^ x3[1] ^ c[2] ^ c[3];
        column[1] = x2[1] ^ x3[2] ^ c[3] ^ c[0];
        column[2] = x2[2] ^ x3[3] ^ c[0] ^ c[1];
        column[3] = x2[3] ^ x3[0] ^ c[1] ^ c[2];
    }
}

fn xor_column(a: [u8; 4], b: [u8; 4]) -> [u8; 4] {
    [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]]
}

fn xtime_column(c: [u8; 4]) -> [u8; 4] {
    [xtime(c[0]), xtime(c[1]), xtime(c[2]), xtime(c[3])]
}

fn xtime(byte: u8) -> u8 {
    let h = (byte as i8 >> 7) as u8;
    (byte << 1) ^ (0x1b & h)
}

// S-box implementation from
// David Canright. A very compact Rijndael S-box. 2004.
const A2X: [u8; 8] = [0x98, 0xF3, 0xF2, 0x48, 0x09, 0x81, 0xA9, 0xFF];
const X2S: [u8; 8] = [0x58, 0x2D, 0x9E, 0x0B, 0xDC, 0x04, 0x03, 0x24];

fn s_box(n: u8) -> u8 {
    let mut t = g256_newbasis(n, A2X);
    t = g256_inv(t);
    t = g256_newbasis(t, X2S);
    t ^ 0x63
}

fn g256_newbasis(x: u8, b: [u8; 8]) -> u8 {
    let mut x = x;
    let mut y = 0;
    for &b_i in b.iter().rev() {
        let h = x << 7;
        let m = (h as i8 >> 7) as u8;
        y ^= b_i & m;
        x >>= 1;
    }
    y
}

fn g256_inv(x: u8) -> u8 {
    let a = (x & 0xf0) >> 4;
    let b = x & 0x0f;
    let c = g16_sq_scl(a ^ b);
    let d = g16_mul(a, b);
    let e = g16_inv(c ^ d);
    let p = g16_mul(e, b);
    let q = g16_mul(e, a);
    (p << 4) | q
}

fn g16_inv(x: u8) -> u8 {
    let a = (x & 0xc) >> 2;
    let b = x & 0x3;
    let c = g4_scl_n(g4_sq(a ^ b));
    let d = g4_mul(a, b);
    let e = g4_sq(c ^ d);
    let p = g4_mul(e, b);
    let q = g4_mul(e, a);
    (p << 2) | q
}

fn g16_mul(x: u8, y: u8) -> u8 {
    let a = (x & 0xc) >> 2;
    let b = x & 0x3;
    let c = (y & 0xc) >> 2;
    let d = y & 0x3;
    let mut e = g4_mul(a ^ b, c ^ d);
    e = g4_scl_n(e);
    let p = g4_mul(a, c) ^ e;
    let q = g4_mul(b, d) ^ e;
    (p << 2) | q
}

fn g16_sq_scl(x: u8) -> u8 {
    let a = (x & 0xc) >> 2;
    let b = x & 0x3;
    let p = g4_sq(a ^ b);
    let q = g4_scl_n2(g4_sq(b));
    (p << 2) | q
}

fn g4_mul(x: u8, y: u8) -> u8 {
    let a = (x & 0x2) >> 1;
    let b = x & 0x1;
    let c = (y & 0x2) >> 1;
    let d = y & 0x1;
    let e = (a ^ b) & (c ^ d);
    let p = (a & c) ^ e;
    let q = (b & d) ^ e;
    (p << 1) | q
}

fn g4_scl_n(x: u8) -> u8 {
    let a = (x & 0x2) >> 1;
    let b = x & 0x1;
    let p = b;
    let q = a ^ b;
    (p << 1) | q
}

fn g4_scl_n2(x: u8) -> u8 {
    let a = (x & 0x2) >> 1;
    let b = x & 0x1;
    let p = a ^ b;
    let q = a;
    (p << 1) | q
}

fn g4_sq(x: u8) -> u8 {
    let a = (x & 0x2) >> 1;
    let b = x & 0x1;
    (b << 1) | a
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::*;

    fn create_s_box() -> [u8; 256] {
        let mut s_box = [0; 256];
        let mut p = 1;
        let mut q = 1;
        while {
            p ^= xtime(p);
            q ^= q << 1;
            q ^= q << 2;
            q ^= q << 4;
            let h = (q as i8 >> 7) as u8;
            q ^= 0x09 & h;
            let x = q ^ q.rotate_left(1) ^ q.rotate_left(2) ^ q.rotate_left(3) ^ q.rotate_left(4);
            s_box[p as usize] = x ^ 0x63;
            p != 1
        } {}
        s_box[0] = 0x63;
        s_box
    }

    const KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const INPUT: &str = "00112233445566778899aabbccddeeff";
    const OUTPUT: &str = "8ea2b7ca516745bfeafc49904b496089";
    const START: &[&str; 14] = &[
        "00102030405060708090a0b0c0d0e0f0",
        "4f63760643e0aa85efa7213201a4e705",
        "1859fbc28a1c00a078ed8aadc42f6109",
        "975c66c1cb9f3fa8a93a28df8ee10f63",
        "1c05f271a417e04ff921c5c104701554",
        "c357aae11b45b7b0a2c7bd28a8dc99fa",
        "7f074143cb4e243ec10c815d8375d54c",
        "d653a4696ca0bc0f5acaab5db96c5e7d",
        "5aa858395fd28d7d05e1a38868f3b9c5",
        "4a824851c57e7e47643de50c2af3e8c9",
        "c14907f6ca3b3aa070e9aa313b52b5ec",
        "5f9c6abfbac634aa50409fa766677653",
        "516604954353950314fb86e401922521",
        "627bceb9999d5aaac945ecf423f56da5",
    ];
    const SUB_BYTES: &[&str; 14] = &[
        "63cab7040953d051cd60e0e7ba70e18c",
        "84fb386f1ae1ac97df5cfd237c49946b",
        "adcb0f257e9c63e0bc557e951c15ef01",
        "884a33781fdb75c2d380349e19f876fb",
        "9c6b89a349f0e18499fda678f2515920",
        "2e5bacf8af6ea9e73ac67a34c286ee2d",
        "d2c5831a1f2f36b278fe0c4cec9d0329",
        "f6ed49f950e06576be74624c565058ff",
        "bec26a12cfb55dff6bf80ac4450d56a6",
        "d61352d1a6f3f3a04327d9fee50d9bdd",
        "783bc54274e280e0511eacc7e200d5ce",
        "cfde0208f4b418ac5309db5c338538ed",
        "d133f22a1aed2a7bfa0f44697c4f3ffd",
        "aa218b56ee5ebeacdd6ecebf26e63c06",
    ];
    const SHIFT_ROWS: &[&str; 14] = &[
        "6353e08c0960e104cd70b751bacad0e7",
        "84e1fd6b1a5c946fdf4938977cfbac23",
        "ad9c7e017e55ef25bc150fe01ccb6395",
        "88db34fb1f807678d3f833c2194a759e",
        "9cf0a62049fd59a399518984f26be178",
        "2e6e7a2dafc6eef83a86ace7c25ba934",
        "d22f0c291ffe031a789d83b2ecc5364c",
        "f6e062ff507458f9be50497656ed654c",
        "beb50aa6cff856126b0d6aff45c25dc4",
        "d6f3d9dda6279bd1430d52a0e513f3fe",
        "78e2acce741ed5425100c5e0e23b80c7",
        "cfb4dbedf4093808538502ac33de185c",
        "d1ed44fd1a0f3f2afa4ff27b7c332a69",
        "aa5ece06ee6e3c56dde68bac2621bebf",
    ];
    const MIX_COLUMNS: &[&str; 13] = &[
        "5f72641557f5bc92f7be3b291db9f91a",
        "bd2a395d2b6ac438d192443e615da195",
        "810dce0cc9db8172b3678c1e88a1b5bd",
        "b2822d81abe6fb275faf103a078c0033",
        "aeb65ba974e0f822d73f567bdb64c877",
        "b951c33c02e9bd29ae25cdb1efa08cc7",
        "ebb19e1c3ee7c9e87d7535e9ed6b9144",
        "5174c8669da98435a8b3e62ca974a5ea",
        "0f77ee31d2ccadc05430a83f4ef96ac3",
        "bd86f0ea748fc4f4630f11c1e9331233",
        "af8690415d6e1dd387e5fbedd5c89013",
        "7427fae4d8a695269ce83d315be0392b",
        "2c21a820306f154ab712c75eee0da04f",
    ];

    #[test]
    fn test_permute() {
        let input = &mut [0; 16];
        input.copy_from_slice(&h2b(INPUT));
        let key = &h2b(KEY);
        let output = h2b(OUTPUT);
        let aes = Aes256::new(key);
        assert_eq!(output, aes.permute(input));

        let key = &h2b("000102030405060708090a0b0c0d0e0f1011121314151617");
        let output = h2b("dda97ca4864cdfe06eaf70a0ec0d7191");
        let aes = Aes192::new(key);
        assert_eq!(output, aes.permute(input));

        let key = &h2b("000102030405060708090a0b0c0d0e0f");
        let output = h2b("69c4e0d86a7b0430d8cdb78070b4c55a");
        let aes = Aes128::new(key);
        assert_eq!(output, aes.permute(input));
    }

    #[test]
    fn test_key_expansion() {
        let key = &h2b("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let schedule = h2b(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4\
             9ba354118e6925afa51a8b5f2067fcdea8b09c1a93d194cdbe49846eb75d5b9a\
             d59aecb85bf3c917fee94248de8ebe96b5a9328a2678a647983122292f6c79b3\
             812c81addadf48ba24360af2fab8b46498c5bfc9bebd198e268c3ba709e04214\
             68007bacb2df331696e939e46c518d80c814e20476a9fb8a5025c02d59c58239\
             de1369676ccc5a71fa2563959674ee155886ca5d2e2f31d77e0af1fa27cf73c3\
             749c47ab18501ddae2757e4f7401905acafaaae3e4d59b349adf6acebd10190d\
             fe4890d1e6188d0b046df344706c631e",
        );
        let key_schedule = Aes256::key_expansion(key);
        assert_eq!(schedule, key_schedule.to_vec());
    }

    #[test]
    fn test_add_round_key() {
        let aes = Aes256::new(&h2b(KEY));
        let state = &mut [0; 16];
        state.copy_from_slice(&h2b(INPUT));
        aes.add_round_key(state, 0);
        assert_eq!(&h2b(START[0]), state);
        aes.add_round_key(state, 0);
        assert_eq!(&h2b(INPUT), state);

        for (i, (before, after)) in START
            .iter()
            .skip(1)
            .map(|x| h2b(x))
            .zip(MIX_COLUMNS)
            .enumerate()
        {
            let after = &h2b(after);
            state.copy_from_slice(after);
            aes.add_round_key(state, i + 1);
            assert_eq!(&before, state);
            aes.add_round_key(state, i + 1);
            assert_eq!(after, state);
        }

        state.copy_from_slice(&h2b(SHIFT_ROWS[13]));
        aes.add_round_key(state, 14);
        assert_eq!(&h2b(OUTPUT), state);
        aes.add_round_key(state, 14);
        assert_eq!(&h2b(SHIFT_ROWS[13]), state);
    }

    #[test]
    fn test_sub_bytes() {
        let state = &mut [0; 16];
        for (before, after) in START.iter().map(|x| h2b(x)).zip(SUB_BYTES) {
            let after = &h2b(after);
            state.copy_from_slice(&before);
            sub_bytes(state);
            assert_eq!(after, state);
        }
    }

    #[test]
    fn test_shift_rows() {
        let state = &mut [0; 16];
        for (before, after) in SUB_BYTES.iter().map(|x| h2b(x)).zip(SHIFT_ROWS) {
            let after = &h2b(after);
            state.copy_from_slice(&before);
            shift_rows(state);
            assert_eq!(after, state);
        }
    }

    #[test]
    fn test_mix_columns() {
        let state = &mut [0; 16];
        for (before, after) in SHIFT_ROWS.iter().map(|x| h2b(x)).zip(MIX_COLUMNS) {
            let after = &h2b(after);
            state.copy_from_slice(&before);
            mix_columns(state);
            assert_eq!(after, state);
        }
    }

    #[test]
    fn test_xtime() {
        let powers = [0x57, 0xae, 0x47, 0x8e, 0x07];
        for pair in powers.windows(2) {
            assert_eq!(pair[1], xtime(pair[0]));
        }
    }

    #[test]
    fn test_s_box() {
        let s_box_array = create_s_box();
        for (i, &y) in s_box_array.iter().enumerate() {
            let x = i as u8;
            assert_eq!(y, s_box(x));
        }
    }
}
