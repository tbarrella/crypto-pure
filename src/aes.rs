const NK: usize = 8;
const NR: usize = NK + 6;

lazy_static! {
    static ref S_BOX: [u8; 256] = init_s_box();
    static ref INV_S_BOX: [u8; 256] = init_inv_s_box();
}

/// Don't use this! It's slow and susceptible to attacks.
pub struct AES {
    key_schedule: [u8; 16 * (NR + 1)],
}

impl AES {
    pub fn new(key: &[u8]) -> Self {
        assert_eq!(4 * NK, key.len());
        let mut aes = Self { key_schedule: [0; 16 * (NR + 1)] };
        Self::key_expansion(&mut aes.key_schedule, key);
        aes
    }

    pub fn cipher(&self, input: &[u8]) -> [u8; 16] {
        let mut state = [0; 16];
        state.copy_from_slice(input);
        self.add_round_key(&mut state, 0);
        for round in 1..NR {
            Self::sub_bytes(&mut state);
            Self::shift_rows(&mut state);
            Self::mix_columns(&mut state);
            self.add_round_key(&mut state, round);
        }
        Self::sub_bytes(&mut state);
        Self::shift_rows(&mut state);
        self.add_round_key(&mut state, NR);
        state
    }

    pub fn inv_cipher(&self, input: &[u8]) -> [u8; 16] {
        let mut state = [0; 16];
        state.copy_from_slice(input);
        self.add_round_key(&mut state, NR);
        Self::inv_shift_rows(&mut state);
        Self::inv_sub_bytes(&mut state);
        for round in (1..NR).rev() {
            self.add_round_key(&mut state, round);
            Self::inv_mix_columns(&mut state);
            Self::inv_shift_rows(&mut state);
            Self::inv_sub_bytes(&mut state);
        }
        self.add_round_key(&mut state, 0);
        state
    }

    fn key_expansion(schedule: &mut [u8], key: &[u8]) {
        schedule[..4 * NK].copy_from_slice(key);
        for i in NK..4 * (NR + 1) {
            let mut temp = [0; 4];
            temp.copy_from_slice(&schedule[4 * (i - 1)..4 * i]);
            if i % NK == 0 {
                Self::rot_word(&mut temp);
                Self::sub_word(&mut temp);
                temp[0] ^= 1 << (i / NK - 1);
            } else if NK > 6 && i % NK == 4 {
                Self::sub_word(&mut temp);
            }
            for j in 0..4 {
                schedule[4 * i + j] = schedule[4 * (i - NK) + j] ^ temp[j];
            }
        }
    }

    fn sub_word(word: &mut [u8; 4]) {
        Self::sub_bytes(word);
    }

    fn rot_word(word: &mut [u8; 4]) {
        let temp = word[0];
        for i in 0..3 {
            word[i] = word[i + 1];
        }
        word[3] = temp;
    }

    fn add_round_key(&self, state: &mut [u8; 16], round: usize) {
        for (byte, &k) in state.iter_mut().zip(self.get_round_key(round)) {
            *byte ^= k;
        }
    }

    fn get_round_key(&self, round: usize) -> &[u8] {
        &self.key_schedule[16 * round..16 * (round + 1)]
    }

    fn sub_bytes(state: &mut [u8]) {
        for byte in state {
            *byte = S_BOX[*byte as usize];
        }
    }

    fn inv_sub_bytes(state: &mut [u8]) {
        for byte in state {
            *byte = INV_S_BOX[*byte as usize];
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

    fn inv_shift_rows(state: &mut [u8; 16]) {
        let mut temp = state[13];
        for i in (0..3).rev() {
            state[1 + 4 * (i + 1)] = state[1 + 4 * i];
        }
        state[1] = temp;
        state.swap(2, 10);
        state.swap(6, 14);
        temp = state[3];
        for i in 0..3 {
            state[3 + 4 * i] = state[3 + 4 * (i + 1)];
        }
        state[15] = temp;
    }

    fn mix_columns(state: &mut [u8; 16]) {
        for i in 0..4 {
            let mut c = [0; 4];
            c.copy_from_slice(&state[4 * i..4 * (i + 1)]);
            let x2 = Self::xtime_column(&c);
            let x3 = Self::xor_column(&x2, &c);
            state[4 * i] = x2[0] ^ x3[1] ^ c[2] ^ c[3];
            state[4 * i + 1] = x2[1] ^ x3[2] ^ c[3] ^ c[0];
            state[4 * i + 2] = x2[2] ^ x3[3] ^ c[0] ^ c[1];
            state[4 * i + 3] = x2[3] ^ x3[0] ^ c[1] ^ c[2];
        }
    }

    fn inv_mix_columns(state: &mut [u8; 16]) {
        for i in 0..4 {
            let (x9, x11, x13, x14);
            {
                let s = &state[4 * i..4 * (i + 1)];
                let x2 = Self::xtime_column(s);
                let x4 = Self::xtime_column(&x2);
                let x8 = Self::xtime_column(&x4);
                x9 = Self::xor_column(&x8, s);
                x11 = Self::xor_column(&x9, &x2);
                x13 = Self::xor_column(&x9, &x4);
                let x12 = Self::xor_column(&x8, &x4);
                x14 = Self::xor_column(&x12, &x2);
            }
            state[4 * i] = x14[0] ^ x11[1] ^ x13[2] ^ x9[3];
            state[4 * i + 1] = x14[1] ^ x11[2] ^ x13[3] ^ x9[0];
            state[4 * i + 2] = x14[2] ^ x11[3] ^ x13[0] ^ x9[1];
            state[4 * i + 3] = x14[3] ^ x11[0] ^ x13[1] ^ x9[2];
        }
    }

    fn xor_column(a: &[u8], b: &[u8]) -> [u8; 4] {
        [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]]
    }

    fn xtime_column(c: &[u8]) -> [u8; 4] {
        [xtime(c[0]), xtime(c[1]), xtime(c[2]), xtime(c[3])]
    }
}

fn init_s_box() -> [u8; 256] {
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
    }
    {}
    s_box[0] = 0x63;
    s_box
}

fn init_inv_s_box() -> [u8; 256] {
    let mut inv_s_box = [0; 256];
    for (i, &s) in S_BOX.iter().enumerate() {
        inv_s_box[s as usize] = i as u8;
    }
    inv_s_box
}

fn xtime(byte: u8) -> u8 {
    let h = (byte as i8 >> 7) as u8;
    (byte << 1) ^ (0x1b & h)
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_helpers::*;

    const KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const INPUT: &str = "00112233445566778899aabbccddeeff";
    const OUTPUT: &str = "8ea2b7ca516745bfeafc49904b496089";
    const START: [&str; 14] = [
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
    const SUB_BYTES: [&str; 14] = [
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
    const SHIFT_ROWS: [&str; 14] = [
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
    const MIX_COLUMNS: [&str; 13] = [
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
    fn test_cipher() {
        let aes = AES::new(&h2b(KEY));
        assert_eq!(h2b(OUTPUT), aes.cipher(&h2b(INPUT)));
        assert_eq!(h2b(INPUT), aes.inv_cipher(&h2b(OUTPUT)));
    }

    #[test]
    fn test_key_expansion() {
        let key = h2b(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        );
        let key_schedule = h2b(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4\
             9ba354118e6925afa51a8b5f2067fcdea8b09c1a93d194cdbe49846eb75d5b9a\
             d59aecb85bf3c917fee94248de8ebe96b5a9328a2678a647983122292f6c79b3\
             812c81addadf48ba24360af2fab8b46498c5bfc9bebd198e268c3ba709e04214\
             68007bacb2df331696e939e46c518d80c814e20476a9fb8a5025c02d59c58239\
             de1369676ccc5a71fa2563959674ee155886ca5d2e2f31d77e0af1fa27cf73c3\
             749c47ab18501ddae2757e4f7401905acafaaae3e4d59b349adf6acebd10190d\
             fe4890d1e6188d0b046df344706c631e",
        );
        let mut schedule = [0; 240];
        AES::key_expansion(&mut schedule, &key);
        assert_eq!(key_schedule, schedule.to_vec());
    }

    #[test]
    fn test_add_round_key() {
        let aes = AES::new(&h2b(KEY));
        let mut state = [0; 16];
        state.copy_from_slice(&h2b(INPUT));
        aes.add_round_key(&mut state, 0);
        assert_eq!(h2b(START[0]), state);
        aes.add_round_key(&mut state, 0);
        assert_eq!(h2b(INPUT), state);

        for (i, (start, mix_columns)) in
            START
                .iter()
                .skip(1)
                .map(|x| h2b(&x))
                .zip(MIX_COLUMNS.iter().map(|x| h2b(&x)))
                .enumerate()
        {
            state.copy_from_slice(&mix_columns);
            aes.add_round_key(&mut state, i + 1);
            assert_eq!(start, state);
            aes.add_round_key(&mut state, i + 1);
            assert_eq!(mix_columns, state);
        }

        state.copy_from_slice(&h2b(SHIFT_ROWS[13]));
        aes.add_round_key(&mut state, 14);
        assert_eq!(h2b(OUTPUT), state);
        aes.add_round_key(&mut state, 14);
        assert_eq!(h2b(SHIFT_ROWS[13]), state);
    }

    #[test]
    fn test_sub_bytes() {
        let mut state = [0; 16];
        for (start, sub_bytes) in
            START.iter().map(|x| h2b(&x)).zip(SUB_BYTES.iter().map(
                |x| h2b(&x),
            ))
        {
            state.copy_from_slice(&start);
            AES::sub_bytes(&mut state);
            assert_eq!(sub_bytes, state);
            AES::inv_sub_bytes(&mut state);
            assert_eq!(start, state);
        }
    }

    #[test]
    fn test_shift_rows() {
        let mut state = [0; 16];
        for (sub_bytes, shift_rows) in
            SUB_BYTES.iter().map(|x| h2b(&x)).zip(
                SHIFT_ROWS.iter().map(
                    |x| {
                        h2b(&x)
                    },
                ),
            )
        {
            state.copy_from_slice(&sub_bytes);
            AES::shift_rows(&mut state);
            assert_eq!(shift_rows, state);
            AES::inv_shift_rows(&mut state);
            assert_eq!(sub_bytes, state);
        }
    }

    #[test]
    fn test_mix_columns() {
        let mut state = [0; 16];
        for (shift_rows, mix_columns) in
            SHIFT_ROWS.iter().map(|x| h2b(&x)).zip(
                MIX_COLUMNS.iter().map(
                    |x| {
                        h2b(&x)
                    },
                ),
            )
        {
            state.copy_from_slice(&shift_rows);
            AES::mix_columns(&mut state);
            assert_eq!(mix_columns, state);
            AES::inv_mix_columns(&mut state);
            assert_eq!(shift_rows, state);
        }
    }

    #[test]
    fn test_xtime() {
        let powers = [0x57, 0xae, 0x47, 0x8e, 0x07];
        for pair in powers.windows(2) {
            assert_eq!(pair[1], xtime(pair[0]));
        }
    }
}
