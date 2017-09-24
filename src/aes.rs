/// Don't use this! It's slow and susceptible to attacks.
pub struct AES {
    key_schedule: [u8; 240],
}

lazy_static! {
    static ref S_BOX: [u8; 256] = init_s_box();
    static ref INV_S_BOX: [u8; 256] = init_inv_s_box();
}

impl AES {
    pub fn new(key: &[u8]) -> Self {
        let mut key_schedule = [0; 240];
        Self::key_expansion(&mut key_schedule, key);
        Self { key_schedule: key_schedule }
    }

    pub fn cipher(&self, input: &[u8]) -> [u8; 16] {
        let mut state = [0; 16];
        state.copy_from_slice(input);
        self.add_round_key(&mut state, 0);
        for round in 1..14 {
            Self::sub_bytes(&mut state);
            Self::shift_rows(&mut state);
            Self::mix_columns(&mut state);
            self.add_round_key(&mut state, round);
        }
        Self::sub_bytes(&mut state);
        Self::shift_rows(&mut state);
        self.add_round_key(&mut state, 14);
        state
    }

    pub fn inv_cipher(&self, input: &[u8]) -> [u8; 16] {
        let mut state = [0; 16];
        state.copy_from_slice(input);
        self.add_round_key(&mut state, 14);
        Self::inv_shift_rows(&mut state);
        Self::inv_sub_bytes(&mut state);
        for round in (1..14).rev() {
            self.add_round_key(&mut state, round);
            Self::inv_mix_columns(&mut state);
            Self::inv_shift_rows(&mut state);
            Self::inv_sub_bytes(&mut state);
        }
        self.add_round_key(&mut state, 0);
        state
    }

    fn key_expansion(schedule: &mut [u8], key: &[u8]) {
        for i in 0..8 {
            schedule[4 * i..4 * (i + 1)].copy_from_slice(&key[4 * i..4 * (i + 1)]);
        }
        for i in 8..4 * 15 {
            let mut temp = [0; 4];
            temp.copy_from_slice(&schedule[4 * (i - 1)..4 * i]);
            if i % 8 == 0 {
                Self::rot_word(&mut temp);
                Self::sub_word(&mut temp);
                temp[0] ^= 1 << (i / 8 - 1);
            } else if i % 8 == 4 {
                Self::sub_word(&mut temp);
            }
            for j in 0..4 {
                schedule[4 * i + j] = schedule[4 * (i - 8) + j] ^ temp[j];
            }
        }
    }

    fn sub_word(word: &mut [u8]) {
        Self::sub_bytes(word);
    }

    fn rot_word(word: &mut [u8]) {
        let temp = word[0];
        for i in 0..3 {
            word[i] = word[i + 1];
        }
        word[3] = temp;
    }

    fn add_round_key(&self, state: &mut [u8], round: usize) {
        for i in 0..4 {
            for j in 0..4 {
                state[i + 4 * j] ^= self.key_schedule[4 * (4 * round + j) + i];
            }
        }
    }

    fn sub_bytes(state: &mut [u8]) {
        for byte in state.iter_mut() {
            *byte = S_BOX[*byte as usize];
        }
    }

    fn inv_sub_bytes(state: &mut [u8]) {
        for byte in state.iter_mut() {
            *byte = INV_S_BOX[*byte as usize];
        }
    }

    fn shift_rows(state: &mut [u8]) {
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

    fn inv_shift_rows(state: &mut [u8]) {
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

    fn mix_columns(state: &mut [u8]) {
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

    fn inv_mix_columns(state: &mut [u8]) {
        for i in 0..4 {
            let (x9, x11, x13, x14);
            {
                let c = &state[4 * i..4 * (i + 1)];
                let x2 = Self::xtime_column(c);
                let x4 = Self::xtime_column(&x2);
                let x8 = Self::xtime_column(&x4);
                x9 = Self::xor_column(&x8, c);
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
    use aes::*;

    const KEY: [u8; 32] = [
        0x00,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0a,
        0x0b,
        0x0c,
        0x0d,
        0x0e,
        0x0f,
        0x10,
        0x11,
        0x12,
        0x13,
        0x14,
        0x15,
        0x16,
        0x17,
        0x18,
        0x19,
        0x1a,
        0x1b,
        0x1c,
        0x1d,
        0x1e,
        0x1f,
    ];
    const INPUT: [u8; 16] = [
        0x00,
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        0x88,
        0x99,
        0xaa,
        0xbb,
        0xcc,
        0xdd,
        0xee,
        0xff,
    ];
    const OUTPUT: [u8; 16] = [
        0x8e,
        0xa2,
        0xb7,
        0xca,
        0x51,
        0x67,
        0x45,
        0xbf,
        0xea,
        0xfc,
        0x49,
        0x90,
        0x4b,
        0x49,
        0x60,
        0x89,
    ];
    const START: [[u8; 16]; 14] = [
        [
            0x00,
            0x10,
            0x20,
            0x30,
            0x40,
            0x50,
            0x60,
            0x70,
            0x80,
            0x90,
            0xa0,
            0xb0,
            0xc0,
            0xd0,
            0xe0,
            0xf0,
        ],
        [
            0x4f,
            0x63,
            0x76,
            0x06,
            0x43,
            0xe0,
            0xaa,
            0x85,
            0xef,
            0xa7,
            0x21,
            0x32,
            0x01,
            0xa4,
            0xe7,
            0x05,
        ],
        [
            0x18,
            0x59,
            0xfb,
            0xc2,
            0x8a,
            0x1c,
            0x00,
            0xa0,
            0x78,
            0xed,
            0x8a,
            0xad,
            0xc4,
            0x2f,
            0x61,
            0x09,
        ],
        [
            0x97,
            0x5c,
            0x66,
            0xc1,
            0xcb,
            0x9f,
            0x3f,
            0xa8,
            0xa9,
            0x3a,
            0x28,
            0xdf,
            0x8e,
            0xe1,
            0x0f,
            0x63,
        ],
        [
            0x1c,
            0x05,
            0xf2,
            0x71,
            0xa4,
            0x17,
            0xe0,
            0x4f,
            0xf9,
            0x21,
            0xc5,
            0xc1,
            0x04,
            0x70,
            0x15,
            0x54,
        ],
        [
            0xc3,
            0x57,
            0xaa,
            0xe1,
            0x1b,
            0x45,
            0xb7,
            0xb0,
            0xa2,
            0xc7,
            0xbd,
            0x28,
            0xa8,
            0xdc,
            0x99,
            0xfa,
        ],
        [
            0x7f,
            0x07,
            0x41,
            0x43,
            0xcb,
            0x4e,
            0x24,
            0x3e,
            0xc1,
            0x0c,
            0x81,
            0x5d,
            0x83,
            0x75,
            0xd5,
            0x4c,
        ],
        [
            0xd6,
            0x53,
            0xa4,
            0x69,
            0x6c,
            0xa0,
            0xbc,
            0x0f,
            0x5a,
            0xca,
            0xab,
            0x5d,
            0xb9,
            0x6c,
            0x5e,
            0x7d,
        ],
        [
            0x5a,
            0xa8,
            0x58,
            0x39,
            0x5f,
            0xd2,
            0x8d,
            0x7d,
            0x05,
            0xe1,
            0xa3,
            0x88,
            0x68,
            0xf3,
            0xb9,
            0xc5,
        ],
        [
            0x4a,
            0x82,
            0x48,
            0x51,
            0xc5,
            0x7e,
            0x7e,
            0x47,
            0x64,
            0x3d,
            0xe5,
            0x0c,
            0x2a,
            0xf3,
            0xe8,
            0xc9,
        ],
        [
            0xc1,
            0x49,
            0x07,
            0xf6,
            0xca,
            0x3b,
            0x3a,
            0xa0,
            0x70,
            0xe9,
            0xaa,
            0x31,
            0x3b,
            0x52,
            0xb5,
            0xec,
        ],
        [
            0x5f,
            0x9c,
            0x6a,
            0xbf,
            0xba,
            0xc6,
            0x34,
            0xaa,
            0x50,
            0x40,
            0x9f,
            0xa7,
            0x66,
            0x67,
            0x76,
            0x53,
        ],
        [
            0x51,
            0x66,
            0x04,
            0x95,
            0x43,
            0x53,
            0x95,
            0x03,
            0x14,
            0xfb,
            0x86,
            0xe4,
            0x01,
            0x92,
            0x25,
            0x21,
        ],
        [
            0x62,
            0x7b,
            0xce,
            0xb9,
            0x99,
            0x9d,
            0x5a,
            0xaa,
            0xc9,
            0x45,
            0xec,
            0xf4,
            0x23,
            0xf5,
            0x6d,
            0xa5,
        ],
    ];
    const SUB_BYTES: [[u8; 16]; 14] = [
        [
            0x63,
            0xca,
            0xb7,
            0x04,
            0x09,
            0x53,
            0xd0,
            0x51,
            0xcd,
            0x60,
            0xe0,
            0xe7,
            0xba,
            0x70,
            0xe1,
            0x8c,
        ],
        [
            0x84,
            0xfb,
            0x38,
            0x6f,
            0x1a,
            0xe1,
            0xac,
            0x97,
            0xdf,
            0x5c,
            0xfd,
            0x23,
            0x7c,
            0x49,
            0x94,
            0x6b,
        ],
        [
            0xad,
            0xcb,
            0x0f,
            0x25,
            0x7e,
            0x9c,
            0x63,
            0xe0,
            0xbc,
            0x55,
            0x7e,
            0x95,
            0x1c,
            0x15,
            0xef,
            0x01,
        ],
        [
            0x88,
            0x4a,
            0x33,
            0x78,
            0x1f,
            0xdb,
            0x75,
            0xc2,
            0xd3,
            0x80,
            0x34,
            0x9e,
            0x19,
            0xf8,
            0x76,
            0xfb,
        ],
        [
            0x9c,
            0x6b,
            0x89,
            0xa3,
            0x49,
            0xf0,
            0xe1,
            0x84,
            0x99,
            0xfd,
            0xa6,
            0x78,
            0xf2,
            0x51,
            0x59,
            0x20,
        ],
        [
            0x2e,
            0x5b,
            0xac,
            0xf8,
            0xaf,
            0x6e,
            0xa9,
            0xe7,
            0x3a,
            0xc6,
            0x7a,
            0x34,
            0xc2,
            0x86,
            0xee,
            0x2d,
        ],
        [
            0xd2,
            0xc5,
            0x83,
            0x1a,
            0x1f,
            0x2f,
            0x36,
            0xb2,
            0x78,
            0xfe,
            0x0c,
            0x4c,
            0xec,
            0x9d,
            0x03,
            0x29,
        ],
        [
            0xf6,
            0xed,
            0x49,
            0xf9,
            0x50,
            0xe0,
            0x65,
            0x76,
            0xbe,
            0x74,
            0x62,
            0x4c,
            0x56,
            0x50,
            0x58,
            0xff,
        ],
        [
            0xbe,
            0xc2,
            0x6a,
            0x12,
            0xcf,
            0xb5,
            0x5d,
            0xff,
            0x6b,
            0xf8,
            0x0a,
            0xc4,
            0x45,
            0x0d,
            0x56,
            0xa6,
        ],
        [
            0xd6,
            0x13,
            0x52,
            0xd1,
            0xa6,
            0xf3,
            0xf3,
            0xa0,
            0x43,
            0x27,
            0xd9,
            0xfe,
            0xe5,
            0x0d,
            0x9b,
            0xdd,
        ],
        [
            0x78,
            0x3b,
            0xc5,
            0x42,
            0x74,
            0xe2,
            0x80,
            0xe0,
            0x51,
            0x1e,
            0xac,
            0xc7,
            0xe2,
            0x00,
            0xd5,
            0xce,
        ],
        [
            0xcf,
            0xde,
            0x02,
            0x08,
            0xf4,
            0xb4,
            0x18,
            0xac,
            0x53,
            0x09,
            0xdb,
            0x5c,
            0x33,
            0x85,
            0x38,
            0xed,
        ],
        [
            0xd1,
            0x33,
            0xf2,
            0x2a,
            0x1a,
            0xed,
            0x2a,
            0x7b,
            0xfa,
            0x0f,
            0x44,
            0x69,
            0x7c,
            0x4f,
            0x3f,
            0xfd,
        ],
        [
            0xaa,
            0x21,
            0x8b,
            0x56,
            0xee,
            0x5e,
            0xbe,
            0xac,
            0xdd,
            0x6e,
            0xce,
            0xbf,
            0x26,
            0xe6,
            0x3c,
            0x06,
        ],
    ];
    const SHIFT_ROWS: [[u8; 16]; 14] = [
        [
            0x63,
            0x53,
            0xe0,
            0x8c,
            0x09,
            0x60,
            0xe1,
            0x04,
            0xcd,
            0x70,
            0xb7,
            0x51,
            0xba,
            0xca,
            0xd0,
            0xe7,
        ],
        [
            0x84,
            0xe1,
            0xfd,
            0x6b,
            0x1a,
            0x5c,
            0x94,
            0x6f,
            0xdf,
            0x49,
            0x38,
            0x97,
            0x7c,
            0xfb,
            0xac,
            0x23,
        ],
        [
            0xad,
            0x9c,
            0x7e,
            0x01,
            0x7e,
            0x55,
            0xef,
            0x25,
            0xbc,
            0x15,
            0x0f,
            0xe0,
            0x1c,
            0xcb,
            0x63,
            0x95,
        ],
        [
            0x88,
            0xdb,
            0x34,
            0xfb,
            0x1f,
            0x80,
            0x76,
            0x78,
            0xd3,
            0xf8,
            0x33,
            0xc2,
            0x19,
            0x4a,
            0x75,
            0x9e,
        ],
        [
            0x9c,
            0xf0,
            0xa6,
            0x20,
            0x49,
            0xfd,
            0x59,
            0xa3,
            0x99,
            0x51,
            0x89,
            0x84,
            0xf2,
            0x6b,
            0xe1,
            0x78,
        ],
        [
            0x2e,
            0x6e,
            0x7a,
            0x2d,
            0xaf,
            0xc6,
            0xee,
            0xf8,
            0x3a,
            0x86,
            0xac,
            0xe7,
            0xc2,
            0x5b,
            0xa9,
            0x34,
        ],
        [
            0xd2,
            0x2f,
            0x0c,
            0x29,
            0x1f,
            0xfe,
            0x03,
            0x1a,
            0x78,
            0x9d,
            0x83,
            0xb2,
            0xec,
            0xc5,
            0x36,
            0x4c,
        ],
        [
            0xf6,
            0xe0,
            0x62,
            0xff,
            0x50,
            0x74,
            0x58,
            0xf9,
            0xbe,
            0x50,
            0x49,
            0x76,
            0x56,
            0xed,
            0x65,
            0x4c,
        ],
        [
            0xbe,
            0xb5,
            0x0a,
            0xa6,
            0xcf,
            0xf8,
            0x56,
            0x12,
            0x6b,
            0x0d,
            0x6a,
            0xff,
            0x45,
            0xc2,
            0x5d,
            0xc4,
        ],
        [
            0xd6,
            0xf3,
            0xd9,
            0xdd,
            0xa6,
            0x27,
            0x9b,
            0xd1,
            0x43,
            0x0d,
            0x52,
            0xa0,
            0xe5,
            0x13,
            0xf3,
            0xfe,
        ],
        [
            0x78,
            0xe2,
            0xac,
            0xce,
            0x74,
            0x1e,
            0xd5,
            0x42,
            0x51,
            0x00,
            0xc5,
            0xe0,
            0xe2,
            0x3b,
            0x80,
            0xc7,
        ],
        [
            0xcf,
            0xb4,
            0xdb,
            0xed,
            0xf4,
            0x09,
            0x38,
            0x08,
            0x53,
            0x85,
            0x02,
            0xac,
            0x33,
            0xde,
            0x18,
            0x5c,
        ],
        [
            0xd1,
            0xed,
            0x44,
            0xfd,
            0x1a,
            0x0f,
            0x3f,
            0x2a,
            0xfa,
            0x4f,
            0xf2,
            0x7b,
            0x7c,
            0x33,
            0x2a,
            0x69,
        ],
        [
            0xaa,
            0x5e,
            0xce,
            0x06,
            0xee,
            0x6e,
            0x3c,
            0x56,
            0xdd,
            0xe6,
            0x8b,
            0xac,
            0x26,
            0x21,
            0xbe,
            0xbf,
        ],
    ];
    const MIX_COLUMNS: [[u8; 16]; 13] = [
        [
            0x5f,
            0x72,
            0x64,
            0x15,
            0x57,
            0xf5,
            0xbc,
            0x92,
            0xf7,
            0xbe,
            0x3b,
            0x29,
            0x1d,
            0xb9,
            0xf9,
            0x1a,
        ],
        [
            0xbd,
            0x2a,
            0x39,
            0x5d,
            0x2b,
            0x6a,
            0xc4,
            0x38,
            0xd1,
            0x92,
            0x44,
            0x3e,
            0x61,
            0x5d,
            0xa1,
            0x95,
        ],
        [
            0x81,
            0x0d,
            0xce,
            0x0c,
            0xc9,
            0xdb,
            0x81,
            0x72,
            0xb3,
            0x67,
            0x8c,
            0x1e,
            0x88,
            0xa1,
            0xb5,
            0xbd,
        ],
        [
            0xb2,
            0x82,
            0x2d,
            0x81,
            0xab,
            0xe6,
            0xfb,
            0x27,
            0x5f,
            0xaf,
            0x10,
            0x3a,
            0x07,
            0x8c,
            0x00,
            0x33,
        ],
        [
            0xae,
            0xb6,
            0x5b,
            0xa9,
            0x74,
            0xe0,
            0xf8,
            0x22,
            0xd7,
            0x3f,
            0x56,
            0x7b,
            0xdb,
            0x64,
            0xc8,
            0x77,
        ],
        [
            0xb9,
            0x51,
            0xc3,
            0x3c,
            0x02,
            0xe9,
            0xbd,
            0x29,
            0xae,
            0x25,
            0xcd,
            0xb1,
            0xef,
            0xa0,
            0x8c,
            0xc7,
        ],
        [
            0xeb,
            0xb1,
            0x9e,
            0x1c,
            0x3e,
            0xe7,
            0xc9,
            0xe8,
            0x7d,
            0x75,
            0x35,
            0xe9,
            0xed,
            0x6b,
            0x91,
            0x44,
        ],
        [
            0x51,
            0x74,
            0xc8,
            0x66,
            0x9d,
            0xa9,
            0x84,
            0x35,
            0xa8,
            0xb3,
            0xe6,
            0x2c,
            0xa9,
            0x74,
            0xa5,
            0xea,
        ],
        [
            0x0f,
            0x77,
            0xee,
            0x31,
            0xd2,
            0xcc,
            0xad,
            0xc0,
            0x54,
            0x30,
            0xa8,
            0x3f,
            0x4e,
            0xf9,
            0x6a,
            0xc3,
        ],
        [
            0xbd,
            0x86,
            0xf0,
            0xea,
            0x74,
            0x8f,
            0xc4,
            0xf4,
            0x63,
            0x0f,
            0x11,
            0xc1,
            0xe9,
            0x33,
            0x12,
            0x33,
        ],
        [
            0xaf,
            0x86,
            0x90,
            0x41,
            0x5d,
            0x6e,
            0x1d,
            0xd3,
            0x87,
            0xe5,
            0xfb,
            0xed,
            0xd5,
            0xc8,
            0x90,
            0x13,
        ],
        [
            0x74,
            0x27,
            0xfa,
            0xe4,
            0xd8,
            0xa6,
            0x95,
            0x26,
            0x9c,
            0xe8,
            0x3d,
            0x31,
            0x5b,
            0xe0,
            0x39,
            0x2b,
        ],
        [
            0x2c,
            0x21,
            0xa8,
            0x20,
            0x30,
            0x6f,
            0x15,
            0x4a,
            0xb7,
            0x12,
            0xc7,
            0x5e,
            0xee,
            0x0d,
            0xa0,
            0x4f,
        ],
    ];

    #[test]
    fn test_cipher() {
        let aes = AES::new(&KEY);
        assert_eq!(OUTPUT, aes.cipher(&INPUT));
        assert_eq!(INPUT, aes.inv_cipher(&OUTPUT));
    }

    #[test]
    fn test_key_expansion() {
        let key = [
            0x60,
            0x3d,
            0xeb,
            0x10,
            0x15,
            0xca,
            0x71,
            0xbe,
            0x2b,
            0x73,
            0xae,
            0xf0,
            0x85,
            0x7d,
            0x77,
            0x81,
            0x1f,
            0x35,
            0x2c,
            0x07,
            0x3b,
            0x61,
            0x08,
            0xd7,
            0x2d,
            0x98,
            0x10,
            0xa3,
            0x09,
            0x14,
            0xdf,
            0xf4,
        ];
        let key_schedule = [
            0x60,
            0x3d,
            0xeb,
            0x10,
            0x15,
            0xca,
            0x71,
            0xbe,
            0x2b,
            0x73,
            0xae,
            0xf0,
            0x85,
            0x7d,
            0x77,
            0x81,
            0x1f,
            0x35,
            0x2c,
            0x07,
            0x3b,
            0x61,
            0x08,
            0xd7,
            0x2d,
            0x98,
            0x10,
            0xa3,
            0x09,
            0x14,
            0xdf,
            0xf4,
            0x9b,
            0xa3,
            0x54,
            0x11,
            0x8e,
            0x69,
            0x25,
            0xaf,
            0xa5,
            0x1a,
            0x8b,
            0x5f,
            0x20,
            0x67,
            0xfc,
            0xde,
            0xa8,
            0xb0,
            0x9c,
            0x1a,
            0x93,
            0xd1,
            0x94,
            0xcd,
            0xbe,
            0x49,
            0x84,
            0x6e,
            0xb7,
            0x5d,
            0x5b,
            0x9a,
            0xd5,
            0x9a,
            0xec,
            0xb8,
            0x5b,
            0xf3,
            0xc9,
            0x17,
            0xfe,
            0xe9,
            0x42,
            0x48,
            0xde,
            0x8e,
            0xbe,
            0x96,
            0xb5,
            0xa9,
            0x32,
            0x8a,
            0x26,
            0x78,
            0xa6,
            0x47,
            0x98,
            0x31,
            0x22,
            0x29,
            0x2f,
            0x6c,
            0x79,
            0xb3,
            0x81,
            0x2c,
            0x81,
            0xad,
            0xda,
            0xdf,
            0x48,
            0xba,
            0x24,
            0x36,
            0x0a,
            0xf2,
            0xfa,
            0xb8,
            0xb4,
            0x64,
            0x98,
            0xc5,
            0xbf,
            0xc9,
            0xbe,
            0xbd,
            0x19,
            0x8e,
            0x26,
            0x8c,
            0x3b,
            0xa7,
            0x09,
            0xe0,
            0x42,
            0x14,
            0x68,
            0x00,
            0x7b,
            0xac,
            0xb2,
            0xdf,
            0x33,
            0x16,
            0x96,
            0xe9,
            0x39,
            0xe4,
            0x6c,
            0x51,
            0x8d,
            0x80,
            0xc8,
            0x14,
            0xe2,
            0x04,
            0x76,
            0xa9,
            0xfb,
            0x8a,
            0x50,
            0x25,
            0xc0,
            0x2d,
            0x59,
            0xc5,
            0x82,
            0x39,
            0xde,
            0x13,
            0x69,
            0x67,
            0x6c,
            0xcc,
            0x5a,
            0x71,
            0xfa,
            0x25,
            0x63,
            0x95,
            0x96,
            0x74,
            0xee,
            0x15,
            0x58,
            0x86,
            0xca,
            0x5d,
            0x2e,
            0x2f,
            0x31,
            0xd7,
            0x7e,
            0x0a,
            0xf1,
            0xfa,
            0x27,
            0xcf,
            0x73,
            0xc3,
            0x74,
            0x9c,
            0x47,
            0xab,
            0x18,
            0x50,
            0x1d,
            0xda,
            0xe2,
            0x75,
            0x7e,
            0x4f,
            0x74,
            0x01,
            0x90,
            0x5a,
            0xca,
            0xfa,
            0xaa,
            0xe3,
            0xe4,
            0xd5,
            0x9b,
            0x34,
            0x9a,
            0xdf,
            0x6a,
            0xce,
            0xbd,
            0x10,
            0x19,
            0x0d,
            0xfe,
            0x48,
            0x90,
            0xd1,
            0xe6,
            0x18,
            0x8d,
            0x0b,
            0x04,
            0x6d,
            0xf3,
            0x44,
            0x70,
            0x6c,
            0x63,
            0x1e,
        ];
        let mut schedule = [0; 240];
        AES::key_expansion(&mut schedule, &key);
        for (lhs, rhs) in key_schedule.iter().zip(schedule.iter()) {
            assert_eq!(lhs, rhs);
        }
    }

    #[test]
    fn test_add_round_key() {
        let aes = AES::new(&KEY);
        let mut state = [0; 16];
        state.copy_from_slice(&INPUT);
        aes.add_round_key(&mut state, 0);
        assert_eq!(START[0], state);
        aes.add_round_key(&mut state, 0);
        assert_eq!(INPUT, state);

        for (i, (&start, &mix_columns)) in START.iter().skip(1).zip(&MIX_COLUMNS).enumerate() {
            state.copy_from_slice(&mix_columns);
            aes.add_round_key(&mut state, i + 1);
            assert_eq!(start, state);
            aes.add_round_key(&mut state, i + 1);
            assert_eq!(mix_columns, state);
        }

        state.copy_from_slice(&SHIFT_ROWS[13]);
        aes.add_round_key(&mut state, 14);
        assert_eq!(OUTPUT, state);
        aes.add_round_key(&mut state, 14);
        assert_eq!(SHIFT_ROWS[13], state);
    }

    #[test]
    fn test_sub_bytes() {
        let mut state = [0; 16];
        for (&start, &sub_bytes) in START.iter().zip(&SUB_BYTES) {
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
        for (&sub_bytes, &shift_rows) in SUB_BYTES.iter().zip(&SHIFT_ROWS) {
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
        for (&shift_rows, &mix_columns) in SHIFT_ROWS.iter().zip(&MIX_COLUMNS) {
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
