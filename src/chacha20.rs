use std::io;
use byteorder::{ByteOrder, LittleEndian};
use key;

pub struct Stream {
    chacha20: ChaCha20,
    counter: u32,
    block: [u8; 64],
    block_index: u8,
}

pub struct ChaCha20 {
    state: [u32; 16],
}

pub fn gen_nonce() -> io::Result<[u8; 12]> {
    Ok(key::gen()?)
}

/// A ChaCha20 iterator that can be used for encryption and decryption.
///
/// Initialized with a 32-byte key and 12-byte nonce. If reusing a key for encryption, be sure to
/// generate a unique nonce so that a given (key, nonce) pair is never used twice.
///
/// # Overflow Behavior
///
/// Iterating past 256 GB of the bytestream will cause the block counter to overflow.
impl Stream {
    pub fn new(key: &[u8], nonce: &[u8]) -> Self {
        let chacha20 = ChaCha20::new(&key, &nonce);
        let block = chacha20.get_block(0);
        Self {
            chacha20: chacha20,
            counter: 0,
            block: block,
            block_index: 0,
        }
    }

    // not sure how legal it is to encrypt without starting with a fresh block
    pub fn encrypt(&mut self, message: &[u8]) -> Vec<u8> {
        self.xor(message)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Vec<u8> {
        self.xor(ciphertext)
    }

    fn xor(&mut self, bytes: &[u8]) -> Vec<u8> {
        self.zip(bytes).map(|(x, y)| x ^ y).collect()
    }
}

// doing this is a bit strange but it seemed interesting
impl Iterator for Stream {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.block_index == 64 {
            self.counter += 1; // could overflow
            self.block = self.chacha20.get_block(self.counter);
            self.block_index = 0;
        }
        let byte = self.block[self.block_index as usize];
        self.block_index += 1;
        Some(byte)
    }
}

impl ChaCha20 {
    pub fn new(key: &[u8], nonce: &[u8]) -> Self {
        assert_eq!(32, key.len());
        assert_eq!(12, nonce.len());
        let mut chacha20 = Self { state: [0; 16] };
        Self::setup_state(&mut chacha20.state, &key, &nonce);
        chacha20
    }

    pub fn get_block(&self, counter: u32) -> [u8; 64] {
        let mut state = [0; 16];
        self.transform_state(&mut state, counter);
        Self::serialize_block(state)
    }

    fn setup_state(state: &mut [u32; 16], key: &[u8], nonce: &[u8]) {
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;
        Self::to_le(&mut state[4..12], key);
        Self::to_le(&mut state[13..], nonce);
    }

    fn transform_state(&self, state: &mut [u32; 16], counter: u32) {
        state.copy_from_slice(&self.state);
        state[12] = counter;
        for _ in 0..10 {
            Self::inner_block(state);
        }
        for (x, &y) in state.iter_mut().zip(&self.state) {
            *x = x.wrapping_add(y);
        }
        state[12] = state[12].wrapping_add(counter);
    }

    fn inner_block(state: &mut [u32; 16]) {
        Self::quarter_round(state, 0, 4, 8, 12);
        Self::quarter_round(state, 1, 5, 9, 13);
        Self::quarter_round(state, 2, 6, 10, 14);
        Self::quarter_round(state, 3, 7, 11, 15);
        Self::quarter_round(state, 0, 5, 10, 15);
        Self::quarter_round(state, 1, 6, 11, 12);
        Self::quarter_round(state, 2, 7, 8, 13);
        Self::quarter_round(state, 3, 4, 9, 14);
    }

    fn quarter_round(state: &mut [u32; 16], i: usize, j: usize, k: usize, l: usize) {
        let mut a = state[i];
        let mut b = state[j];
        let mut c = state[k];
        let mut d = state[l];
        a = a.wrapping_add(b);
        d ^= a;
        d = d.rotate_left(16);
        c = c.wrapping_add(d);
        b ^= c;
        b = b.rotate_left(12);
        a = a.wrapping_add(b);
        d ^= a;
        d = d.rotate_left(8);
        c = c.wrapping_add(d);
        b ^= c;
        b = b.rotate_left(7);
        state[i] = a;
        state[j] = b;
        state[k] = c;
        state[l] = d;
    }

    fn to_le(words: &mut [u32], bytes: &[u8]) {
        for (word, chunk) in words.iter_mut().zip(bytes.chunks(4)) {
            *word = LittleEndian::read_u32(chunk);
        }
    }

    fn serialize_block(block: [u32; 16]) -> [u8; 64] {
        let mut bytes = [0; 64];
        for (chunk, &word) in bytes.chunks_mut(4).zip(&block) {
            LittleEndian::write_u32(chunk, word);
        }
        bytes
    }
}

#[cfg(test)]
mod tests {
    use chacha20::*;

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
    const NONCE: [u8; 12] = [
        0x00,
        0x00,
        0x00,
        0x09,
        0x00,
        0x00,
        0x00,
        0x4a,
        0x00,
        0x00,
        0x00,
        0x00,
    ];
    const BLOCK_ONE: [u8; 64] = [
        0x10,
        0xf1,
        0xe7,
        0xe4,
        0xd1,
        0x3b,
        0x59,
        0x15,
        0x50,
        0x0f,
        0xdd,
        0x1f,
        0xa3,
        0x20,
        0x71,
        0xc4,
        0xc7,
        0xd1,
        0xf4,
        0xc7,
        0x33,
        0xc0,
        0x68,
        0x03,
        0x04,
        0x22,
        0xaa,
        0x9a,
        0xc3,
        0xd4,
        0x6c,
        0x4e,
        0xd2,
        0x82,
        0x64,
        0x46,
        0x07,
        0x9f,
        0xaa,
        0x09,
        0x14,
        0xc2,
        0xd7,
        0x05,
        0xd9,
        0x8b,
        0x02,
        0xa2,
        0xb5,
        0x12,
        0x9c,
        0xd1,
        0xde,
        0x16,
        0x4e,
        0xb9,
        0xcb,
        0xd0,
        0x83,
        0xe8,
        0xa2,
        0x50,
        0x3c,
        0x4e,
    ];
    const SETUP_STATE: [u32; 16] = [
        0x61707865,
        0x3320646e,
        0x79622d32,
        0x6b206574,
        0x03020100,
        0x07060504,
        0x0b0a0908,
        0x0f0e0d0c,
        0x13121110,
        0x17161514,
        0x1b1a1918,
        0x1f1e1d1c,
        0x00000000,
        0x09000000,
        0x4a000000,
        0x00000000,
    ];
    const FINAL_STATE: [u32; 16] = [
        0xe4e7f110,
        0x15593bd1,
        0x1fdd0f50,
        0xc47120a3,
        0xc7f4d1c7,
        0x0368c033,
        0x9aaa2204,
        0x4e6cd4c3,
        0x466482d2,
        0x09aa9f07,
        0x05d7c214,
        0xa2028bd9,
        0xd19c12b5,
        0xb94e16de,
        0xe883d0cb,
        0x4e3c50a2,
    ];

    #[test]
    fn test_encrypt() {
        let message = "Ladies and Gentlemen of the class of '99: If I could offer you only one \
            tip for the future, sunscreen would be it.";
        let mut stream = Stream::new(&KEY, &[0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0]);
        stream.nth(64 - 1);
        assert_eq!(
            vec![
                0x6e,
                0x2e,
                0x35,
                0x9a,
                0x25,
                0x68,
                0xf9,
                0x80,
                0x41,
                0xba,
                0x07,
                0x28,
                0xdd,
                0x0d,
                0x69,
                0x81,
                0xe9,
                0x7e,
                0x7a,
                0xec,
                0x1d,
                0x43,
                0x60,
                0xc2,
                0x0a,
                0x27,
                0xaf,
                0xcc,
                0xfd,
                0x9f,
                0xae,
                0x0b,
                0xf9,
                0x1b,
                0x65,
                0xc5,
                0x52,
                0x47,
                0x33,
                0xab,
                0x8f,
                0x59,
                0x3d,
                0xab,
                0xcd,
                0x62,
                0xb3,
                0x57,
                0x16,
                0x39,
                0xd6,
                0x24,
                0xe6,
                0x51,
                0x52,
                0xab,
                0x8f,
                0x53,
                0x0c,
                0x35,
                0x9f,
                0x08,
                0x61,
                0xd8,
                0x07,
                0xca,
                0x0d,
                0xbf,
                0x50,
                0x0d,
                0x6a,
                0x61,
                0x56,
                0xa3,
                0x8e,
                0x08,
                0x8a,
                0x22,
                0xb6,
                0x5e,
                0x52,
                0xbc,
                0x51,
                0x4d,
                0x16,
                0xcc,
                0xf8,
                0x06,
                0x81,
                0x8c,
                0xe9,
                0x1a,
                0xb7,
                0x79,
                0x37,
                0x36,
                0x5a,
                0xf9,
                0x0b,
                0xbf,
                0x74,
                0xa3,
                0x5b,
                0xe6,
                0xb4,
                0x0b,
                0x8e,
                0xed,
                0xf2,
                0x78,
                0x5e,
                0x42,
                0x87,
                0x4d,
            ],
            stream.encrypt(message.as_bytes())
        );
    }

    #[test]
    fn test_new() {
        let chacha20 = ChaCha20::new(&KEY, &NONCE);
        let mut state = [0; 16];
        ChaCha20::setup_state(&mut state, &KEY, &NONCE);
        assert_eq!(state, chacha20.state);
    }

    fn check_serialized_block(block: &[u8]) {
        assert_eq!(BLOCK_ONE.len(), block.len());
        for (lhs, rhs) in BLOCK_ONE.iter().zip(block) {
            assert_eq!(lhs, rhs);
        }
    }

    #[test]
    fn test_get_block() {
        let mut chacha20 = ChaCha20 { state: [0; 16] };
        ChaCha20::setup_state(&mut chacha20.state, &KEY, &NONCE);
        check_serialized_block(&chacha20.get_block(1));
    }

    #[test]
    fn test_setup_state() {
        let mut state = [0; 16];
        ChaCha20::setup_state(&mut state, &KEY, &NONCE);
        assert_eq!(SETUP_STATE, state);
    }

    #[test]
    fn test_transform_state() {
        let chacha20 = ChaCha20 { state: SETUP_STATE };
        let mut state = [0; 16];
        chacha20.transform_state(&mut state, 1);
        assert_eq!(FINAL_STATE, state);
    }

    #[test]
    fn test_inner_block() {
        let mut state = SETUP_STATE;
        state[12] = 1;
        for _ in 0..10 {
            ChaCha20::inner_block(&mut state);
        }
        assert_eq!(
            [
                0x837778ab,
                0xe238d763,
                0xa67ae21e,
                0x5950bb2f,
                0xc4f2d0c7,
                0xfc62bb2f,
                0x8fa018fc,
                0x3f5ec7b7,
                0x335271c2,
                0xf29489f3,
                0xeabda8fc,
                0x82e46ebd,
                0xd19c12b4,
                0xb04e16de,
                0x9e83d0cb,
                0x4e3c50a2,
            ],
            state
        );
    }

    #[test]
    fn test_quarter_round() {
        let mut state = [0; 16];
        state[0] = 0x11111111;
        state[1] = 0x01020304;
        state[2] = 0x9b8d6f43;
        state[3] = 0x01234567;
        ChaCha20::quarter_round(&mut state, 0, 1, 2, 3);
        assert_eq!([0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb], state[..4]);

        state = [
            0x879531e0,
            0xc5ecf37d,
            0x516461b1,
            0xc9a62f8a,
            0x44c20ef3,
            0x3390af7f,
            0xd9fc690b,
            0x2a5f714c,
            0x53372767,
            0xb00a5631,
            0x974c541a,
            0x359e9963,
            0x5c971061,
            0x3d631689,
            0x2098d9d6,
            0x91dbd320,
        ];
        ChaCha20::quarter_round(&mut state, 2, 7, 8, 13);
        assert_eq!(
            [
                0x879531e0,
                0xc5ecf37d,
                0xbdb886dc,
                0xc9a62f8a,
                0x44c20ef3,
                0x3390af7f,
                0xd9fc690b,
                0xcfacafd2,
                0xe46bea80,
                0xb00a5631,
                0x974c541a,
                0x359e9963,
                0x5c971061,
                0xccc07c79,
                0x2098d9d6,
                0x91dbd320,
            ],
            state
        );
    }

    #[test]
    fn test_to_le() {
        let mut key = [0; 8];
        ChaCha20::to_le(&mut key, &KEY);
        assert_eq!(
            [
                0x03020100,
                0x07060504,
                0x0b0a0908,
                0x0f0e0d0c,
                0x13121110,
                0x17161514,
                0x1b1a1918,
                0x1f1e1d1c,
            ],
            key
        );

        let mut nonce = [0; 3];
        ChaCha20::to_le(&mut nonce, &NONCE);
        assert_eq!([0x09000000, 0x4a000000, 0x00000000], nonce);
    }

    #[test]
    fn test_serialize_block() {
        check_serialized_block(&ChaCha20::serialize_block(FINAL_STATE));
    }
}
