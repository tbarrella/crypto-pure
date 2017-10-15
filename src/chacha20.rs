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
        let chacha20 = ChaCha20::new(key, nonce);
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
        self.take(bytes.len())
            .zip(bytes)
            .map(|(x, y)| x ^ y)
            .collect()
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
        Self::setup_state(&mut chacha20.state, key, nonce);
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
    use test_helpers::*;

    const KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const NONCE: [u8; 12] = [0, 0, 0, 0x09, 0, 0, 0, 0x4a, 0, 0, 0, 0];
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
        let mut stream = Stream::new(&h2b(KEY), &[0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0]);
        stream.nth(64 - 1);
        let ciphertext = h2b(
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b\
             f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8\
             07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736\
             5af90bbf74a35be6b40b8eedf2785e42874d",
        );
        assert_eq!(ciphertext, stream.encrypt(message.as_bytes()));
    }

    #[test]
    fn test_new() {
        let chacha20 = ChaCha20::new(&h2b(KEY), &NONCE);
        let mut state = [0; 16];
        ChaCha20::setup_state(&mut state, &h2b(KEY), &NONCE);
        assert_eq!(state, chacha20.state);
    }

    fn check_serialized_block(block: &[u8]) {
        let block_one = h2b(
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e\
             d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
        );
        assert_eq!(block_one, block.to_vec());
    }

    #[test]
    fn test_get_block() {
        let mut chacha20 = ChaCha20 { state: [0; 16] };
        ChaCha20::setup_state(&mut chacha20.state, &h2b(KEY), &NONCE);
        check_serialized_block(&chacha20.get_block(1));
    }

    #[test]
    fn test_setup_state() {
        let mut state = [0; 16];
        ChaCha20::setup_state(&mut state, &h2b(KEY), &NONCE);
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
        ChaCha20::to_le(&mut key, &h2b(KEY));
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
