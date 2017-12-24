//! Module for the ChaCha20 stream cipher.
use byteorder::{ByteOrder, LittleEndian};

/// A ChaCha20 iterator that can be used as a stream cipher or pseudorandom generator.
///
/// Initialized with a 32-byte key and 12-byte nonce. If reusing a key for encryption, be sure to
/// generate a unique nonce so that a given (key, nonce) pair is never used twice.
///
/// # Overflow Behavior
///
/// Iterating past 256 GB of the bytestream will cause the block counter to overflow.
pub struct Stream {
    chacha20: ChaCha20,
    counter: u32,
    block: [u8; 64],
    block_index: u8,
}

impl Stream {
    /// Initializes a ChaCha20 stream given a key and nonce.
    ///
    /// # Panics
    ///
    /// Panics if `key.len()` is not equal to 32 or if `nonce.len()` is not equal to 12.
    pub fn new(key: &[u8], nonce: &[u8]) -> Self {
        let chacha20 = ChaCha20::new(key, nonce);
        let block = chacha20.block(0);
        Self {
            chacha20: chacha20,
            counter: 0,
            block: block,
            block_index: 0,
        }
    }

    /// Encrypts a message into a ciphertext.
    ///
    /// # Panics
    ///
    /// Panics if `input.len()` is not equal to `output.len()`.
    pub fn encrypt(&mut self, input: &[u8], output: &mut [u8]) {
        self.process(input, output)
    }

    /// Decrypts a ciphertext into a message.
    ///
    /// # Panics
    ///
    /// Panics if `input.len()` is not equal to `output.len()`.
    pub fn decrypt(&mut self, input: &[u8], output: &mut [u8]) {
        self.process(input, output)
    }

    fn process(&mut self, input: &[u8], output: &mut [u8]) {
        assert_eq!(input.len(), output.len());
        for (x, (y, z)) in output.iter_mut().zip(self.take(input.len()).zip(input)) {
            *x = y ^ z;
        }
    }
}

impl Iterator for Stream {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.block_index == 64 {
            self.counter += 1; // could overflow
            self.block = self.chacha20.block(self.counter);
            self.block_index = 0;
        }
        let byte = self.block[self.block_index as usize];
        self.block_index += 1;
        Some(byte)
    }
}

pub(crate) struct ChaCha20 {
    state: [u32; 16],
}

impl ChaCha20 {
    pub(crate) fn new(key: &[u8], nonce: &[u8]) -> Self {
        assert_eq!(32, key.len());
        assert_eq!(12, nonce.len());
        let mut chacha20 = Self { state: [0; 16] };
        chacha20.setup_state(key, nonce);
        chacha20
    }

    pub(crate) fn block(&self, counter: u32) -> [u8; 64] {
        let mut state = [0; 16];
        self.transform_state(&mut state, counter);
        Self::serialize_block(state)
    }

    fn setup_state(&mut self, key: &[u8], nonce: &[u8]) {
        self.state[0] = 0x6170_7865;
        self.state[1] = 0x3320_646e;
        self.state[2] = 0x7962_2d32;
        self.state[3] = 0x6b20_6574;
        LittleEndian::read_u32_into(key, &mut self.state[4..12]);
        LittleEndian::read_u32_into(nonce, &mut self.state[13..]);
    }

    fn transform_state(&self, state: &mut [u32; 16], counter: u32) {
        *state = self.state;
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

    fn serialize_block(block: [u32; 16]) -> [u8; 64] {
        let mut output = [0; 64];
        LittleEndian::write_u32_into(&block, &mut output);
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_helpers::*;

    const KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const NONCE: &[u8] = &[0, 0, 0, 0x09, 0, 0, 0, 0x4a, 0, 0, 0, 0];
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
        let key = &h2b(KEY);
        let nonce = &[0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0];
        let message = "Ladies and Gentlemen of the class of '99: If I could offer you only one \
            tip for the future, sunscreen would be it.";
        let ciphertext = h2b(
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b\
             f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8\
             07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736\
             5af90bbf74a35be6b40b8eedf2785e42874d",
        );
        let encrypted_message = &mut vec![0; message.len()];
        let decrypted_ciphertext = &mut vec![0; ciphertext.len()];

        let mut stream = Stream::new(key, nonce);
        stream.nth(64 - 1);
        stream.encrypt(message.as_bytes(), encrypted_message);
        assert_eq!(&ciphertext, encrypted_message);

        stream = Stream::new(key, nonce);
        stream.nth(64 - 1);
        stream.decrypt(&ciphertext, decrypted_ciphertext);
        assert_eq!(message.as_bytes(), decrypted_ciphertext.as_slice());
    }

    #[test]
    fn test_new() {
        let chacha20 = ChaCha20::new(&h2b(KEY), NONCE);
        assert_eq!(SETUP_STATE, chacha20.state);
    }

    fn check_serialized_block(block: &[u8]) {
        let block_one = h2b(
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e\
             d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
        );
        assert_eq!(block_one, block.to_vec());
    }

    fn check_block(expected: &str, key: &[u8], nonce: &[u8], counter: u32) {
        let chacha20 = ChaCha20::new(key, nonce);
        let block = &chacha20.block(counter);
        let expected = h2b(expected);
        assert_eq!(expected, block.to_vec());
    }

    #[test]
    fn test_block() {
        let chacha20 = ChaCha20::new(&h2b(KEY), NONCE);
        let block = &chacha20.block(1);
        check_serialized_block(block);

        let key = &[0; 32];
        let nonce = &[0; 12];
        let expected = "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7\
                        da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586";
        check_block(expected, key, nonce, 0);

        let expected = "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed\
                        29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f";
        check_block(expected, key, nonce, 1);

        let key = &mut [0; 32];
        key[31] = 1;
        let expected = "3aeb5224ecf849929b9d828db1ced4dd832025e8018b8160b82284f3c949aa5a\
                        8eca00bbb4a73bdad192b5c42f73f2fd4e273644c8b36125a64addeb006c13a0";
        check_block(expected, key, nonce, 1);

        let key = &mut [0; 32];
        key[1] = 0xff;
        let expected = "72d54dfbf12ec44b362692df94137f328fea8da73990265ec1bbbea1ae9af0ca\
                        13b25aa26cb4a648cb9b9d1be65b2c0924a66c54d545ec1b7374f4872e99f096";
        check_block(expected, key, nonce, 2);

        let key = &[0; 32];
        let nonce = &mut [0; 12];
        nonce[11] = 2;
        let expected = "c2c64d378cd536374ae204b9ef933fcd1a8b2288b3dfa49672ab765b54ee27c7\
                        8a970e0e955c14f3a88e741b97c286f75f8fc299e8148362fa198a39531bed6d";
        check_block(expected, key, nonce, 0);
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
    fn test_serialize_block() {
        let block = ChaCha20::serialize_block(FINAL_STATE);
        check_serialized_block(&block);
    }
}
