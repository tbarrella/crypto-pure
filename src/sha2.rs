//! Module for the SHA-2 family of hash functions.
use byteorder::{BigEndian, ByteOrder};
use core::mem::size_of;

/// A trait for hash functions.
pub trait HashFunction: Default {
    /// Digest size in bytes.
    const DIGEST_SIZE: usize;
    /// Block size in bytes.
    const BLOCK_SIZE: usize;

    /// Feeds input into the hash function to update its state.
    fn update(&mut self, input: &[u8]);

    /// Writes the hash function digest into an output buffer.
    fn write_digest(self, output: &mut [u8]);
}

/// The SHA-512 hash function.
///
/// # Examples
///
/// ```
/// use crypto_pure::sha2::{HashFunction, Sha512};
/// let mut digest = [0; Sha512::DIGEST_SIZE];
/// let mut sha = Sha512::default();
/// sha.update(b"part one");
/// sha.update(b"part two");
/// sha.write_digest(&mut digest);
/// ```
pub struct Sha512(Processor512);

/// The SHA-384 hash function.
///
/// # Examples
///
/// ```
/// use crypto_pure::sha2::{HashFunction, Sha384};
/// let mut digest = [0; Sha384::DIGEST_SIZE];
/// let mut sha = Sha384::default();
/// sha.update(b"part one");
/// sha.update(b"part two");
/// sha.write_digest(&mut digest);
/// ```
pub struct Sha384(Processor512);

/// The SHA-256 hash function.
///
/// # Examples
///
/// ```
/// use crypto_pure::sha2::{HashFunction, Sha256};
/// let mut digest = [0; Sha256::DIGEST_SIZE];
/// let mut sha = Sha256::default();
/// sha.update(b"part one");
/// sha.update(b"part two");
/// sha.write_digest(&mut digest);
/// ```
pub struct Sha256(Processor256);

/// The SHA-224 hash function.
///
/// # Examples
///
/// ```
/// use crypto_pure::sha2::{HashFunction, Sha224};
/// let mut digest = [0; Sha224::DIGEST_SIZE];
/// let mut sha = Sha224::default();
/// sha.update(b"part one");
/// sha.update(b"part two");
/// sha.write_digest(&mut digest);
/// ```
pub struct Sha224(Processor256);

macro_rules! impl_wrapper {
    ($function:ident, $message:expr) => {{
        let mut digest = [0; $function::DIGEST_SIZE];
        let mut sha = $function::default();
        sha.update($message);
        sha.write_digest(&mut digest);
        digest
    }};
}

/// Wrapper for obtaining the SHA-512 digest for a complete message.
pub fn sha512(message: &[u8]) -> [u8; Sha512::DIGEST_SIZE] {
    impl_wrapper!(Sha512, message)
}

/// Wrapper for obtaining the SHA-384 digest for a complete message.
pub fn sha384(message: &[u8]) -> [u8; Sha384::DIGEST_SIZE] {
    impl_wrapper!(Sha384, message)
}

/// Wrapper for obtaining the SHA-256 digest for a complete message.
pub fn sha256(message: &[u8]) -> [u8; Sha256::DIGEST_SIZE] {
    impl_wrapper!(Sha256, message)
}

/// Wrapper for obtaining the SHA-224 digest for a complete message.
pub fn sha224(message: &[u8]) -> [u8; Sha224::DIGEST_SIZE] {
    impl_wrapper!(Sha224, message)
}

macro_rules! impl_function {
    ($function:ident, $algorithm:expr, $processor:ident) => {
        impl Default for $function {
            fn default() -> Self {
                $function($processor::new(&$algorithm))
            }
        }

        impl HashFunction for $function {
            const DIGEST_SIZE: usize = $algorithm.digest_size;
            const BLOCK_SIZE: usize = $algorithm.block_size;

            fn update(&mut self, input: &[u8]) {
                self.0.update(input);
            }

            /// Writes the hash function digest into an output buffer.
            ///
            /// # Panics
            ///
            /// Panics if `output.len()` is not equal to the digest size.
            fn write_digest(self, output: &mut [u8]) {
                assert_eq!(Self::DIGEST_SIZE, output.len());
                self.0.write_digest(output);
            }
        }
    };
}

impl_function!(Sha512, SHA512, Processor512);
impl_function!(Sha384, SHA384, Processor512);
impl_function!(Sha256, SHA256, Processor256);
impl_function!(Sha224, SHA224, Processor256);

pub(crate) const MAX_DIGEST_SIZE: usize = 64;

struct Algorithm<S> {
    digest_size: usize,
    block_size: usize,
    initial_state: S,
}

const SHA512: Algorithm<[u64; 8]> = Algorithm {
    digest_size: 64,
    block_size: 128,
    initial_state: [
        0x6a09_e667_f3bc_c908,
        0xbb67_ae85_84ca_a73b,
        0x3c6e_f372_fe94_f82b,
        0xa54f_f53a_5f1d_36f1,
        0x510e_527f_ade6_82d1,
        0x9b05_688c_2b3e_6c1f,
        0x1f83_d9ab_fb41_bd6b,
        0x5be0_cd19_137e_2179,
    ],
};

const SHA384: Algorithm<[u64; 8]> = Algorithm {
    digest_size: 48,
    block_size: 128,
    initial_state: [
        0xcbbb_9d5d_c105_9ed8,
        0x629a_292a_367c_d507,
        0x9159_015a_3070_dd17,
        0x152f_ecd8_f70e_5939,
        0x6733_2667_ffc0_0b31,
        0x8eb4_4a87_6858_1511,
        0xdb0c_2e0d_64f9_8fa7,
        0x47b5_481d_befa_4fa4,
    ],
};

const SHA256: Algorithm<[u32; 8]> = Algorithm {
    digest_size: 32,
    block_size: 64,
    initial_state: [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ],
};

const SHA224: Algorithm<[u32; 8]> = Algorithm {
    digest_size: 28,
    block_size: 64,
    initial_state: [
        0xc105_9ed8,
        0x367c_d507,
        0x3070_dd17,
        0xf70e_5939,
        0xffc0_0b31,
        0x6858_1511,
        0x64f9_8fa7,
        0xbefa_4fa4,
    ],
};

const K512: [u64; 80] = [
    0x428a_2f98_d728_ae22,
    0x7137_4491_23ef_65cd,
    0xb5c0_fbcf_ec4d_3b2f,
    0xe9b5_dba5_8189_dbbc,
    0x3956_c25b_f348_b538,
    0x59f1_11f1_b605_d019,
    0x923f_82a4_af19_4f9b,
    0xab1c_5ed5_da6d_8118,
    0xd807_aa98_a303_0242,
    0x1283_5b01_4570_6fbe,
    0x2431_85be_4ee4_b28c,
    0x550c_7dc3_d5ff_b4e2,
    0x72be_5d74_f27b_896f,
    0x80de_b1fe_3b16_96b1,
    0x9bdc_06a7_25c7_1235,
    0xc19b_f174_cf69_2694,
    0xe49b_69c1_9ef1_4ad2,
    0xefbe_4786_384f_25e3,
    0x0fc1_9dc6_8b8c_d5b5,
    0x240c_a1cc_77ac_9c65,
    0x2de9_2c6f_592b_0275,
    0x4a74_84aa_6ea6_e483,
    0x5cb0_a9dc_bd41_fbd4,
    0x76f9_88da_8311_53b5,
    0x983e_5152_ee66_dfab,
    0xa831_c66d_2db4_3210,
    0xb003_27c8_98fb_213f,
    0xbf59_7fc7_beef_0ee4,
    0xc6e0_0bf3_3da8_8fc2,
    0xd5a7_9147_930a_a725,
    0x06ca_6351_e003_826f,
    0x1429_2967_0a0e_6e70,
    0x27b7_0a85_46d2_2ffc,
    0x2e1b_2138_5c26_c926,
    0x4d2c_6dfc_5ac4_2aed,
    0x5338_0d13_9d95_b3df,
    0x650a_7354_8baf_63de,
    0x766a_0abb_3c77_b2a8,
    0x81c2_c92e_47ed_aee6,
    0x9272_2c85_1482_353b,
    0xa2bf_e8a1_4cf1_0364,
    0xa81a_664b_bc42_3001,
    0xc24b_8b70_d0f8_9791,
    0xc76c_51a3_0654_be30,
    0xd192_e819_d6ef_5218,
    0xd699_0624_5565_a910,
    0xf40e_3585_5771_202a,
    0x106a_a070_32bb_d1b8,
    0x19a4_c116_b8d2_d0c8,
    0x1e37_6c08_5141_ab53,
    0x2748_774c_df8e_eb99,
    0x34b0_bcb5_e19b_48a8,
    0x391c_0cb3_c5c9_5a63,
    0x4ed8_aa4a_e341_8acb,
    0x5b9c_ca4f_7763_e373,
    0x682e_6ff3_d6b2_b8a3,
    0x748f_82ee_5def_b2fc,
    0x78a5_636f_4317_2f60,
    0x84c8_7814_a1f0_ab72,
    0x8cc7_0208_1a64_39ec,
    0x90be_fffa_2363_1e28,
    0xa450_6ceb_de82_bde9,
    0xbef9_a3f7_b2c6_7915,
    0xc671_78f2_e372_532b,
    0xca27_3ece_ea26_619c,
    0xd186_b8c7_21c0_c207,
    0xeada_7dd6_cde0_eb1e,
    0xf57d_4f7f_ee6e_d178,
    0x06f0_67aa_7217_6fba,
    0x0a63_7dc5_a2c8_98a6,
    0x113f_9804_bef9_0dae,
    0x1b71_0b35_131c_471b,
    0x28db_77f5_2304_7d84,
    0x32ca_ab7b_40c7_2493,
    0x3c9e_be0a_15c9_bebc,
    0x431d_67c4_9c10_0d4c,
    0x4cc5_d4be_cb3e_42b6,
    0x597f_299c_fc65_7e2a,
    0x5fcb_6fab_3ad6_faec,
    0x6c44_198c_4a47_5817,
];

const K256: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

struct Processor512 {
    state: [u64; 8],
    buffer: [u8; 128],
    offset: usize,
    /// Only supports messages with at most 2^64 - 8 bits for now.
    len: u64,
}

struct Processor256 {
    state: [u32; 8],
    buffer: [u8; 64],
    offset: usize,
    len: u64,
}

macro_rules! impl_processor {
    (
        $processor:ident,
        $word:ty,
        $block_size:expr,
        $round_constants:expr,
        $rounds:expr,
        $read_into:path,
        $write_into:path,
        $b0:expr,
        $b1:expr,
        $s0:expr,
        $s1:expr,
    ) => {
        impl $processor {
            fn new(algorithm: &'static Algorithm<[$word; 8]>) -> Self {
                Self {
                    state: algorithm.initial_state,
                    buffer: [0; $block_size],
                    offset: 0,
                    len: 0,
                }
            }

            fn update(&mut self, input: &[u8]) {
                self.len += input.len() as u64;
                let mut input_offset = 0;
                let buffer_space = self.buffer.len() - self.offset;
                if self.offset > 0 {
                    if input.len() < buffer_space {
                        self.buffer[self.offset..self.offset + input.len()].copy_from_slice(input);
                        self.offset += input.len();
                        return;
                    }
                    self.buffer[self.offset..].copy_from_slice(&input[..buffer_space]);
                    self.offset = 0;
                    Self::process(&mut self.state, &self.buffer);
                    input_offset = buffer_space;
                }
                for chunk in input[input_offset..].chunks(self.buffer.len()) {
                    if chunk.len() < self.buffer.len() {
                        self.buffer[..chunk.len()].copy_from_slice(chunk);
                        self.offset = chunk.len();
                    } else {
                        Self::process(&mut self.state, chunk);
                    }
                }
            }

            fn write_digest(mut self, output: &mut [u8]) {
                self.pad();
                Self::process(&mut self.state, &self.buffer);
                $write_into(&self.state[..output.len() / size_of::<$word>()], output);
            }

            fn process(state: &mut [$word; 8], input: &[u8]) {
                let mut w = [0; $rounds];
                $read_into(input, &mut w[..16]);
                for t in 16..$rounds {
                    w[t] = Self::ssig1(w[t - 2])
                        .wrapping_add(w[t - 7])
                        .wrapping_add(Self::ssig0(w[t - 15]))
                        .wrapping_add(w[t - 16]);
                }
                let mut a = state[0];
                let mut b = state[1];
                let mut c = state[2];
                let mut d = state[3];
                let mut e = state[4];
                let mut f = state[5];
                let mut g = state[6];
                let mut h = state[7];
                for (&kt, &wt) in $round_constants.iter().zip(w.iter()) {
                    let t1 = h
                        .wrapping_add(Self::bsig1(e))
                        .wrapping_add(Self::ch(e, f, g))
                        .wrapping_add(kt)
                        .wrapping_add(wt);
                    let t2 = Self::bsig0(a).wrapping_add(Self::maj(a, b, c));
                    h = g;
                    g = f;
                    f = e;
                    e = d.wrapping_add(t1);
                    d = c;
                    c = b;
                    b = a;
                    a = t1.wrapping_add(t2);
                }
                state[0] = state[0].wrapping_add(a);
                state[1] = state[1].wrapping_add(b);
                state[2] = state[2].wrapping_add(c);
                state[3] = state[3].wrapping_add(d);
                state[4] = state[4].wrapping_add(e);
                state[5] = state[5].wrapping_add(f);
                state[6] = state[6].wrapping_add(g);
                state[7] = state[7].wrapping_add(h);
            }

            fn pad(&mut self) {
                self.buffer[self.offset] = 0x80;
                self.offset += 1;
                if self.offset > $block_size - 2 * size_of::<$word>() {
                    for byte in self.buffer.iter_mut().skip(self.offset) {
                        *byte = 0;
                    }
                    self.offset = 0;
                    Self::process(&mut self.state, &self.buffer);
                }
                for byte in self
                    .buffer
                    .iter_mut()
                    .take($block_size - 8)
                    .skip(self.offset)
                {
                    *byte = 0;
                }
                BigEndian::write_u64(&mut self.buffer[$block_size - 8..], 8 * self.len);
            }

            fn ch(x: $word, y: $word, z: $word) -> $word {
                (x & y) ^ (!x & z)
            }

            fn maj(x: $word, y: $word, z: $word) -> $word {
                (x & y) ^ (x & z) ^ (y & z)
            }

            fn bsig0(x: $word) -> $word {
                x.rotate_right($b0.0) ^ x.rotate_right($b0.1) ^ x.rotate_right($b0.2)
            }

            fn bsig1(x: $word) -> $word {
                x.rotate_right($b1.0) ^ x.rotate_right($b1.1) ^ x.rotate_right($b1.2)
            }

            fn ssig0(x: $word) -> $word {
                x.rotate_right($s0.0) ^ x.rotate_right($s0.1) ^ (x >> $s0.2)
            }

            fn ssig1(x: $word) -> $word {
                x.rotate_right($s1.0) ^ x.rotate_right($s1.1) ^ (x >> $s1.2)
            }
        }
    };
}

impl_processor!(
    Processor512,
    u64,
    128,
    K512,
    80,
    BigEndian::read_u64_into,
    BigEndian::write_u64_into,
    (28, 34, 39),
    (14, 18, 41),
    (1, 8, 7),
    (19, 61, 6),
);
impl_processor!(
    Processor256,
    u32,
    64,
    K256,
    64,
    BigEndian::read_u32_into,
    BigEndian::write_u32_into,
    (2, 13, 22),
    (6, 11, 25),
    (7, 18, 3),
    (17, 19, 10),
);

#[cfg(test)]
mod tests {
    use super::*;
    use std::string::String;
    use test_helpers::*;

    const TEST1: &[u8] = b"abc";
    const TEST2_1: &[u8] = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    const TEST2_2: &[u8] = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn\
        hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    const TEST3: &[u8] = &[0x61; 1000000];

    #[test]
    fn test_pad() {
        let message = [0b01100001, 0b01100010, 0b01100011, 0b01100100, 0b01100101];
        let expected = h2b(
            "6162636465800000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000028",
        );
        let mut processor = Processor512::new(&SHA512);
        processor.update(&message);
        processor.pad();
        assert_eq!(expected, processor.buffer.to_vec());

        let expected = h2b(
            "6162636465800000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000028",
        );
        let mut processor = Processor256::new(&SHA256);
        processor.update(&message);
        processor.pad();
        assert_eq!(expected, processor.buffer.to_vec());
    }

    macro_rules! check {
        ($function:ident, $wrapper:path, $expected:expr, $message:expr) => {
            let expected = h2b($expected);
            let actual = $wrapper($message);
            assert_eq!(expected, actual.to_vec());

            let actual = &mut vec![0; expected.len()];
            let mut sha = <$function>::default();
            for word in $message.chunks(4) {
                sha.update(word);
            }
            sha.write_digest(actual);
            assert_eq!(expected, actual.to_vec());
        };
    }

    fn check(exp512: &str, exp384: &str, exp256: &str, exp224: &str, message: &[u8]) {
        check512(exp512, exp384, message);
        check256(exp256, exp224, message);
    }

    fn check512(exp512: &str, exp384: &str, message: &[u8]) {
        check!(Sha512, sha512, exp512, message);
        check!(Sha384, sha384, exp384, message);
    }

    fn check256(exp256: &str, exp224: &str, message: &[u8]) {
        check!(Sha256, sha256, exp256, message);
        check!(Sha224, sha224, exp224, message);
    }

    #[test]
    fn test_digest() {
        let exp512 = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
                      47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
        let exp384 = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da\
                      274edebfe76f65fbd51ad2f14898b95b";
        let exp256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let exp224 = "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f";
        check(exp512, exp384, exp256, exp224, &[]);

        let exp512 = "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A\
                      2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F";
        let exp384 = "CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED\
                      8086072BA1E7CC2358BAECA134C825A7";
        let exp256 = "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD";
        let exp224 = "23097D223405D8228642A477BDA255B32AADBCE4BDA0B3F7E36C9DA7";
        check(exp512, exp384, exp256, exp224, TEST1);

        let exp512 = "8E959B75DAE313DA8CF4F72814FC143F8F7779C6EB9F7FA17299AEADB6889018\
                      501D289E4900F7E4331B99DEC4B5433AC7D329EEB6DD26545E96E55B874BE909";
        let exp384 = "09330C33F71147E83D192FC782CD1B4753111B173B3B05D22FA08086E3B0F712\
                      FCC7C71A557E2DB966C3E9FA91746039";
        check512(exp512, exp384, TEST2_2);

        let exp256 = "248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1";
        let exp224 = "75388B16512776CC5DBA5DA1FD890150B0C6455CB4F58B1952522525";
        check256(exp256, exp224, TEST2_1);

        let exp512 = "E718483D0CE769644E2E42C7BC15B4638E1F98B13B2044285632A803AFA973EB\
                      DE0FF244877EA60A4CB0432CE577C31BEB009C5C2C49AA2E4EADB217AD8CC09B";
        let exp384 = "9D0E1809716474CB086E834E310A4A1CED149E9C00F248527972CEC5704C2A5B\
                      07B8B3DC38ECC4EBAE97DDD87F3D8985";
        let exp256 = "CDC76E5C9914FB9281A1C7E284D73E67F1809A48A497200E046D39CCC7112CD0";
        let exp224 = "20794655980C91D8BBB4C1EA97618A4BF03F42581948B2EE4EE7AD67";
        check(exp512, exp384, exp256, exp224, TEST3);

        let mut test4 = String::new();
        for _ in 0..80 {
            test4.push_str("01234567");
        }
        let exp512 = "89D05BA632C699C31231DED4FFC127D5A894DAD412C0E024DB872D1ABD2BA814\
                      1A0F85072A9BE1E2AA04CF33C765CB510813A39CD5A84C4ACAA64D3F3FB7BAE9";
        let exp384 = "2FC64A4F500DDB6828F6A3430B8DD72A368EB7F3A8322A70BC84275B9C0B3AB0\
                      0D27A5CC3C2D224AA6B61A0D79FB4596";
        let exp256 = "594847328451BDFA85056225462CC1D867D877FB388DF0CE35F25AB5562BFBB5";
        let exp224 = "567F69F168CD7844E65259CE658FE7AADFA25216E68ECA0EB7AB8262";
        check(exp512, exp384, exp256, exp224, test4.as_bytes());
    }
}
