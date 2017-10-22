# Cryptography Practice  [![Build Status](https://travis-ci.org/tbarrella/crypto-practice.svg?branch=master)](https://travis-ci.org/tbarrella/crypto-practice)

This is a way for me to practice Rust by writing cryptography-related functions.
Even though I attempt to use secure algorithms, the implementations are not
meant to be secure, so don't use them.

## Possible TODOs
* aes
  * create cipher API
  * bitslicing for `sub_bytes`
  * add AES-128
* chacha20
  * get blocks in parallel, async encrypt/decrypt
  * add Poly1305
* curve25519
  * rewrite everything in constant time, removing dependency on `num`
* gcm
  * extend to support other ciphers
  * improve tag verification
* ghash
  * make constant time once `u128` is stable
  * async hashing
* hkdf
  * support arbitrary hash algorithms
* hmac
  * support arbitrary hash algorithms
* sha
  * allow for incremental processing, preferably once `u128` is stable
  * add SHA-256
* other
  * remove usage of `Vec`
  * documentation, if anything ever becomes secure
  * add RSA (PCKS1 and PSS) and/or NIST P-256 for key exchange
