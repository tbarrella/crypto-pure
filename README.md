# crypto-pure  [![Build Status](https://travis-ci.org/tbarrella/crypto-pure.svg?branch=master)](https://travis-ci.org/tbarrella/crypto-pure)

A pure-Rust cryptography library that aims to be lightweight.

This is still being developed and is not yet secure.

## Possible TODOs
* aes
  * constant time `sub_bytes`
  * create Cipher trait
  * add AES-128
* chacha20
  * incremental encryption/decryption
  * get blocks in parallel
  * add Poly1305
* curve25519
  * clean up/make more idiomatic
* gcm
  * incremental encryption/decryption
  * extend to support other ciphers
  * improve tag verification
* ghash
  * incremental processing
* hkdf
  * support more hash algorithms
* hmac
  * support more hash algorithms
* sha
  * allow updates after getting digest
  * add SHA-256
* other
  * work on HashFunction trait
  * refactor buffering for incremental processing
  * documentation for anything that might be secure
  * add RSA (PCKS1 and PSS) and/or NIST P-256 for key exchange
