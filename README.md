# crypto-pure  [![Build Status](https://travis-ci.org/tbarrella/crypto-pure.svg?branch=master)](https://travis-ci.org/tbarrella/crypto-pure)

A pure-Rust cryptography library that aims to be lightweight.

This is still being developed and is not yet secure.

## Possible TODOs
* aes
  * create Cipher trait
  * add AES-128
  * bit slicing
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
* other
  * more tests
  * more documentation
  * refactor buffering for incremental processing
  * add RSA (PCKS1 and PSS) and/or NIST P-256 for key exchange
