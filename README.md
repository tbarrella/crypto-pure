# crypto-pure  [![Build Status](https://travis-ci.org/tbarrella/crypto-pure.svg?branch=master)](https://travis-ci.org/tbarrella/crypto-pure)

A pure-Rust cryptography library that aims to be lightweight.

This is still being developed and is not yet secure.

## Possible TODOs
* aes
  * add AES-128
  * bit slicing
* curve25519
  * clean up/make more idiomatic
* gcm
  * extend to support AES-128
* other
  * more tests
  * more documentation
  * refactor buffering for incremental processing
  * add RSA (PCKS1 and PSS) and/or NIST P-256 for key exchange
