# BLST benchmarks

Benchmarks showing different ways of using aggregated BLS signaturess using the [BLST](https://crates.io/crates/blst) library.

## Rationale

Vanilla BLS signatures are vulnerable to rogue-key attacks, where an adversary effectively forges an aggregated signature using a public key to which it does not control the signing key.
As described in a [paper](https://crypto.stanford.edu/~dabo/pubs/papers/aggreg.pdf) by Boneh _et al._, there are different ways to mitigate the risk.

One is to use a _proof of possession_, where each signer generates an initial signature using its signing key that must be verified.
Thereafter, it suffices for such signers to generate an aggregate signature on a common message that can be verified efficiently.

Another is to use _distinct messages_, where each signer of a common message first prepends its verification key to the message.
An aggregate signature on these messages cannot be verified as efficiently.

This repository contains benchmarks for different aspects of these designs:
- proof of possession verification with verification key validation
- proof of possession batch verification with verification key validation
- aggregated signature verification on common messages without verification key validation
- aggregated signature verification on key-prefixed distinct messages with verification key validation

Each benchmark is run using BLST's minimal key and minimal signature variants.

## Running benchmarks

Run the benchmarks with `cargo bench`.

## Warning

This code is for testing only, and is not intended for use in production.
