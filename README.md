# Proof of Consensus: Recursive ZK

This repo contains prototype circuits to study use of recursive proof composition for proof-of-consensus based header oracles. 

The test circuit that is going to be proven recursively contains a light client sync committee rotation logic that consist of:
1. Using a next committee SSZ Merkle root (32 bytes) as a public input message, hash it to BLS12-381 G2 pairing curve point based on [draft-irtf-cfrg-hash-to-curve-16](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16)
2. Verify aggregate BLS signature using the hash point calculated in step 1 and aggregate public key of current committee.
3. Generate SSZ Merkle root of a current committee and return it as output.

## Theory

The theoretic background and proving systems overview can be found on [THEORY.md](./THEORY.md).

## Benchmarks

The experimental results can be found on [BENCHMARKS.md](./BENCHMARKS.md).

## Analysis

The analysis of this research can be found on [ANALYSIS.md](./ANALYSIS.md).
