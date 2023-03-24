# Proof of Consensus: Recursive ZK

This repo contains prototype circuits to study use of recursive proof composition for proof-of-consensus based header oracles. 

The test circuit that is going to be proven recursively contains a light client sync committee rotation logic that consist of:
1. Using a next committee SSZ Merkle root (32 bytes) as a public input message, hash it to BLS12-381 G2 pairing curve point based on [draft-irtf-cfrg-hash-to-curve-16](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16)
2. Verify aggregate BLS signature using the hash point calculated in step 1 and aggregate public key of current committee.
3. Generate SSZ Merkle root of a current committee and return it as output.

## Background

In simple term, recursive proofs aka incrementally verifiable computation (IVC) is proof verified inside another proof aka proof of a proof. It's extremely powerful because it unlocks a supercharged version of stand SNARK properties:
- *Succinctness* $\rightarrow$ *Compression* // ability to compress arbitrarily amount of knowledge down to a single constant size short proof
- Zero-knowledge $\rightarrow$ *Composability* // ability to make statements about the knowledge that is distributed amount multiple disjoint parties without revealing all it to a common party

Practically today recursive proof composition can be differentiated in three categories that form a hierarchy based on requirements on the underlying proof systems:
1. *Full recursion* - require succinct verifier (e.g. STARK in Groth'16)
2. *Prover (atomic) accumulation* - require succinct accumulator (e.g. Halo2)
3. *Instance (split) accumulation* - require succinct public accumulator (e.g. Nova)

In the following sections we discuss prototype circuits each implementing one of these categories.

## STARK in Groth'16

[`Cairo`](https://www.cairo-lang.org/) is a DSL for STARKs which are known for their fast proof generation. The problem is that STARKs are FRI based proofs that are large (up to a several hundred kilobytes). Groth'16 proofs on the other hand are constant (~200B) and are as close to theoretical minimum as it gets. 

One can compose STARK verifier into a Groth'16 R1CS circuit thereby getting "best of both worlds". This would be an example of *full recursion* because on each step a STARK proof must be fully generated and then verified with Groth'16 system.

This is perhaps the most hacky method so I haven't initially planned to include it, but during writing have come up with a somewhat practical way to achieve it. 

Here's a brief instruction:
1. Use [`NethermindEth/optimized_ecc_cairo`](https://github.com/NethermindEth/optimized_ecc_cairo) to develop committee rotation in Cairo
2. Use [`maxgillett/giza`](https://github.com/maxgillett/giza) to prove Cairo code with [`facebook/winterfell`](https://github.com/facebook/winterfell) backend
3. Use [`VictorColomb/stark-snark-recursive-proofs`](https://github.com/VictorColomb/stark-snark-recursive-proofs) to compose Winterfell proof into Groth'16

## Halo2

Halo2 is both a proving system and the frontend SDK for itself. It's built for efficient recursion and it is based on *prover accumulation* scheme. Namely, on every recursion step only the accumulation check is performed that involves elliptic curve multi-scalar multiplication, but the expensive pairing checks are deferred to the very last step when the end proof is generated.

The [`SCRotationStepCircuit`](https://github.com/ChainSafe/recursive-zk-bridge/blob/main/halo2/src/circuit.rs) implement light client committee rotation as described above. The crate also contains modified [`Sha256`](https://github.com/ChainSafe/recursive-zk-bridge/blob/main/halo2/src/sha256.rs) and a brand new [`HashToCurve`](https://github.com/ChainSafe/recursive-zk-bridge/blob/main/halo2/src/sha256.rs) gadgets. The pairing cryptography for BLS12-381 is from [`DelphinusLab/halo2ecc-s`](https://github.com/DelphinusLab/halo2ecc-s) and aggregated verifier circuit is from [`DelphinusLab/halo2aggregator-s`](https://github.com/DelphinusLab/halo2aggregator-s).

The Halo2 system is based on older version from [`junyu0312/halo2`](https://github.com/junyu0312/halo2) fork. It supports GPU acceleration.

## Nova Scotia

Nova is not a proving system but a recursive SNARK pre-processor which is based on *instance accumulation* aka *folding scheme*. On each recursion step only public instances are accumulated and a very cheap accumulation check is performed (20k constraints). Public accumulator doesn't have access to private inputs, it instead relies on the prover to provide commitments to the private parts. The result is linear combination of public inputs from all steps that can be consumed by some external proving system to generate a final proof.

The original version of Nova from [\[KST21\]](https://eprint.iacr.org/2021/370.pdf) uses a relaxed R1CS for arithmetization and generates final proof using [`microsoft/spartan`](https://github.com/microsoft/Spartan) system. This prototype is based on [`nalinbhardwaj/Nova-Scotia`](https://github.com/nalinbhardwaj/Nova-Scotia) which is a combination of Circom HDL and Nova. The final proof is generated using Groth'16 system.

Nova can be combined with PLONK arithmetization. This is currently being explored by Geometry Research with [Sangria](https://geometryresearch.xyz/notebook/sangria-a-folding-scheme-for-plonk) project.


## Benchmarks

The experimental results can be found on [BENCHMARKS.md](./BENCHMARKS.md).
