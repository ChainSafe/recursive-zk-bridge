# Anylysis

> Please see the experimental results first: [BENCHMARKS.md](./BENCHMARKS.md)

For analysis let's look at the studied proving systems using following 7 aspects:

### Software generation

PLONK-based systems (Halo2, Plonky2) are equipped with widely recognized optimizations such as custom gates and lookup arguments. While leveraging these comes with a steep learning curve it's hard to imagine writing circuits for complex applications (zkEVMs, zkPoS) on older R1CS-based systems (Groth'16, Circom) that don't support them.  New-generation systems are also modular which can allow reusing same code for multiple deployments (KZG backend for EVM, FRI backend for Cosmos, etc).

### Performance
Based on the [benchmarks](https://github.com/ChainSafe/recursive-zk-bridge/blob/main/BENCHMARKS.md) both Circom and Halo2-GPU significantly outperform other systems (Plonky2, STARK) where Halo2-GPU is faster in smaller circuit with BLS-pairing only, but Circom marginally wins with composite "committee rotation" circuit. 

What's important to note, is that the performance argument is rather a tricky one: on paper, more speed & purpose optimized systems should always be faster (e.g. Plonky2 should be faster than Halo2), in practice however the more developed systems with better-optimized libraries are able to compensate for the inferior underlying design (e.g. Circom's extreme preprocessing during compilation and heavily optimized c++ prover [`iden3/rapidsnark`](https://github.com/iden3/rapidsnark) are surprisingly fast for almost a decade old Groth'16 system). So, when choosing a proving backend, the adoption of the system is just as important as its underlying design and raw performance numbers.

### On-chain verification cost

When it comes to proof verification and proof size Groth'16 is the current theoretical minimum (230k gas). Systems like Plonky2 & STARK are much more expensive to verify both because of larger proofs (KBs for Plonky2, hundreds KBs for STARK) but also because EVM lucks cryptography to verify them efficiently (Goldilocks curve, hash functions). Halo2-ce (community edition) is in an interesting compromise because the resulting proofs are larger than Groth'16 but it's KZG based so can be efficiently verified on EVM.

### Recursive proving support
Halo2, Plonky2 were design for recursion, while Groth'16 didn't. Although the combination of Nova and Groth'16 aka Nova Scotia could theoretically flip the odds, the reality is that the current implementation is suboptimal, lacks final composition to Groth'16, and overall is harder to apply to zkPoS application as it's more suited for zkVMs.

### Distributed proof generation support
This prototype shows that Halo2 can efficiently support PCD-based parallelization. Alternative techniques would be studied separately.

### Hardware acceleration

Modular proving systems (Halo2, Plonky2) are better suited for hardware acceleration than monolithic ones (Circom). Halo2-GPU already shows a significant bump in performance, and yet it's still the worse it would ever be. Current efforts only accelerate FFTs. It also lacks support for distributing the load on multiple cards. All that and more is a big focus for the industry right now.

### Library ecosystem & Industry adoption

Circom is the oldest and most used of all the researched systems, having perhaps the richest library ecosystems and most optimized prover software. However, as the industry focus shifts towards PLONK-based systems Halo2 gains increasingly more trust and interest with players like EF and Scroll building on it and extending its ecosystem. Interestingly, Plonky2 ecosystem also grows steadily with players like JumpCrypto joining.

## Conclusion

Considering the requirements of our target application (Proof of Consensus) and the direction where industry is heading Halo2 system looks most promising of all. 

It's true thjat Circom (Groth'16) was marginally better at some tests thanks to better optimized circuits (developed by 0xPARC and Succinct Labs) and heavy preprocessing during compilation (8.5 hours).

Nonetheless, Halo2 in my view has much greater potential because of being a newer-generation modular system with the most expressive PLONK-based language, rich custom gates and lookup argument, and native support for recursive proof composition and hardware acceleration.

> **Note**: we are still short of distributed proof generation and on-chain verification cost study results to make a fully definitive decision here. Research in these directions is currently ongoing.
