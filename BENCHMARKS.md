# Benchmarks

## Setup
- CPU: `Intel Xeon (Cascade Lake) 32-core vCPU @ 3.1 GHz` ([AWS r5n.8xlarge](https://instances.vantage.sh/aws/ec2/r5n.8xlarge))
- RAM: `256gB`
- GPU: `4 NVIDIA Tesla V100 16gB RAM each` ([AWS p3.8xlarge](https://instances.vantage.sh/aws/ec2/p3.8xlarge))

## Pairing

|                     | Halo2          | Halo2-GPU        | Circom (Groth'16) | Plonky2           | Cairo (STARK)   |
| ------------------- | -------------- | ---------------- | ----------------- | ----------------- | --------------- |
| Circuit compilation | `179s` ✅ 1.0x | `45.1s` 🚀 3.9x  | `2.7h` 🐢 54x     | `1453s` 🐢 8.1x   | `?`             |
| Proof generation    | `185s` ✅ 1.0x | `55.3s` 🚀 3.4x  | `112s` 🚀 1.7x    | `892s` 🐢 4.8x    | `410s` 🐢 2.2x  |
| Proof verification  | `10ms` ✅ 1.0x | `10ms` ✅ 1.0x   | `100ms` 🐢 10x    | `55.1ms` 🐢 5.5x  | `?`             |

> **Note**: Proof verification in Circom is using JavaScript while other systems use Rust. If compared fairly Groth'16 verification would likely be the fastest one of all.

> I'm not an expert in Plonky2 but resulted prover time seem too slow. It's likely due to poorly optimized [implementation](https://github.com/polymerdao/plonky2-pairing). Another team from JumpCrypto promised their [BLS pairing](https://github.com/jumpcrypto/plonky2-crypto#features) so we'll have to wait and see.

> Cairo benchmarks are taken from [`0xNonCents/cairo-bls12-381`](https://github.com/0xNonCents/cairo-bls12-381#benchmark).

## Committe rotation

Following tests are done with `N=16` validators. Doing `N=512` is possibly with Circom but compilation is absurdly slow so I didn't bother.

|                     | Halo2                      | Halo2-GPU                   | Circom (Groth'16) |
| ------------------- | -------------------------- | --------------------------- | ----------------- |
| Circuit compilation | `453s` &emsp; ✅ 1.0x      | `80s` &emsp;&nbsp; 🚀 5.7x  | `8.53h`  🐢 67.8x |
| Proof generation    | `508.9s` ✅ 1.0x           | `227.7s` 🚀 2.23x           | `172s`  🚀 2.95x |
| Proof verification  | `51ms` &emsp;&nbsp;✅ 1.0x | `51ms`&emsp; ✅ 1.0x        | `100ms`   🐢 1.9x |
| Proof size          | `5.34kB` ✅ 1.0x           | `5.34kB` ✅ 1.0x            | `704B`   🚀 7.59x |

> **Note**: My Halo2 implementation is far from optimal (can be improved by using lookup arguments and custom gates, parallelizing MSM, etc). All the while, Circom code is highly optimized and currently is being used in production by Succinct Labs.

Unfortunatly, Halo2-GPU test with `N=512` run out GPU memory. The main issue, is that current implemenation doesn't support mutli-GPU setups. This is something that can be fixed in the future. 

For comparsion, tests below are done on the `Intel Xeon(R) (Ice Lake) 64-core vCPU @ 3.5 GHz & 512 RAM` ([AWS r6in.16xlarge](https://instances.vantage.sh/aws/ec2/r6in.16xlarge)) instance.

| Validators | Compile   | Generate | Verify | Max RAM |
| ---------- | --------- | -------- | ------ | ------- |
| 16         | `219.8s`  | `199.9s` | `36ms` | `98gB`  |
| 512        | `496.9s`  | `396.1s` | `45ms` | `175gB` |
| 1024       | `1049.5s` | `784.2s` | `62ms` | `350gB` |


## Committe rotation (recursion enabled)

Following tests are done with `N=16` validators. The aim is to chain multiple proofs together to reduce the ammortize proof verification cost. 

Both tests are achiving this goal differently:
- With Halo2 we generate multiple step proofs and then verify them all in the final aggregated proof.
- With Nova we fold public inputs for multiple steps and then generating a single proof.

 > **Note**: Atomic accumulation which Halo2 is known for isn't supported with the current implementation. Using it would further reduce down prover time as expansive pairing checks are delayed for final proof only.

|                     | Halo2 Aggregate | Nova R1CS       |
| ------------------- | --------------- | --------------- |
| Circuit compilation | `135s`          | `1h`            |
| Proof generation    | `N*228s + 126s` | `976s + N*110s` |
| Proof verification  | `26.6ms`        |                 |
| Proof size          | `3.13kB`        |                 |


> **Note**: Step proofs in Halo2 can be generated in parallel on multiple threads or machines. However, folding with Nova sequential process and can't be parallelized.
