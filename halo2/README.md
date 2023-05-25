# Halo 2

## Requirements

- Rust
- Cuda 11+ & Nvidia Driver 525+ - see instructions [here](https://gist.github.com/primus852/b6bac167509e6f352efb8a462dcf1854#file-cuda_11-7_installation_on_ubuntu_22-04-L13-L49)

## Instruction

Run proof generation test:

```bash
cargo test --release --package committee-rotation-halo2 test_proof_aggregation_circuit -- --nocapture
```

For GPU-accelerated proof generation, run:

```bash
export EC_GPU_CUDA_NVCC_ARGS="--fatbin --gpu-architecture=sm_70 --generate-code=arch=compute_70,code=sm_70"
cargo test --release --features=cuda --package committee-rotation-halo2 test_proof_aggregation_circuit -- --nocapture
```
