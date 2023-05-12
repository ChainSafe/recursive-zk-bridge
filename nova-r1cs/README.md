# Nova Scotia

## Requirements

- Rust
- [Circom w/ Pasta Curves](https://github.com/nalinbhardwaj/circom)
- `gcc`, `nlohmann-json3-dev`, `libgmp-dev` and `nasm` (for native witness generation, use WASM otherwise) see [docs](https://docs.circom.io/getting-started/computing-the-witness/#what-is-a-witness).

## Instruction

Setup: increase maximum number of mapped ranges (details [here](https://www.systutorials.com/maximum-number-of-mmaped-ranges-and-how-to-set-it-on-linux/))

```bash
sudo sysctl -w vm.max_map_count=655300
```

Install dependencies

```bash
npm i && cd circom-pairing && npm i && cd ..
```

Compile Circom circuits. Use `--c` for native witness generation.

```bash
circom ./circuits/committee_rotation_step.circom -o ./build --r1cs --sym --wasm --prime vesta
```

For native witness generation compile binaries too:

```bash
cd ./build/committee_rotation_step/committee_rotation_step_cpp && make
```

(optionally) generate test inputs

```bash
npx tsx scripts/generate_input_data.ts
```

Run proof generation test:

```bash
cargo run --release
```
