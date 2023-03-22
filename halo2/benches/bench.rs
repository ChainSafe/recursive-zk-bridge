use std::fs::DirBuilder;
use std::path::Path;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use halo2_proofs::pairing::bn256::{Bn256, Fr};
use halo2aggregator_s::circuits::utils::{load_or_build_unsafe_params, load_or_build_vkey, load_or_create_proof, TranscriptHash};
use committee_rotation_halo2::{circuit_with_input, SCRotationStepCircuit};

fn bench_step_circuit_gen(c: &mut Criterion) {
    const prefix: &str = "step-circuit";
    const K: u32 = 22;
    let path = {
        let p = "./build";
        DirBuilder::new().recursive(true).create(p).unwrap();
        Path::new(p)
    };
    let circuit = circuit_with_input("../input.json");

    let params =
        load_or_build_unsafe_params::<Bn256>(K, Some(&path.join(format!("K{}.params", K))));

    let vkey = load_or_build_vkey::<Bn256, SCRotationStepCircuit>(
        &params,
        &circuit,
        Some(&path.join(format!("{}.vkey.data", prefix))),
    );
    let mut group = c.benchmark_group("rotation_step_circuit-proofgen-blake2");

    let instances: Vec<Fr> = vec![];

    group.sample_size(10);
    group.bench_function("transcript::blake2b", |b| {
        let proof = load_or_create_proof::<Bn256, SCRotationStepCircuit>(
            &params,
            vkey.clone(),
            circuit.clone(),
            &[&instances],
            Some(&path.join(format!("{}.transcript.data", prefix))),
            TranscriptHash::Blake2b,
            false,
        );
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_step_circuit_gen
);
criterion_main!(benches);
