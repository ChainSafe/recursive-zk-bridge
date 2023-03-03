use halo2aggregator_s::circuits::samples::simple::SimpleCircuit;
use halo2aggregator_s::circuits::utils::run_circuit_unsafe_full_pass;
use halo2aggregator_s::circuits::utils::TranscriptHash;
use halo2_proofs::pairing::bn256::{Bn256, Fr};
use std::fs::DirBuilder;
use std::path::Path;
use std::sync::Arc;
use halo2ecc_s::context::Context;
use crate::circuit::{build_bls_signature_verification_chip_over_bn256_fr_circuit, test_circuit, TestCircuit};

#[test]
fn test_one_layer_recursion_circuit() {
    let path = "./output";
    DirBuilder::new().recursive(true).create(path).unwrap();

    let path = Path::new(path);

    let circuit = test_circuit();
    let instances = vec![];

    let (circuit, instances) = run_circuit_unsafe_full_pass::<Bn256, _>(
        path,
        "simple-circuit",
        22,
        vec![circuit],
        vec![instances],
        TranscriptHash::Poseidon,
        vec![],
        true,
    ).unwrap();

    run_circuit_unsafe_full_pass::<Bn256, _>(
        path,
        "verify-circuit",
        22,
        vec![circuit],
        vec![vec![instances]],
        TranscriptHash::Blake2b,
        vec![],
        true,
    );
}
