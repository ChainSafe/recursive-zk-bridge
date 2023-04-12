use std::collections::HashMap;
use crate::circuit::{circuit_with_input, circuit_with_random_input, SCRotationStepCircuit};
use halo2_proofs::pairing::bn256::{Bn256, Fr, G1Affine};
use halo2aggregator_s::circuits::samples::simple::SimpleCircuit;
use halo2aggregator_s::circuits::utils::{load_or_build_unsafe_params, load_or_build_vkey, load_or_create_proof, store_instance, TranscriptHash};
use halo2ecc_s::context::Context;
use std::fs::DirBuilder;
use std::path::Path;
use std::sync::Arc;
use ark_std::{end_timer, start_timer};
use halo2_proofs::arithmetic::MultiMillerLoop;
use halo2_proofs::dev::MockProver;
use halo2_proofs::plonk::{Circuit, SingleVerifier, verify_proof, VerifyingKey};
use halo2_proofs::poly::commitment::ParamsVerifier;
use halo2_proofs::transcript::Blake2bRead;
use halo2aggregator_s::{circuit_verifier, native_verifier};
use halo2aggregator_s::circuit_verifier::build_aggregate_verify_circuit;
use halo2aggregator_s::circuit_verifier::circuit::AggregatorCircuit;
use halo2aggregator_s::native_verifier::verify_proofs;
use halo2aggregator_s::transcript::poseidon::PoseidonRead;
use halo2aggregator_s::transcript::sha256::ShaRead;

#[test]
fn test_one_layer_recursion_circuit() {
    let path = "./build";
    DirBuilder::new().recursive(true).create(path).unwrap();

    let path = Path::new(path);

    let (circuit, instances) = circuit_with_input("../input.json")[0].clone();

    let (circuit, instances) = run_circuit_unsafe_full_pass::<Bn256, _>(
        path,
        "step-circuit",
        22,
        vec![circuit],
        vec![instances],
        TranscriptHash::Poseidon,
        vec![],
        true,
    )
    .unwrap();

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

#[test]
fn test_proof_aggregation_circuit() {
    let path = "./build";
    DirBuilder::new().recursive(true).create(path).unwrap();

    let path = Path::new(path);

    let step_circuits = circuit_with_input("../input.json");

    let mut circuits = vec![];
    let mut instances = vec![];
    for (step_circuit, step_instances) in step_circuits {
        circuits.push(step_circuit);
        instances.push(step_instances);
    }

    let (circuit, instances) = run_circuit_unsafe_full_pass::<Bn256, _>(
        path,
        "step-circuit",
        22,
        circuits,
        instances,
        TranscriptHash::Poseidon,
        vec![],
        true,
    )
        .unwrap();

    run_circuit_unsafe_full_pass::<Bn256, _>(
        path,
        "verify-circuit",
        23,
        vec![circuit],
        vec![vec![instances]],
        TranscriptHash::Blake2b,
        vec![],
        true,
    );
}


pub fn run_circuit_unsafe_full_pass<E: MultiMillerLoop, C: Circuit<E::Scalar>>(
    cache_folder: &Path,
    prefix: &str,
    k: u32,
    circuits: Vec<C>,
    instances: Vec<Vec<Vec<E::Scalar>>>,
    hash: TranscriptHash,
    commitment_check: Vec<[usize; 4]>,
    force_create_proof: bool,
    // vkey_map: &mut HashMap<String, VerifyingKey<E::G1Affine>>
) -> Option<(AggregatorCircuit<E::G1Affine>, Vec<E::Scalar>)> {
    // 1. setup params
    let params =
        load_or_build_unsafe_params::<E>(k, Some(&cache_folder.join(format!("K{}.params", k))));

    let mut vkey_map = HashMap::new();
    let mut proofs = vec![];

    for (i, circuit) in circuits.into_iter().enumerate() {
        // 2. setup vkey
        let vkey = load_or_build_vkey::<E, C>(
            &params,
            &circuit,
            None, //Some(&cache_folder.join(format!("{}.{}.vkey.data", prefix, i))),
        );

        vkey_map.insert(format!("{}.{}.vkey.data", prefix, i), vkey.clone());

        // 3. create proof
        let proof = load_or_create_proof::<E, C>(
            &params,
            vkey.clone(),
            circuit,
            &instances[i].iter().map(|x| &x[..]).collect::<Vec<_>>(),
            Some(&cache_folder.join(format!("{}.{}.transcript.data", prefix, i))),
            hash,
            !force_create_proof,
        );
        proofs.push(proof);

        store_instance(
            &instances[i],
            &cache_folder.join(format!("{}.{}.instance.data", prefix, i)),
        );
    }

    // 4. many verify
    let public_inputs_size = instances.iter().fold(0usize, |acc, x| {
        usize::max(acc, x.iter().fold(0, |acc, x| usize::max(acc, x.len())))
    });
    let params_verifier: ParamsVerifier<E> = params.verifier(public_inputs_size).unwrap();

    let mut vkeys = vec![];

    for (i, proof) in proofs.iter().enumerate() {
        let vkey = vkey_map.get(&format!("{}.{}.vkey.data", prefix, i)).unwrap().clone();

        // origin check
        if true {
            let timer = start_timer!(|| "origin verify single proof");
            let strategy = SingleVerifier::new(&params_verifier);
            match hash {
                TranscriptHash::Blake2b => verify_proof(
                    &params_verifier,
                    &vkey,
                    strategy,
                    &[&instances[i].iter().map(|x| &x[..]).collect::<Vec<_>>()[..]],
                    &mut Blake2bRead::init(&proof[..]),
                ),
                TranscriptHash::Poseidon => verify_proof(
                    &params_verifier,
                    &vkey,
                    strategy,
                    &[&instances[i].iter().map(|x| &x[..]).collect::<Vec<_>>()[..]],
                    &mut PoseidonRead::init(&proof[..]),
                ),
                TranscriptHash::Sha => verify_proof(
                    &params_verifier,
                    &vkey,
                    strategy,
                    &[&instances[i].iter().map(|x| &x[..]).collect::<Vec<_>>()[..]],
                    &mut ShaRead::<_, _, _, sha2::Sha256>::init(&proof[..]),
                ),
            }
                .unwrap();
            end_timer!(timer);
        }

        // native single check
        if true {
            let timer = start_timer!(|| "native verify single proof");
            for (i, proof) in proofs.iter().enumerate() {
                native_verifier::verify_single_proof::<E>(
                    &params_verifier,
                    &vkey,
                    &instances[i],
                    proof.clone(),
                    hash,
                );
            }
            end_timer!(timer);
        }

        vkeys.push(vkey);
    }

    // native multi check
    if false {
        let timer = start_timer!(|| "native verify aggregated proofs");
        verify_proofs::<E>(
            &params_verifier,
            &vkeys.iter().map(|x| x).collect::<Vec<_>>()[..],
            instances.iter().collect(),
            proofs.clone(),
            hash,
            commitment_check.clone(),
        );
        end_timer!(timer);
    }

    // circuit multi check
    if hash == TranscriptHash::Poseidon {
        let timer = start_timer!(|| "circuit verify single proof");
        let (circuit, instances) = build_aggregate_verify_circuit::<E>(
            &params_verifier,
            &vkeys[..].iter().collect::<Vec<_>>(),
            instances.iter().collect(),
            proofs,
            hash,
            commitment_check,
        );
        end_timer!(timer);

        if false {
            const K: u32 = 21;
            let prover = MockProver::run(K, &circuit, vec![instances.clone()]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }

        Some((circuit, instances))
    } else {
        None
    }
}
