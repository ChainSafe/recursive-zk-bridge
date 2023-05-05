use ark_std::{end_timer, start_timer};
use std::{collections::HashMap, env::current_dir, fs, time::Instant};

use common::SlotCommitteeRotation;
use nova_scotia::{
    circom::reader::load_r1cs, create_public_params, create_recursive_circuit, FileLocation, F1,
    G1, G2,
};
use nova_snark::{traits::Group, CompressedSNARK};
use serde_json::json;

fn main() {
    let iteration_count = 1;
    let root = current_dir().unwrap();

    let timer = start_timer!(|| "load_r1cs");
    let circuit_file = root.join("./build/committee_rotation_step_pasta.r1cs");
    let r1cs = load_r1cs(&FileLocation::PathBuf(circuit_file));
    let witness_generator_file =
        root.join("./build/committee_rotation_step_pasta_js/committee_rotation_step_pasta.wasm");
    end_timer!(timer);

    let inputs: Vec<SlotCommitteeRotation> =
    serde_json::from_slice(&fs::read("../input.json").unwrap()).unwrap();

    let mut private_inputs = Vec::new();
    for input in inputs.into_iter().take(iteration_count) {
        let mut private_input = HashMap::new();
        private_input.insert("pubkeys".to_string(), json!(input.pubkeys));
        private_input.insert("pubkeybits".to_string(), json!(input.pubkeybits));
        private_input.insert("signature".to_string(), json!(input.signature));
        private_input.insert("pubkeyHex".to_string(), json!(input.pubkey_hexes));
        private_input.insert(
            "aggregatePubkeyHex".to_string(),
            json!(input.agg_pubkey_hex),
        );

        private_inputs.push(private_input);
    }

    let start_public_input = [F1::from(0); 32].to_vec();


    let (pp, timer)= if fs::metadata("./build/public_params.wtns").is_ok() {
        let timer: ark_std::perf_trace::TimerInfo = start_timer!(|| "read_public_params");

        let pp_bytes = fs::read("./build/public_params.wtns").unwrap();
        (serde_cbor::from_slice(&pp_bytes).unwrap(), timer)
    } else {
        let timer: ark_std::perf_trace::TimerInfo = start_timer!(|| "create_public_params");
        
        let pp = create_public_params(r1cs.clone());
    
        let pp_json = serde_cbor::to_vec(&pp).unwrap();
        fs::write("./build/public_params.wtns", pp_json).unwrap();

        println!(
            "Number of constraints per step (primary circuit): {}",
            pp.num_constraints().0
        );
        println!(
            "Number of constraints per step (secondary circuit): {}",
            pp.num_constraints().1
        );
    
        println!(
            "Number of variables per step (primary circuit): {}",
            pp.num_variables().0
        );
        println!(
            "Number of variables per step (secondary circuit): {}",
            pp.num_variables().1
        );
    
        (pp, timer)
    };

    end_timer!(timer);

    let timer = start_timer!(|| "create_recursive_snark");
    let recursive_snark = create_recursive_circuit(
        FileLocation::PathBuf(witness_generator_file),
        r1cs,
        private_inputs,
        start_public_input.clone(),
        &pp,
    )
    .unwrap();
    end_timer!(timer);

    // TODO: empty?
    let z0_secondary = vec![<G2 as Group>::Scalar::zero()];

    // verify the recursive SNARK
    let timer = start_timer!(|| "verify_recursive_snark");
    let res = recursive_snark.verify(
        &pp,
        iteration_count,
        start_public_input.clone(),
        z0_secondary.clone(),
    );
    println!("RecursiveSNARK::verify: {:?}", res);
    assert!(res.is_ok());
    end_timer!(timer);

    // produce a compressed SNARK
    // println!("Generating a CompressedSNARK using Spartan with IPA-PC...");
    // let start = Instant::now();
    // type S1 = nova_snark::spartan_with_ipa_pc::RelaxedR1CSSNARK<G1>;
    // type S2 = nova_snark::spartan_with_ipa_pc::RelaxedR1CSSNARK<G2>;
    // let res = CompressedSNARK::<_, _, _, _, S1, S2>::prove(&pp, &recursive_snark);
    // println!(
    //     "CompressedSNARK::prove: {:?}, took {:?}",
    //     res.is_ok(),
    //     start.elapsed()
    // );
    // assert!(res.is_ok());
    // let compressed_snark = res.unwrap();
    //
    // // verify the compressed SNARK
    // println!("Verifying a CompressedSNARK...");
    // let start = Instant::now();
    // let res = compressed_snark.verify(
    //     &pp,
    //     iteration_count,
    //     start_public_input.clone(),
    //     z0_secondary,
    // );
    // println!(
    //     "CompressedSNARK::verify: {:?}, took {:?}",
    //     res.is_ok(),
    //     start.elapsed()
    // );
    // assert!(res.is_ok());
}
