use std::cell::RefCell;
use std::{fs, iter};
use std::marker::PhantomData;
use std::ops::{Add, Mul, Neg};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::str::FromStr;
use std::sync::Arc;
use ark_std::{end_timer, start_timer};
use halo2_proofs::{
    arithmetic::{BaseExt, FieldExt},
    circuit::{Layouter, SimpleFloorPlanner},
    dev::MockProver,
    pairing::bn256::{Bn256, Fr},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ConstraintSystem, Error,
        SingleVerifier,
    },
    poly::commitment::{Params, ParamsVerifier},
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use halo2_proofs::arithmetic::{CurveAffine, Field, PairingCurveAffine};
use halo2_proofs::pairing::bls12_381::{Fq, G1Affine};
use halo2_proofs::pairing::bls12_381::{G1, G2, G2Affine, Fp2, pairing};
use halo2_proofs::pairing::group::cofactor::CofactorCurveAffine;
use halo2_proofs::pairing::group::{Curve, Group, GroupEncoding};
use halo2_proofs::pairing::group::prime::PrimeCurveAffine;
use sha2::Digest;
use halo2ecc_s::{
    circuit::{
        base_chip::{BaseChip, BaseChipConfig, BaseChipOps},
        range_chip::{RangeChip, RangeChipConfig, RangeChipOps},
    },
    context::{Context, Records},
};
use halo2ecc_s::assign::{AssignedCondition, AssignedFq2, AssignedG2Affine, AssignedPoint};
use halo2ecc_s::circuit::ecc_chip::{EccBaseIntegerChipWrapper, EccChipBaseOps};
use halo2ecc_s::circuit::fq12::{Fq12ChipOps, Fq2ChipOps};
use halo2ecc_s::circuit::pairing_chip::PairingChipOps;
use halo2ecc_s::context::{GeneralScalarEccContext, IntegerContext, NativeScalarEccContext};
use halo2ecc_s::utils::field_to_bn;
use hex::ToHex;
use itertools::Itertools;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::digest::core_api::Block;
use common::SlotCommitteeRotation;
use crate::hash2curve::HashToCurve;

use crate::sha256::{BlockWord, Sha256, Sha256Instructions, Table16Chip, Table16Config};

const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

#[derive(Clone)]
pub struct SCRotationStepConfig {
    base_chip_config: BaseChipConfig,
    range_chip_config: RangeChipConfig,
    sha256: Table16Config,
}

#[derive(Default, Clone)]
pub struct SCRotationStepCircuit {
    // witnesses:
    pub pub_keys: Vec<G1Affine>,
    pub signature: G2Affine,
    pub message_hash_point: G2Affine,
    pub message_hash: [u8; 32],
}

impl Circuit<Fr> for SCRotationStepCircuit {
    type Config = SCRotationStepConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let base_chip_config = BaseChip::configure(meta);
        let range_chip_config = RangeChip::<Fr>::configure(meta);
        SCRotationStepConfig {
            base_chip_config,
            range_chip_config,
            sha256: Table16Chip::configure(meta)
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let base_chip = BaseChip::<Fr>::new(config.base_chip_config);
        let range_chip = RangeChip::<Fr>::new(config.range_chip_config);

        range_chip.init_table(&mut layouter)?;

        Table16Chip::load(config.sha256.clone(), &mut layouter)?;
        let hash_chip = Table16Chip::construct(config.sha256.clone());

        let hash_point = {
            let mut ctx = Context::new();

            let msg = self.message_hash.map(|b| ctx.assign(Fr::from(b as u64)));

            let ctx = Rc::new(RefCell::new(ctx));

            let hash2curve = HashToCurve::new(ctx.clone(), hash_chip.clone());

            let g2 = hash2curve.hash_to_g2(msg, DST, layouter.namespace(|| "hash-to-curve"))?;

            drop(hash2curve);

            let records = Arc::try_unwrap(Rc::try_unwrap(ctx).unwrap().into_inner().records).unwrap().into_inner().unwrap();

            layouter.assign_region(
                || "bls_verification",
                |mut region| {
                    records.assign_all(&mut region, &base_chip, &range_chip)?;
                    Ok(())
                },
            )?;

            g2
        };

        layouter.assign_region(
            || "bls_verification",
            |mut region| {
                let timer = start_timer!(|| "assign::bls_verification");

                let ctx = Rc::new(RefCell::new(Context::new()));
                let mut ctx = GeneralScalarEccContext::<G1Affine, Fr>::new(ctx);

                let mut agg_pubkey = ctx.assign_identity(); //assign_constant_point(&G1::identity());
                for pk in &self.pub_keys {
                    agg_pubkey = {
                        let pk = ctx.assign_point(&pk.to_curve());
                        let p = ctx.ecc_add(&agg_pubkey, &pk);
                        ctx.to_point_with_curvature(p)
                    }
                }

                let agg_pubkey = AssignedPoint::new(agg_pubkey.x, agg_pubkey.y, agg_pubkey.z);

                let a_g1_neg = ctx.assign_constant_point(&G1::generator().neg());

                let a_sig = assign_g2(&mut ctx, self.signature);

                let a_h = assign_g2(&mut ctx, self.message_hash_point);

                // assert_eq!(a_h, hash_point);

                println!("x: ({{{:?}, {}}}, {{{:?}, {}}}), y: ({{{:?}, {}}}, {{{:?}, {}}}), z: {}",
                         hash_point.x.0.limbs_le.iter().map(|e| e.val.get_lower_128()).collect_vec(), hash_point.x.0.native.val.get_lower_128(),
                         hash_point.x.1.limbs_le.iter().map(|e| e.val.get_lower_128()).collect_vec(), hash_point.x.1.native.val.get_lower_128(),
                         hash_point.y.0.limbs_le.iter().map(|e| e.val.get_lower_128()).collect_vec(), hash_point.y.0.native.val.get_lower_128(),
                         hash_point.y.1.limbs_le.iter().map(|e| e.val.get_lower_128()).collect_vec(), hash_point.y.1.native.val.get_lower_128(),
                         hash_point.z.0.val.get_lower_128()
                );

                println!("x: ({{{:?}, {}}}, {{{:?}, {}}}), y: ({{{:?}, {}}}, {{{:?}, {}}}), z: {}",
                         a_h.x.0.limbs_le.iter().map(|e| e.val.get_lower_128()).collect_vec(), a_h.x.0.native.val.get_lower_128(),
                         a_h.x.1.limbs_le.iter().map(|e| e.val.get_lower_128()).collect_vec(), a_h.x.1.native.val.get_lower_128(),
                         a_h.y.0.limbs_le.iter().map(|e| e.val.get_lower_128()).collect_vec(), a_h.y.0.native.val.get_lower_128(),
                         a_h.y.1.limbs_le.iter().map(|e| e.val.get_lower_128()).collect_vec(), a_h.y.1.native.val.get_lower_128(),
                         a_h.z.0.val.get_lower_128()
                );

                ctx.check_pairing(&[(&a_g1_neg, &a_sig), (&agg_pubkey, &hash_point)]);

                let ctx: Context<Fr> = ctx.into();

                Arc::try_unwrap(ctx.records).unwrap().into_inner().unwrap()
                    .assign_all(&mut region, &base_chip, &range_chip)?;

                end_timer!(timer);

                Ok(())
            },
        )?;

        let ctx = Rc::new(RefCell::new(Context::new()));

        let mut agg_pk = G1::identity().to_affine();
        let mut pubkey_hexes = vec![];

        for pk in &self.pub_keys {
            agg_pk = agg_pk.add(pk.clone()).to_affine();
            pubkey_hexes.push(pk.to_bytes().as_ref().to_vec())
        }

        let timer = start_timer!(|| "assign::sync_committee_ssz");

        let pubkeys_root = {
            let mut leafs_layer = vec![];

            for layer in 0..5 {
                if layer == 0 {
                    for mut pubkey_hex in pubkey_hexes.clone() {
                        pubkey_hex.resize(64, 0);
                        leafs_layer.push(Sha256::digest_bytes(hash_chip.clone(), ctx.clone(), layouter.namespace(|| "ssz::pubkeys_root::leafs"), pubkey_hex).unwrap());
                    }
                } else {
                    leafs_layer = leafs_layer.chunks_exact(2).map(|w| Sha256::digest(
                        hash_chip.clone(),
                        ctx.clone(),
                        layouter.namespace(|| "ssz::pubkeys_root::branches"),
                        w.flatten().to_vec()
                    ).unwrap()).collect_vec()
                }
            }
            assert_eq!(leafs_layer.len(), 1);

            leafs_layer[0]
        };

        let agg_pubkey_hash = {
            let mut bytes = agg_pk.to_bytes().as_ref().to_vec();
            bytes.resize(64, 0);

            Sha256::digest_bytes(hash_chip.clone(), ctx.clone(), layouter.namespace(|| "ssz::agg_pubkey_hash"), bytes).unwrap()
        };

        let sync_committee_ssz = {
            let words = pubkeys_root.into_iter().chain(agg_pubkey_hash).collect_vec();
            Sha256::digest(hash_chip.clone(), ctx.clone(), layouter.namespace(|| "ssz::sync_committee"), words).unwrap()
        };

        let sync_committee_ssz = sync_committee_ssz.map(|w| w.val.get_lower_128() as u8).to_vec();

        println!("{:?}", sync_committee_ssz);

        end_timer!(timer);

        let records = Arc::try_unwrap(Rc::try_unwrap(ctx).unwrap().into_inner().records).unwrap().into_inner().unwrap();

        layouter.assign_region(
            || "bls_verification",
            |mut region| {
                records.assign_all(&mut region, &base_chip, &range_chip)?;
                Ok(())
            },
        )?;

        Ok(())
    }
}

fn assign_g2(
    ctx: &mut GeneralScalarEccContext<G1Affine, Fr>,
    point: G2Affine,
) -> AssignedG2Affine<G1Affine, Fr> {
    let x = AssignedFq2::from((
        ctx.base_integer_chip().assign_w(&field_to_bn(&point.x.c0)),
        ctx.base_integer_chip().assign_w(&field_to_bn(&point.x.c1))
    ));

    let y = AssignedFq2::from((
        ctx.base_integer_chip().assign_w(&field_to_bn(&point.y.c0)),
        ctx.base_integer_chip().assign_w(&field_to_bn(&point.y.c1))
    ));

    AssignedG2Affine::new(
        x,
        y,
        AssignedCondition(ctx.base_integer_ctx.ctx.borrow_mut().assign_constant(Fr::zero())),
    )
}

fn gen_keypair(mut rng: impl RngCore) -> (halo2_proofs::pairing::bls12_381::Fr, G1) {
    let x = halo2_proofs::pairing::bls12_381::Fr::random(&mut rng);

    (x, G1::generator().mul(x))
}

#[test]
fn test_standalone_circuit() {
    let circuit = circuit_with_input("../input_nova_bls_verify.json");

    let prover = match MockProver::run(22, &circuit, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    assert_eq!(prover.verify(), Ok(()));
}

pub fn circuit_with_random_input() -> SCRotationStepCircuit {
    let kps: Vec<_> = iter::repeat_with(|| gen_keypair(&mut OsRng)).take(16).collect();

    let h = G2::random(&mut OsRng).to_affine();

    let mut agg_pk = G1::identity().to_affine();
    let mut agg_sig = G2::identity().to_affine();
    let mut pub_keys = vec![];

    for (sk, pk) in kps {
        let sig = h.mul(sk);
        agg_sig = agg_sig.add(&sig).to_affine();
        agg_pk = agg_pk.add(pk.clone()).to_affine();
        pub_keys.push(pk.to_affine());
    }

    SCRotationStepCircuit {
        pub_keys,
        signature: agg_sig,
        message_hash_point: h,
        message_hash: [0; 32]
    }
}

pub fn circuit_with_input(p: impl AsRef<Path>) -> SCRotationStepCircuit {
    let input = {
        let inputs: Vec<SlotCommitteeRotation> = serde_json::from_slice(&fs::read(p).unwrap()).unwrap();
        inputs[0].clone()
    };

    let pub_keys = input.pubkey_hexes.into_iter().map(|pk| G1Affine::from_compressed(&pk.try_into().unwrap()).unwrap()).collect_vec();

    let signature = G2Affine::from_compressed(input.signature_hex.as_slice().try_into().unwrap()).unwrap();
    let message_hash = G2Affine::from_compressed(input.hm_hex.as_slice().try_into().unwrap()).unwrap();

    let mut agg_pubkey = G1::identity().to_affine();
    for pk in &pub_keys {
        agg_pubkey = agg_pubkey.add(pk.clone()).to_affine();
    }

    println!("bn input {}", field_to_bn(&message_hash.x.c0));

    assert_eq!(
        pairing(&G1Affine::generator(), &signature),
        pairing(&agg_pubkey, &message_hash)
    );

    SCRotationStepCircuit {
        pub_keys,
        signature,
        message_hash_point: message_hash,
        message_hash: input.old_committee_root.try_into().unwrap()
    }
}
