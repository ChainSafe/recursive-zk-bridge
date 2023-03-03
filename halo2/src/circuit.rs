use std::cell::RefCell;
use std::iter;
use std::marker::PhantomData;
use std::ops::{Add, Mul, Neg};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use ark_std::{end_timer, start_timer};
use halo2_gadgets::sha256::{BlockWord, Sha256, Sha256Instructions, Table16Chip, Table16Config};

use halo2_proofs::{
    arithmetic::{BaseExt, FieldExt},
    circuit::{Layouter, SimpleFloorPlanner},
    dev::MockProver,
    pairing::bn256::{Bn256, Fr, G1Affine},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ConstraintSystem, Error,
        SingleVerifier,
    },
    poly::commitment::{Params, ParamsVerifier},
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use halo2_proofs::arithmetic::{CurveAffine, Field, PairingCurveAffine};
use halo2_proofs::pairing::bn256::{G1, G1Compressed, G2, G2Affine, G2Compressed, pairing};
use halo2_proofs::pairing::group::cofactor::CofactorCurveAffine;
use halo2_proofs::pairing::group::{Curve, Group, GroupEncoding};

use halo2ecc_s::{
    circuit::{
        base_chip::{BaseChip, BaseChipConfig},
        range_chip::{RangeChip, RangeChipConfig},
    },
    context::{Context, Records},
};
use halo2ecc_s::assign::{AssignedCondition, AssignedFq2, AssignedG2Affine, AssignedPoint};
use halo2ecc_s::circuit::base_chip::BaseChipOps;
use halo2ecc_s::circuit::ecc_chip::{EccBaseIntegerChipWrapper, EccChipBaseOps};
use halo2ecc_s::circuit::fq12::{Fq12ChipOps, Fq2ChipOps};
use halo2ecc_s::circuit::pairing_chip::PairingChipOps;
use halo2ecc_s::context::{IntegerContext, NativeScalarEccContext};
use halo2ecc_s::utils::field_to_bn;
use hex::ToHex;
use itertools::Itertools;
use rand::rngs::OsRng;

use rand::RngCore;
use sha2::digest::core_api::Block;

#[derive(Clone)]
pub struct TestChipConfig {
    base_chip_config: BaseChipConfig,
    range_chip_config: RangeChipConfig,
    sha256: Table16Config,
}

#[derive(Default, Clone)]
pub struct TestCircuit {
    // witnesses:
    pub pub_keys: Vec<G1Affine>,
    pub signature: G2Affine,
    pub message_hash: G2Affine,
}

impl Circuit<Fr> for TestCircuit {
    type Config = TestChipConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let base_chip_config = BaseChip::configure(meta);
        let range_chip_config = RangeChip::<Fr>::configure(meta);
        TestChipConfig {
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
        let base_chip = BaseChip::new(config.base_chip_config);
        let range_chip = RangeChip::<Fr>::new(config.range_chip_config);

        range_chip.init_table(&mut layouter)?;

        Table16Chip::load(config.sha256.clone(), &mut layouter)?;
        let hash_chip = Table16Chip::construct(config.sha256.clone());

        layouter.assign_region(
            || "bls_verification",
            |mut region| {
                let timer = start_timer!(|| "assign::bls_verification");

                let ctx = Rc::new(RefCell::new(Context::new()));
                let ctx = IntegerContext::<halo2_proofs::pairing::bn256::Fq, Fr>::new(ctx);
                let mut ctx = NativeScalarEccContext::<G1Affine>(ctx);

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

                let a_h = assign_g2(&mut ctx, self.message_hash);

                ctx.check_pairing(&[(&a_g1_neg, &a_sig), (&agg_pubkey, &a_h)]);

                let ctx: Context<Fr> = ctx.into();

                Arc::try_unwrap(ctx.records).unwrap().into_inner().unwrap()
                    .assign_all(&mut region, &base_chip, &range_chip)?;
                end_timer!(timer);
                Ok(())
            },
        )?;

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
                        let words: Vec<_> = pubkey_hex.chunks_exact(4)
                            .map(|chunk| BlockWord(Some(u32::from_be_bytes(chunk.try_into().unwrap()))))
                            .collect();
                        leafs_layer.push(Sha256::digest(hash_chip.clone(), layouter.namespace(|| "ssz::pubkeys_root::leafs"), &words).unwrap().0);
                    }
                } else {
                    leafs_layer = leafs_layer.chunks_exact(2).map(|w| Sha256::digest(
                        hash_chip.clone(),
                        layouter.namespace(|| "ssz::pubkeys_root::branches"),
                        w.flatten()
                    ).unwrap().0).collect_vec()
                }
            }
            assert_eq!(leafs_layer.len(), 1);

            leafs_layer[0]
        };


        let agg_pubkey_hash = {
            let mut bytes = agg_pk.to_bytes().as_ref().to_vec();
            bytes.resize(64, 0);
            let words = bytes.chunks_exact(4)
                .map(|chunk| BlockWord(Some(u32::from_be_bytes(chunk.try_into().unwrap()))))
                .collect_vec();

            Sha256::digest(hash_chip.clone(), layouter.namespace(|| "ssz::agg_pubkey_hash"), &words).unwrap().0
        };

        let sync_committee_ssz = {
            let words = pubkeys_root.into_iter().chain(agg_pubkey_hash).collect_vec();
            Sha256::digest(hash_chip.clone(), layouter.namespace(|| "ssz::sync_committee"), &words).unwrap().0
        };

        let x = sync_committee_ssz.map(|w| w.0.unwrap().to_be_bytes()).flatten().to_vec();

        end_timer!(timer);

        Ok(())
    }
}

fn assign_g2(
    ctx: &mut NativeScalarEccContext<G1Affine>,
    point: G2Affine,
) -> AssignedG2Affine<G1Affine, Fr> {
    let x = AssignedFq2::from((
        ctx.base_integer_chip().assign_w(&field_to_bn(&point.coordinates().unwrap().x().c0)),
        ctx.base_integer_chip().assign_w(&field_to_bn(&point.coordinates().unwrap().x().c1))
    ));

    let y = AssignedFq2::from((
        ctx.base_integer_chip().assign_w(&field_to_bn(&point.coordinates().unwrap().y().c0)),
        ctx.base_integer_chip().assign_w(&field_to_bn(&point.coordinates().unwrap().y().c1))
    ));

    AssignedG2Affine::new(
        x,
        y,
        AssignedCondition(ctx.0.ctx.borrow_mut().assign_constant(Fr::zero())),
    )
}

pub fn build_bls_signature_verification_chip_over_bn256_fr_circuit(
    verifier_key: G1Affine,
    //msg: &[u8],
    h: G2Affine,
    sig: G2Affine,
) -> NativeScalarEccContext<G1Affine> {
    let ctx = Rc::new(RefCell::new(Context::new()));
    let ctx = IntegerContext::<halo2_proofs::pairing::bn256::Fq, Fr>::new(ctx);
    let mut ctx = NativeScalarEccContext::<G1Affine>(ctx);

    let a_vk = ctx.assign_point(&verifier_key.to_curve());

    let a_g1_neg = ctx.assign_constant_point(&G1::generator().neg());

    let a_sig = assign_g2(&mut ctx, sig);

    let a_h = assign_g2(&mut ctx, h);

    ctx.check_pairing(&[(&a_g1_neg, &a_sig), (&a_vk, &a_h)]);

    ctx
}

fn gen_keypair(mut rng: impl RngCore) -> (Fr, G1) {
    let x = Fr::random(&mut rng);

    (x, G1::generator().mul(x))
}

#[test]
fn test_standalone_circuit() {
    let circuit = test_circuit();

    let prover = match MockProver::run(22, &circuit, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    assert_eq!(prover.verify(), Ok(()));
}

pub fn test_circuit() -> TestCircuit {
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

    TestCircuit {
        pub_keys,
        signature: agg_sig,
        message_hash: h
    }
}
