use std::cell::RefCell;
use std::marker::PhantomData;
use std::ops::{Add, Mul, Neg};
use std::rc::Rc;
use std::sync::Arc;
use ark_std::{end_timer, start_timer};

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
use halo2ecc_s::assign::{AssignedCondition, AssignedG2Affine};
use halo2ecc_s::circuit::base_chip::BaseChipOps;
use halo2ecc_s::circuit::ecc_chip::EccChipBaseOps;
use halo2ecc_s::circuit::fq12::{Fq12ChipOps, Fq2ChipOps};
use halo2ecc_s::circuit::pairing_chip::PairingChipOps;
use halo2ecc_s::context::{IntegerContext, NativeScalarEccContext};
use rand::rngs::OsRng;

use milagro_bls::*;
use rand::RngCore;

#[derive(Clone)]
struct TestChipConfig {
    base_chip_config: BaseChipConfig,
    range_chip_config: RangeChipConfig,
}

#[derive(Default, Clone)]
struct TestCircuit<N: FieldExt> {
    records: Records<N>,
}

impl<N: FieldExt> Circuit<N> for TestCircuit<N> {
    type Config = TestChipConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
        let base_chip_config = BaseChip::configure(meta);
        let range_chip_config = RangeChip::<N>::configure(meta);
        TestChipConfig {
            base_chip_config,
            range_chip_config,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<N>,
    ) -> Result<(), Error> {
        let base_chip = BaseChip::new(config.base_chip_config);
        let range_chip = RangeChip::<N>::new(config.range_chip_config);

        range_chip.init_table(&mut layouter)?;

        layouter.assign_region(
            || "base",
            |mut region| {
                let timer = start_timer!(|| "assign");
                self.records
                    .assign_all(&mut region, &base_chip, &range_chip)?;
                end_timer!(timer);
                Ok(())
            },
        )?;


        Ok(())
    }
}

pub fn run_circuit_on_bn256(ctx: Context<Fr>, k: u32) {
    println!("offset {} {}", ctx.range_offset, ctx.base_offset);

    let circuit = TestCircuit::<Fr> {
        records: Arc::try_unwrap(ctx.records).unwrap().into_inner().unwrap(),
    };

    let prover = match MockProver::run(k, &circuit, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    assert_eq!(prover.verify(), Ok(()));
}

fn assign_g2(
    ctx: &mut NativeScalarEccContext<G1Affine>,
    point: G2Affine,
) -> AssignedG2Affine<G1Affine, Fr> {
    let x = ctx.fq2_assign_constant((
        point.coordinates().unwrap().x().c0,
        point.coordinates().unwrap().x().c1,
    ));
    let y = ctx.fq2_assign_constant((
        point.coordinates().unwrap().y().c0,
        point.coordinates().unwrap().y().c1,
    ));

    AssignedG2Affine::new(
        x,
        y,
        AssignedCondition(ctx.0.ctx.borrow_mut().assign_constant(Fr::zero())),
    )
}

fn build_bls_signature_verification_chip_over_bn256_fr_circuit(
    verifier_key: G1Affine,
    //msg: &[u8],
    h: G2Affine,
    sig: G2Affine,
) -> NativeScalarEccContext<G1Affine> {
    let ctx = Rc::new(RefCell::new(Context::new()));
    let ctx = IntegerContext::<halo2_proofs::pairing::bn256::Fq, Fr>::new(ctx);
    let mut ctx = NativeScalarEccContext::<G1Affine>(ctx);

    // let h = G1Affine::random(&mut OsRng);

    let a_vk = ctx.assign_point(&verifier_key.to_curve());

    let a_g1_neg = ctx.assign_point(&G1::generator().neg());

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
fn test_bn256_pairing_chip_over_bn256_fr() {
    let kps = [
        gen_keypair(&mut OsRng),
        gen_keypair(&mut OsRng),
        gen_keypair(&mut OsRng),
    ];

    // let msg = "hello zk".as_bytes();

    let h = G2::random(&mut OsRng).to_affine();

    let mut agg_pk = G1::identity().to_affine();
    let mut agg_sig = G2::identity().to_affine();

    for (sk, pk) in kps {
        let sig = h.mul(sk);
        agg_sig = agg_sig.add(&sig).to_affine();
        agg_pk = agg_pk.add(pk.clone()).to_affine();
    }

    assert_eq!(
        G1::generator().to_affine().pairing_with(&agg_sig),
        agg_pk.pairing_with(&h),
    );

    let ctx = build_bls_signature_verification_chip_over_bn256_fr_circuit(
        agg_pk, h, agg_sig,
    );
    run_circuit_on_bn256(ctx.into(), 22);
}
