use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::pairing;
use halo2_proofs::pairing::bls12_381::{Fp2, Fq, G1Affine, G2Affine, G2};
use halo2_proofs::pairing::bn256::Fr;
use halo2_proofs::pairing::group::prime::PrimeCurveAffine;
use halo2ecc_s::assign::{
    AssignedCondition, AssignedFq2, AssignedG2, AssignedG2Affine, AssignedInteger,
};
use halo2ecc_s::circuit::base_chip::BaseChipOps;
use halo2ecc_s::circuit::ecc_chip::{EccBaseIntegerChipWrapper, EccChipScalarOps};
use halo2ecc_s::circuit::fq12::Fq2ChipOps;
use halo2ecc_s::circuit::integer_chip::IntegerChipOps;
use halo2ecc_s::circuit::pairing_chip::PairingChipOps;
use halo2ecc_s::context::{Context, GeneralScalarEccContext};
use halo2ecc_s::utils::{bn_to_field, field_to_bn};
use itertools::Itertools;
use num_bigint::BigUint;
use num_traits::{One, ToPrimitive, Zero};
use std::cell::RefCell;
use std::ops::{Mul, MulAssign};
use std::rc::Rc;
use subtle::Choice;

pub fn fq_from(n: u64) -> Fq {
    Fq::from_raw_unchecked([n, 0, 0, 0, 0, 0])
}

pub fn fq2_is_zero(
    f: &AssignedFq2<Fq, Fr>,
    ctx: &mut GeneralScalarEccContext<G1Affine, Fr>,
) -> AssignedCondition<Fr> {
    let c0_zero = ctx.base_integer_chip().is_int_zero(&f.0);
    let c1_zero = ctx.base_integer_chip().is_int_zero(&f.1);

    ctx.native_ctx.as_ref().borrow_mut().and(&c0_zero, &c1_zero)
}

pub fn fq2_bisec(
    cond: &AssignedCondition<Fr>,
    a: &AssignedFq2<Fq, Fr>,
    b: &AssignedFq2<Fq, Fr>,
    ctx: &mut GeneralScalarEccContext<G1Affine, Fr>,
) -> AssignedFq2<Fq, Fr> {
    let c0 = ctx.base_integer_chip().bisec_int(cond, &a.0, &b.0);
    let c1 = ctx.base_integer_chip().bisec_int(cond, &a.1, &b.1);

    AssignedFq2::from((c0, c1))
}

pub fn assigned_fq2_to_value(u: &AssignedFq2<Fq, Fr>) -> Fp2 {
    let c0 = {
        let ls =
            u.0.limbs_le
                .iter()
                .map(|v| v.val.get_lower_128())
                .collect_vec();
        let bn = limbs_to_biguint::<108>(ls);
        bn_to_field::<Fq>(&bn)
    };

    let c1 = {
        let ls =
            u.1.limbs_le
                .iter()
                .map(|v| v.val.get_lower_128())
                .collect_vec();
        let bn = limbs_to_biguint::<108>(ls);
        bn_to_field::<Fq>(&bn)
    };

    Fp2 { c0, c1 }
}

pub fn assign_fq2(u: &Fp2, ctx: &mut GeneralScalarEccContext<G1Affine, Fr>) -> AssignedFq2<Fq, Fr> {
    AssignedFq2::from((
        ctx.base_integer_chip().assign_w(&field_to_bn(&u.c0)),
        ctx.base_integer_chip().assign_w(&field_to_bn(&u.c1)),
    ))
}

pub fn is_fq2_sgn0(
    u: &AssignedFq2<Fq, Fr>,
    ctx: &mut GeneralScalarEccContext<G1Affine, Fr>,
) -> AssignedCondition<Fr> {
    let t = assigned_fq2_to_value(&u);
    let is_odd = if t.c0.is_zero().unwrap_u8() == 1 {
        t.c1.to_bytes()[47] & 1 == 1
    } else {
        t.c0.to_bytes()[47] & 1 == 1
    };

    ctx.base_integer_chip()
        .base_chip()
        .assign_bit(Fr::from(!is_odd))
}

// fn is_fq_sgn0(
//     u: &AssignedFq<Fq, Fr>,
//     ctx: &mut GeneralScalarEccContext<G1Affine, Fr>
// ) -> AssignedCondition<Fr> {
//     let ctx = ctx.base_integer_chip().base_chip();
//     ctx.ass
// }

pub fn limbs_to_biguint<const N: usize>(ls: Vec<u128>) -> BigUint {
    let mut modx = BigUint::one();
    for i in 0..N {
        modx = modx.mul(2u32)
    }
    let mut x = BigUint::zero();

    for i in (0..ls.len()).rev() {
        x = x * modx.clone() + BigUint::from(ls[i])
    }

    x
}

pub fn biguint_to_limbs<const K: usize, const N: usize>(x: BigUint) -> [u128; K] {
    let mut modx = BigUint::one();
    for i in 0..N {
        modx = modx.mul(2u32)
    }
    let mut res = [0; K];
    let mut temp = x.clone();
    for i in 0..K {
        res[i] = (temp.clone() % modx.clone()).to_u128().unwrap();
        temp = temp.clone() / modx.clone();
    }

    res
}

pub fn fq2_conjugate(
    u: &AssignedFq2<Fq, Fr>,
    ctx: &mut GeneralScalarEccContext<G1Affine, Fr>,
) -> AssignedFq2<Fq, Fr> {
    let c0 = u.0.clone();
    let c1 = ctx.base_integer_chip().int_neg(&u.1);

    AssignedFq2::from((c0, c1))
}

pub fn assign_g2(
    point: &G2Affine,
    ctx: &mut GeneralScalarEccContext<G1Affine, Fr>,
) -> AssignedG2Affine<G1Affine, Fr> {
    let x = AssignedFq2::from((
        ctx.base_integer_chip().assign_w(&field_to_bn(&point.x.c0)),
        ctx.base_integer_chip().assign_w(&field_to_bn(&point.x.c1)),
    ));

    let y = AssignedFq2::from((
        ctx.base_integer_chip().assign_w(&field_to_bn(&point.y.c0)),
        ctx.base_integer_chip().assign_w(&field_to_bn(&point.y.c1)),
    ));

    AssignedG2Affine::new(
        x,
        y,
        AssignedCondition(
            ctx.base_integer_ctx
                .ctx
                .borrow_mut()
                .assign_constant(Fr::zero()),
        ),
    )
}

pub fn g2affine_bisec(
    cond: &AssignedCondition<Fr>,
    a: &AssignedG2Affine<G1Affine, Fr>,
    b: &AssignedG2Affine<G1Affine, Fr>,
    ctx: &mut GeneralScalarEccContext<G1Affine, Fr>,
) -> AssignedG2Affine<G1Affine, Fr> {
    let x = fq2_bisec(cond, &a.x, &b.x, ctx);
    let y = fq2_bisec(cond, &a.y, &b.y, ctx);
    let z = ctx
        .base_integer_chip()
        .base_chip()
        .bisec_cond(cond, &a.z, &b.z);

    AssignedG2Affine::new(x, y, z)
}

pub fn g2_bisec(
    cond: &AssignedCondition<Fr>,
    a: &AssignedG2<G1Affine, Fr>,
    b: &AssignedG2<G1Affine, Fr>,
    ctx: &mut GeneralScalarEccContext<G1Affine, Fr>,
) -> AssignedG2<G1Affine, Fr> {
    let x = fq2_bisec(cond, &a.x, &b.x, ctx);
    let y = fq2_bisec(cond, &a.y, &b.y, ctx);
    let z = fq2_bisec(cond, &a.z, &b.z, ctx);

    AssignedG2::new(x, y, z)
}

pub fn g2affine_add(
    a: &AssignedG2Affine<G1Affine, Fr>,
    b: &AssignedG2Affine<G1Affine, Fr>,
    ctx: &mut GeneralScalarEccContext<G1Affine, Fr>,
) -> AssignedG2Affine<G1Affine, Fr> {
    let diff_x = ctx.fq2_sub(&a.x, &b.x);
    let diff_y = ctx.fq2_sub(&a.y, &b.y);
    let lambda = {
        let dx_inv = ctx.fq2_unsafe_invert(&diff_x);
        ctx.fq2_mul(&diff_y, &dx_inv)
    };

    //  x_3 = lambda^2 - x_1 - x_2 (mod p)
    let lambda_sq = ctx.fq2_square(&lambda);
    let lambda_sq_minus_ax = ctx.fq2_sub(&lambda_sq, &a.x);
    let x_3 = ctx.fq2_sub(&lambda_sq_minus_ax, &b.x);

    //  y_3 = lambda (x_1 - x_3) - y_1 mod p
    let dx_13 = ctx.fq2_sub(&a.x, &x_3);
    let lambda_dx_13 = ctx.fq2_mul(&lambda, &dx_13);
    let y_3 = ctx.fq2_sub(&lambda_dx_13, &a.y);

    AssignedG2Affine::new(x_3, y_3, a.z)
}

pub fn g2_add(
    a: &AssignedG2<G1Affine, Fr>,
    b: &AssignedG2<G1Affine, Fr>,
    ctx: &mut GeneralScalarEccContext<G1Affine, Fr>,
) -> AssignedG2<G1Affine, Fr> {
    if assigned_fq2_to_value(&a.z).is_zero().unwrap_u8() == 1 {
        return AssignedG2::new(b.x.clone(), b.y.clone(), b.z.clone());
    }
    // println!("a.z={:?}", assigned_fq2_to_value(&a.z).is_zero());
    // println!("b.z={:?}", assigned_fq2_to_value(&b.z));
    //if (a.z.isZero()) return b;
    // if (b.isZero()) return a;
    let x1 = a.x.clone();
    let y1 = a.y.clone();
    let z1 = a.z.clone();
    let x2 = b.x.clone();
    let y2 = b.y.clone();
    let z2 = b.z.clone();
    let u1 = ctx.fq2_mul(&y2, &z1);
    let u2 = ctx.fq2_mul(&y1, &z2);
    let v = ctx.fq2_mul(&x2, &z1); // x2.multiply(z1);
    let v2 = ctx.fq2_mul(&x1, &z2); // x1.multiply(z2);
                                    // if assigned_fq2_to_value(&v).eq(&assigned_fq2_to_value(&v2)) && assigned_fq2_to_value(&u1).eq(&assigned_fq2_to_value(&u2)) {
                                    //     println!("V1.equals(V2) && U1.equals(U2)");
                                    //     return g2_double(&a, ctx)
                                    // }
                                    // if (v.equals(v2)) return this.getZero();
    let u = ctx.fq2_sub(&u1, &u2); // u1.subtract(u2);
    let v = ctx.fq2_sub(&v, &v2); // v.subtract(v2);
    let vv = ctx.fq2_mul(&v, &v); // v.multiply(v);
    let vvv = ctx.fq2_mul(&vv, &v); // vv.multiply(v);
    let v2vv = ctx.fq2_mul(&v2, &vv); // v2.multiply(vv);
    let w = ctx.fq2_mul(&z1, &z2); // z1.multiply(z2);
    let A = {
        let t = ctx.fq2_mul(&u, &u);
        let t = ctx.fq2_mul(&t, &w);
        let t = ctx.fq2_sub(&t, &vvv);
        let t2 = fq2_mul_constant(&v2vv, 2, ctx);
        ctx.fq2_sub(&t, &t2)
    };

    let x3 = ctx.fq2_mul(&v, &A); // V.multiply(A);
    let y3 = {
        let t = ctx.fq2_sub(&v2vv, &A);
        let t = ctx.fq2_mul(&u, &t);
        let t2 = ctx.fq2_mul(&vvv, &u2);
        ctx.fq2_sub(&t, &t2)
    };
    let z3 = ctx.fq2_mul(&vvv, &w); // VVV.multiply(w);
    AssignedG2::new(x3, y3, z3)
}

pub fn fq2_mul_constant(
    u: &AssignedFq2<Fq, Fr>,
    c: u64,
    ctx: &mut GeneralScalarEccContext<G1Affine, Fr>,
) -> AssignedFq2<Fq, Fr> {
    let c0 = ctx.base_integer_chip().int_mul_small_constant(&u.0, c);
    let c1 = ctx.base_integer_chip().int_mul_small_constant(&u.1, c);

    AssignedFq2::from((c0, c1))
}

pub fn g2_sub(
    a: &AssignedG2Affine<G1Affine, Fr>,
    b: &AssignedG2Affine<G1Affine, Fr>,
    ctx: &mut GeneralScalarEccContext<G1Affine, Fr>,
) -> AssignedG2Affine<G1Affine, Fr> {
    let b_neg = ctx.g2_neg(&b);
    g2affine_add(&a, &b_neg, ctx)
}

pub fn g2_double(
    p: &AssignedG2<G1Affine, Fr>,
    ctx: &mut GeneralScalarEccContext<G1Affine, Fr>,
) -> AssignedG2<G1Affine, Fr> {
    //let p = ctx.g2affine_to_g2(p);
    let w = {
        let t = ctx.fq2_mul(&p.x, &p.x);
        fq2_mul_constant(&t, 3, ctx)
    };
    let s = ctx.fq2_mul(&p.y, &p.z);
    let ss = ctx.fq2_mul(&s, &s);
    let sss = ctx.fq2_mul(&ss, &s);
    let b = {
        let t = ctx.fq2_mul(&p.x, &p.y);
        ctx.fq2_mul(&t, &s)
    };
    let h = {
        let t = ctx.fq2_mul(&w, &w);
        let t2 = fq2_mul_constant(&b, 8, ctx);
        ctx.fq2_sub(&t, &t2)
    };
    let x3 = {
        let t = ctx.fq2_mul(&h, &s);
        fq2_mul_constant(&t, 2, ctx)
    };
    let y3 = {
        let t = fq2_mul_constant(&b, 4, ctx);
        let t = ctx.fq2_sub(&t, &h);
        let t = ctx.fq2_mul(&w, &t);
        let t2 = ctx.fq2_mul(&p.y, &p.y);
        let t2 = fq2_mul_constant(&t2, 8, ctx);
        let t2 = ctx.fq2_mul(&t2, &ss);
        ctx.fq2_sub(&t, &t2)
    };
    let z3 = fq2_mul_constant(&sss, 8, ctx);
    AssignedG2::new(x3, y3, z3)
}

pub fn g2_mul_x(
    p: &AssignedG2<G1Affine, Fr>,
    mut x: u64,
    ctx: &mut GeneralScalarEccContext<G1Affine, Fr>,
) -> AssignedG2<G1Affine, Fr> {
    let mut acc = {
        let x = ctx.fq2_assign_zero();
        let y = ctx.fq2_assign_one();
        let z = ctx.fq2_assign_zero();
        AssignedG2::new(x, y, z)
    };
    // let mut acc = assign_g2(ctx, G2Affine::identity());
    let mut double = AssignedG2::new(p.x.clone(), p.y.clone(), p.z.clone());

    let mut bits = vec![];
    let mut i = 0;
    while x > 0 {
        bits.push(if x % 2 == 1 { 1 } else { 0 });
        let bit = ctx
            .base_integer_chip()
            .base_chip()
            .assign_bit(Fr::from((x % 2 == 1) as u64));
        let acc_d = g2_add(&acc, &double, ctx);
        acc = g2_bisec(&bit, &acc_d, &acc, ctx);
        // println!("[{i}] point {:?} {:?} {:?}", assigned_fq2_to_value(&acc.x), assigned_fq2_to_value(&acc.y), assigned_fq2_to_value(&acc.z));

        double = g2_double(&double, ctx);
        // println!("[{i}] double {:?} {:?} {:?}", assigned_fq2_to_value(&double.x), assigned_fq2_to_value(&double.y), assigned_fq2_to_value(&double.z));

        x >>= 1;
        i += 1;
    }

    acc
}

pub fn g2_to_affine(
    p: &AssignedG2<G1Affine, Fr>,
    ctx: &mut GeneralScalarEccContext<G1Affine, Fr>,
) -> AssignedG2Affine<G1Affine, Fr> {
    let z_inv = ctx.fq2_unsafe_invert(&p.z);
    let x = ctx.fq2_mul(&p.x, &z_inv);
    let y = ctx.fq2_mul(&p.y, &z_inv);
    let z = ctx.base_integer_chip().base_chip().assign_bit(Fr::zero());
    AssignedG2Affine::new(x, y, z)
}

pub fn g2_neg(
    p: &AssignedG2<G1Affine, Fr>,
    ctx: &mut GeneralScalarEccContext<G1Affine, Fr>,
) -> AssignedG2<G1Affine, Fr> {
    let y = ctx.fq2_neg(&p.y);
    AssignedG2::new(p.x.clone(), y, p.z.clone())
}

pub fn g2_psi(
    p: &AssignedG2<G1Affine, Fr>,
    ctx: &mut GeneralScalarEccContext<G1Affine, Fr>,
) -> AssignedG2<G1Affine, Fr> {
    // 1 / ((u+1) ^ ((q-1)/3))
    let psi_coeff_x = assign_fq2(
        &Fp2 {
            c0: Fq::zero(),
            c1: Fq::from_raw_unchecked([
                0x890dc9e4867545c3,
                0x2af322533285a5d5,
                0x50880866309b7e2c,
                0xa20d1b8c7e881024,
                0x14e4f04fe2db9068,
                0x14e56d3f1564853a,
            ]),
        },
        ctx,
    );
    // 1 / ((u+1) ^ (p-1)/2)
    let psi_coeff_y = assign_fq2(
        &Fp2 {
            c0: Fq::from_raw_unchecked([
                0x3e2f585da55c9ad1,
                0x4294213d86c18183,
                0x382844c88b623732,
                0x92ad2afd19103e18,
                0x1d794e4fac7cf0b9,
                0x0bd592fc7d825ec8,
            ]),
            c1: Fq::from_raw_unchecked([
                0x7bcfa7a25aa30fda,
                0xdc17dec12a927e7c,
                0x2f088dd86b4ebef1,
                0xd1ca2087da74d4a7,
                0x2da2596696cebc1d,
                0x0e2b7eedbbfd87d2,
            ]),
        },
        ctx,
    );

    let x_frob = fq2_conjugate(&p.x, ctx);
    let y_frob = fq2_conjugate(&p.y, ctx);

    let x = ctx.fq2_mul(&x_frob, &psi_coeff_x);
    let y = ctx.fq2_mul(&y_frob, &psi_coeff_y);
    let z = fq2_conjugate(&p.z, ctx);

    AssignedG2::new(x, y, z)
}

pub fn g2affine_double(
    p: &AssignedG2Affine<G1Affine, Fr>,
    ctx: &mut GeneralScalarEccContext<G1Affine, Fr>,
) -> AssignedG2Affine<G1Affine, Fr> {
    let two_y = fq2_mul_constant(&p.y, 2, ctx);
    let three_x = fq2_mul_constant(&p.x, 3, ctx);
    let three_x_sq = ctx.fq2_mul(&three_x, &p.x);
    let lambda = {
        let tho_y_neg = ctx.fq2_neg(&two_y);
        ctx.fq2_mul(&three_x_sq, &tho_y_neg)
    };

    let lambda_sq = ctx.fq2_square(&lambda);
    let two_x = fq2_mul_constant(&p.x, 2, ctx);
    let x_3 = ctx.fq2_sub(&lambda_sq, &two_x);

    let dx = ctx.fq2_sub(&p.x, &x_3);
    let lambda_dx = ctx.fq2_mul(&lambda, &dx);
    let y_3 = ctx.fq2_sub(&lambda_dx, &p.y);

    AssignedG2Affine::new(x_3, y_3, p.z)
}

pub fn g2_psi2(
    p: &AssignedG2Affine<G1Affine, Fr>,
    ctx: &mut GeneralScalarEccContext<G1Affine, Fr>,
) -> AssignedG2Affine<G1Affine, Fr> {
    // 1 / 2 ^ ((q-1)/3)
    let psi2_coeff_x = assign_fq2(
        &Fp2 {
            c0: Fq::from_raw_unchecked([
                0xcd03c9e48671f071,
                0x5dab22461fcda5d2,
                0x587042afd3851b95,
                0x8eb60ebe01bacb9e,
                0x03f97d6e83d050d2,
                0x18f0206554638741,
            ]),
            c1: Fq::zero(),
        },
        ctx,
    );

    let x = ctx.fq2_mul(&p.x, &psi2_coeff_x);
    let y = ctx.fq2_neg(&p.y);

    AssignedG2Affine::new(x, y, p.z)
}

pub fn get_scalar_integer_chip(
    ctx: &mut GeneralScalarEccContext<G1Affine, Fr>,
) -> &mut dyn IntegerChipOps<pairing::bls12_381::Fr, Fr> {
    &mut ctx.scalar_integer_ctx
}

macro_rules! square {
    ($var:expr, $n:expr) => {
        for _ in 0..$n {
            $var = $var.square();
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_gadgets::sha256::Table16Config;
    use halo2_proofs::{
        arithmetic::FieldExt,
        circuit::{Layouter, SimpleFloorPlanner},
        dev::MockProver,
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error},
    };
    use halo2ecc_s::context::Context;
    use sha2::Digest;
    use std::cell::RefCell;
    use std::ops::Add;
    use std::ptr::hash;
    use std::rc::Rc;
    use subtle::Choice;

    const TEST_FP2: Fp2 = Fp2 {
        c0: Fq::from_raw_unchecked([
            0x22ea_0000_0cf8_9db2,
            0x6ec8_32df_7138_0aa4,
            0x6e1b_9440_3db5_a66e,
            0x75bf_3c53_a794_73ba,
            0x3dd3_a569_412c_0a34,
            0x125c_db5e_74dc_4fd1,
        ]),
        c1: Fq::from_raw_unchecked([
            0x22ea_0000_0cf8_9db2,
            0x6ec8_32df_7138_0aa4,
            0x6e1b_9440_3db5_a66e,
            0x75bf_3c53_a794_73ba,
            0x3dd3_a569_412c_0a34,
            0x125c_db5e_74dc_4fd1,
        ]),
    };

    #[test]
    fn test_assigned_to_value() {
        let ctx = Rc::new(RefCell::new(Context::new()));
        let mut ctx = GeneralScalarEccContext::<G1Affine, Fr>::new(ctx);

        let assigned = ctx.fq2_assign_constant((TEST_FP2.c0, TEST_FP2.c1));

        let value = assigned_fq2_to_value(&assigned);

        assert_eq!(value, TEST_FP2);
    }

    #[test]
    fn test_fq2_arith() {
        let ctx = Rc::new(RefCell::new(Context::new()));
        let mut ctx = GeneralScalarEccContext::<G1Affine, Fr>::new(ctx);

        // let assigned = ctx.fq2_assign_constant((TEST_FP2.c0, TEST_FP2.c1));

        let c0 = Fq::from_bytes(&[
            12, 137, 217, 106, 50, 146, 136, 72, 133, 56, 121, 4, 216, 99, 109, 128, 49, 215, 124,
            34, 251, 129, 104, 217, 220, 87, 231, 148, 186, 48, 86, 200, 108, 237, 107, 183, 139,
            168, 147, 15, 178, 126, 52, 33, 108, 202, 209, 100,
        ])
        .unwrap();
        let c1 = Fq::from_bytes(&[
            17, 102, 56, 112, 107, 137, 145, 242, 44, 78, 37, 49, 225, 173, 27, 21, 207, 89, 0,
            130, 77, 194, 134, 9, 38, 84, 62, 104, 4, 145, 55, 209, 95, 235, 179, 78, 44, 167, 249,
            168, 32, 33, 224, 187, 18, 226, 238, 50,
        ])
        .unwrap();
        let u = Fp2 { c0, c1 };
        let assigned = ctx.fq2_assign_constant((u.c0, u.c1));
        println!("u={:?}", assigned_fq2_to_value(&assigned));

        let asq = ctx.fq2_square(&assigned);

        let value = assigned_fq2_to_value(&asq);

        println!("{:?}\n{:?}", value, u.square());

        assert_eq!(value, u.square());
    }
}

// from https://github.com/mikelodder7/bls12_381_plus/blob/main/src/hash_to_curve/chain.rs#L328
#[allow(clippy::cognitive_complexity)]
/// addchain for 1001205140483106588246484290269935788605945006208159541241399033561623546780709821462541004956387089373434649096260670658193992783731681621012512651314777238193313314641988297376025498093520728838658813979860931248214124593092835
/// Bos-Coster (win=4) : 895 links, 17 variables
/// Addition chain implementing exponentiation by (p**2 - 9) // 16.
pub fn chain_p2m9div16(var0: &Fp2) -> Fp2 {
    let mut var1 = var0.square();
    //Self::sqr(var1, var0);                              /*    0 : 2 */
    let var2 = var1 * var0;
    //Self::mul(&mut var2, var1, var0);                /*    1 : 3 */
    let var15 = var2 * var1;
    //Self::mul(&mut var15, &var2, var1);              /*    2 : 5 */
    let var3 = var15 * var1;
    //Self::mul(&mut var3, &var15, var1);              /*    3 : 7 */
    let var14 = var3 * var1;
    //Self::mul(&mut var14, &var3, var1);              /*    4 : 9 */
    let var13 = var14 * var1;
    //Self::mul(&mut var13, &var14, var1);             /*    5 : 11 */
    let var5 = var13 * var1;
    //Self::mul(&mut var5, &var13, var1);              /*    6 : 13 */
    let var10 = var5 * var1;
    //Self::mul(&mut var10, &var5, var1);              /*    7 : 15 */
    let var9 = var10 * var1;
    //Self::mul(&mut var9, &var10, var1);              /*    8 : 17 */
    let var16 = var9 * var1;
    //Self::mul(&mut var16, &var9, var1);              /*    9 : 19 */
    let var4 = var16 * var1;
    //Self::mul(&mut var4, &var16, var1);              /*   10 : 21 */
    let var7 = var4 * var1;
    //Self::mul(&mut var7, &var4, var1);               /*   11 : 23 */
    let var6 = var7 * var1;
    //Self::mul(&mut var6, &var7, var1);               /*   12 : 25 */
    let var12 = var6 * var1;
    //Self::mul(&mut var12, &var6, var1);              /*   13 : 27 */
    let var8 = var12 * var1;
    //Self::mul(&mut var8, &var12, var1);              /*   14 : 29 */
    let var11 = var8 * var1;
    //Self::mul(&mut var11, &var8, var1);              /*   15 : 31 */
    var1 = var4.square();
    //Self::sqr(var1, &var4);                             /*   16 : 42 */
    //   17 : 168
    square!(var1, 2);
    //   19 : 169
    var1.mul_assign(var0);
    //   20 : 86528
    square!(var1, 9);
    //   29 : 86555
    var1.mul_assign(&var12);
    //   30 : 1384880
    square!(var1, 4);
    //   34 : 1384893
    var1.mul_assign(&var5);
    //   35 : 88633152
    square!(var1, 6);
    //   41 : 88633161
    var1.mul_assign(&var14);
    //   42 : 1418130576
    square!(var1, 4);
    //   46 : 1418130583
    var1.mul_assign(&var3);
    //   47 : 45380178656
    square!(var1, 5);
    //   52 : 45380178659
    var1.mul_assign(&var2);
    //   53 : 11617325736704
    square!(var1, 8);
    //   61 : 11617325736717
    var1.mul_assign(&var5);
    //   62 : 185877211787472
    square!(var1, 4);
    //   66 : 185877211787479
    var1.mul_assign(&var3);
    //   67 : 2974035388599664
    square!(var1, 4);
    //   71 : 2974035388599679
    var1.mul_assign(&var10);
    //   72 : 761353059481517824
    square!(var1, 8);
    //   80 : 761353059481517853
    var1.mul_assign(&var8);
    //   81 : 48726595806817142592
    square!(var1, 6);
    //   87 : 48726595806817142603
    var1.mul_assign(&var13);
    //   88 : 779625532909074281648
    square!(var1, 4);
    //   92 : 779625532909074281661
    var1.mul_assign(&var5);
    //   93 : 6237004263272594253288
    square!(var1, 3);
    //   96 : 6237004263272594253289
    var1.mul_assign(var0);
    //   97 : 399168272849446032210496
    square!(var1, 6);
    //  103 : 399168272849446032210511
    var1.mul_assign(&var10);
    //  104 : 102187077849458184245890816
    square!(var1, 8);
    //  112 : 102187077849458184245890845
    var1.mul_assign(&var8);
    //  113 : 6539972982365323791737014080
    square!(var1, 6);
    //  119 : 6539972982365323791737014101
    var1.mul_assign(&var4);
    //  120 : 1674233083485522890684675609856
    square!(var1, 8);
    //  128 : 1674233083485522890684675609873
    var1.mul_assign(&var9);
    //  129 : 53575458671536732501909619515936
    square!(var1, 5);
    //  134 : 53575458671536732501909619515951
    var1.mul_assign(&var10);
    //  135 : 3428829354978350880122215649020864
    square!(var1, 6);
    //  141 : 3428829354978350880122215649020873
    var1.mul_assign(&var14);
    //  142 : 109722539359307228163910900768667936
    square!(var1, 5);
    //  147 : 109722539359307228163910900768667951
    var1.mul_assign(&var10);
    //  148 : 438890157437228912655643603074671804
    square!(var1, 2);
    //  150 : 438890157437228912655643603074671805
    var1.mul_assign(var0);
    //  151 : 28088970075982650409961190596778995520
    square!(var1, 6);
    //  157 : 28088970075982650409961190596778995535
    var1.mul_assign(&var10);
    //  158 : 3595388169725779252475032396387711428480
    square!(var1, 7);
    //  165 : 3595388169725779252475032396387711428491
    var1.mul_assign(&var13);
    //  166 : 57526210715612468039600518342203382855856
    square!(var1, 4);
    //  170 : 57526210715612468039600518342203382855863
    var1.mul_assign(&var3);
    //  171 : 3681677485799197954534433173901016502775232
    square!(var1, 6);
    //  177 : 3681677485799197954534433173901016502775241
    var1.mul_assign(&var14);
    //  178 : 471254718182297338180407446259330112355230848
    square!(var1, 7);
    //  185 : 471254718182297338180407446259330112355230855
    var1.mul_assign(&var3);
    //  186 : 15080150981833514821773038280298563595367387360
    square!(var1, 5);
    //  191 : 15080150981833514821773038280298563595367387365
    var1.mul_assign(&var15);
    //  192 : 1930259325674689897186948899878216140207025582720
    square!(var1, 7);
    //  199 : 1930259325674689897186948899878216140207025582727
    var1.mul_assign(&var3);
    //  200 : 61768298421590076709982364796102916486624818647264
    square!(var1, 5);
    //  205 : 61768298421590076709982364796102916486624818647271
    var1.mul_assign(&var3);
    //  206 : 63250737583708238551021941551209386482303814294805504
    square!(var1, 10);
    //  216 : 63250737583708238551021941551209386482303814294805521
    var1.mul_assign(&var9);
    //  217 : 506005900669665908408175532409675091858430514358444168
    square!(var1, 3);
    //  220 : 506005900669665908408175532409675091858430514358444173
    var1.mul_assign(&var15);
    //  221 : 16192188821429309069061617037109602939469776459470213536
    square!(var1, 5);
    //  226 : 16192188821429309069061617037109602939469776459470213549
    var1.mul_assign(&var5);
    //  227 : 4145200338285903121679773961500058352504262773624374668544
    square!(var1, 8);
    //  235 : 4145200338285903121679773961500058352504262773624374668569
    var1.mul_assign(&var6);
    //  236 : 132646410825148899893752766768001867280136408755979989394208
    square!(var1, 5);
    //  241 : 132646410825148899893752766768001867280136408755979989394231
    var1.mul_assign(&var7);
    //  242 : 8489370292809529593200177073152119505928730160382719321230784
    square!(var1, 6);
    //  248 : 8489370292809529593200177073152119505928730160382719321230795
    var1.mul_assign(&var13);
    //  249 : 543319698739809893964811332681735648379438730264494036558770880
    square!(var1, 6);
    //  255 : 543319698739809893964811332681735648379438730264494036558770895
    var1.mul_assign(&var10);
    //  256 : 34772460719347833213747925291631081496284078736927618339761337280
    square!(var1, 6);
    //  262 : 34772460719347833213747925291631081496284078736927618339761337289
    var1.mul_assign(&var14);
    //  263 : 4450874972076522651359734437328778431524362078326735147489451172992
    square!(var1, 7);
    //  270 : 4450874972076522651359734437328778431524362078326735147489451173011
    var1.mul_assign(&var16);
    //  271 : 142427999106448724843511501994520909808779586506455524719662437536352
    square!(var1, 5);
    //  276 : 142427999106448724843511501994520909808779586506455524719662437536361
    var1.mul_assign(&var14);
    //  277 : 9115391942812718389984736127649338227761893536413153582058396002327104
    square!(var1, 6);
    //  283 : 9115391942812718389984736127649338227761893536413153582058396002327119
    var1.mul_assign(&var10);
    //  284 : 583385084340013976959023112169557646576761186330441829251737344148935616
    square!(var1, 6);
    //  290 : 583385084340013976959023112169557646576761186330441829251737344148935633
    var1.mul_assign(&var9);
    //  291 : 18668322698880447262688739589425844690456357962574138536055595012765940256
    square!(var1, 5);
    //  296 : 18668322698880447262688739589425844690456357962574138536055595012765940271
    var1.mul_assign(&var10);
    //  297 : 74673290795521789050754958357703378761825431850296554144222380051063761084
    square!(var1, 2);
    //  299 : 74673290795521789050754958357703378761825431850296554144222380051063761085
    var1.mul_assign(var0);
    //  300 : 19116362443653577996993269339572064963027310553675917860920929293072322837760
    square!(var1, 8);
    //  308 : 19116362443653577996993269339572064963027310553675917860920929293072322837765
    var1.mul_assign(&var15);
    //  309 : 2446894392787657983615138475465224315267495750870517486197878949513257323233920
    square!(var1, 7);
    //  316 : 2446894392787657983615138475465224315267495750870517486197878949513257323233925
    var1.mul_assign(&var15);
    //  317 : 39150310284602527737842215607443589044279932013928279779166063192212117171742800
    square!(var1, 4);
    //  321 : 39150310284602527737842215607443589044279932013928279779166063192212117171742803
    var1.mul_assign(&var2);
    //  322 : 5011239716429123550443803597752779397667831297782819811733256088603150997983078784
    square!(var1, 7);
    //  329 : 5011239716429123550443803597752779397667831297782819811733256088603150997983078795
    var1.mul_assign(&var13);
    //  330 : 320719341851463907228403430256177881450741203058100467950928389670601663870917042880
    square!(var1, 6);
    //  336 : 320719341851463907228403430256177881450741203058100467950928389670601663870917042895
    var1.mul_assign(&var10);
    //  337 : 5131509469623422515654454884098846103211859248929607487214854234729626621934672686320
    square!(var1, 4);
    //  341 : 5131509469623422515654454884098846103211859248929607487214854234729626621934672686333
    var1.mul_assign(&var5);
    //  342 : 656833212111798082003770225164652301211117983862989758363501342045392207607638103850624
    square!(var1, 7);
    //  349 : 656833212111798082003770225164652301211117983862989758363501342045392207607638103850635
    var1.mul_assign(&var13);
    //  350 : 42037325575155077248241294410537747277511550967231344535264085890905101286888838646440640
    square!(var1, 6);
    //  356 : 42037325575155077248241294410537747277511550967231344535264085890905101286888838646440667
    var1.mul_assign(&var12);
    //  357 : 1345194418404962471943721421137207912880369630951403025128450748508963241180442836686101344
    square!(var1, 5);
    //  362 : 1345194418404962471943721421137207912880369630951403025128450748508963241180442836686101367
    var1.mul_assign(&var7);
    //  363 : 43046221388958799102199085476390653212171828190444896804110423952286823717774170773955243744
    square!(var1, 5);
    //  368 : 43046221388958799102199085476390653212171828190444896804110423952286823717774170773955243749
    var1.mul_assign(&var15);
    //  369 : 5509916337786726285081482940978003611157994008376946790926134265892713435875093859066271199872
    square!(var1, 7);
    //  376 : 5509916337786726285081482940978003611157994008376946790926134265892713435875093859066271199899
    var1.mul_assign(&var12);
    //  377 : 176317322809175241122607454111296115557055808268062297309636296508566829948003003490120678396768
    square!(var1, 5);
    //  382 : 176317322809175241122607454111296115557055808268062297309636296508566829948003003490120678396791
    var1.mul_assign(&var7);
    //  383 : 5642154329893607715923438531561475697825785864577993513908361488274138558336096111683861708697312
    square!(var1, 5);
    //  388 : 5642154329893607715923438531561475697825785864577993513908361488274138558336096111683861708697333
    var1.mul_assign(&var4);
    //  389 : 90274469278297723454775016504983611165212573833247896222533783812386216933377537786941787339157328
    square!(var1, 4);
    //  393 : 90274469278297723454775016504983611165212573833247896222533783812386216933377537786941787339157331
    var1.mul_assign(&var2);
    //  394 : 5777566033811054301105601056318951114573604725327865358242162163992717883736162418364274389706069184
    square!(var1, 6);
    //  400 : 5777566033811054301105601056318951114573604725327865358242162163992717883736162418364274389706069189
    var1.mul_assign(&var15);
    //  401 : 369764226163907475270758467604412871332710702420983382927498378495533944559114394775313560941188428096
    square!(var1, 6);
    //  407 : 369764226163907475270758467604412871332710702420983382927498378495533944559114394775313560941188428105
    var1.mul_assign(&var14);
    //  408 : 5916227618622519604332135481670605941323371238735734126839974055928543112945830316405016975059014849680
    square!(var1, 4);
    //  412 : 5916227618622519604332135481670605941323371238735734126839974055928543112945830316405016975059014849683
    var1.mul_assign(&var2);
    //  413 : 94659641897960313669314167706729695061173939819771746029439584894856689807133285062480271600944237594928
    square!(var1, 4);
    //  417 : 94659641897960313669314167706729695061173939819771746029439584894856689807133285062480271600944237594931
    var1.mul_assign(&var2);
    //  418 : 24232868325877840299344426932922801935660528593861566983536533733083312590626120975994949529841724824302336
    square!(var1, 8);
    //  426 : 24232868325877840299344426932922801935660528593861566983536533733083312590626120975994949529841724824302345
    var1.mul_assign(&var14);
    //  427 : 775451786428090889579021661853529661941136915003570143473169079458666002900035871231838384954935194377675040
    square!(var1, 5);
    //  432 : 775451786428090889579021661853529661941136915003570143473169079458666002900035871231838384954935194377675055
    var1.mul_assign(&var10);
    //  433 : 49628914331397816933057386358625898364232762560228489182282821085354624185602295758837656637115852440171203520
    square!(var1, 6);
    //  439 : 49628914331397816933057386358625898364232762560228489182282821085354624185602295758837656637115852440171203527
    var1.mul_assign(&var3);
    //  440 : 1588125258604730141857836363476028747655448401927311653833050274731347973939273464282805012387707278085478512864
    square!(var1, 5);
    //  445 : 1588125258604730141857836363476028747655448401927311653833050274731347973939273464282805012387707278085478512879
    var1.mul_assign(&var10);
    //  446 : 6504961059244974661049697744797813750396716654294268534100173925299601301255264109702369330740049011038119988752384
    square!(var1, 12);
    //  458 : 6504961059244974661049697744797813750396716654294268534100173925299601301255264109702369330740049011038119988752401
    var1.mul_assign(&var9);
    //  459 : 104079376947919594576795163916765020006347466468708296545602782804793620820084225755237909291840784176609919820038416
    square!(var1, 4);
    //  463 : 104079376947919594576795163916765020006347466468708296545602782804793620820084225755237909291840784176609919820038429
    var1.mul_assign(&var5);
    //  464 : 3330540062333427026457445245336480640203118926998665489459289049753395866242695224167613097338905093651517434241229728
    square!(var1, 5);
    //  469 : 3330540062333427026457445245336480640203118926998665489459289049753395866242695224167613097338905093651517434241229741
    var1.mul_assign(&var5);
    //  470 : 213154563989339329693276495701534760972999611327914591325394499184217335439532494346727238229689925993697115791438703424
    square!(var1, 6);
    //  476 : 213154563989339329693276495701534760972999611327914591325394499184217335439532494346727238229689925993697115791438703427
    var1.mul_assign(&var2);
    //  477 : 109135136762541736802957565799185797618175800999892270758601983582319275745040637105524345973601242108772923285216616154624
    square!(var1, 9);
    //  486 : 109135136762541736802957565799185797618175800999892270758601983582319275745040637105524345973601242108772923285216616154649
    var1.mul_assign(&var6);
    //  487 : 3492324376401335577694642105573945523781625631996552664275263474634216823841300387376779071155239747480733545126931716948768
    square!(var1, 5);
    //  492 : 3492324376401335577694642105573945523781625631996552664275263474634216823841300387376779071155239747480733545126931716948793
    var1.mul_assign(&var6);
    //  493 : 223508760089685476972457094756732513522024040447779370513616862376589876725843224792113860553935343838766946888123629884722752
    square!(var1, 6);
    //  499 : 223508760089685476972457094756732513522024040447779370513616862376589876725843224792113860553935343838766946888123629884722755
    var1.mul_assign(&var2);
    //  500 : 14304560645739870526237254064430880865409538588657879712871479192101752110453966386695287075451862005681084600839912312622256320
    square!(var1, 6);
    //  506 : 14304560645739870526237254064430880865409538588657879712871479192101752110453966386695287075451862005681084600839912312622256323
    var1.mul_assign(&var2);
    //  507 : 7323935050618813709433474080988611003089683757392834412990197346356097080552430789987986982631353346908715315630035104062595237376
    square!(var1, 9);
    //  516 : 7323935050618813709433474080988611003089683757392834412990197346356097080552430789987986982631353346908715315630035104062595237399
    var1.mul_assign(&var7);
    //  517 : 937463686479208154807484682366542208395479520946282804862745260333580426310711141118462333776813228404315560400644493320012190387072
    square!(var1, 7);
    //  524 : 937463686479208154807484682366542208395479520946282804862745260333580426310711141118462333776813228404315560400644493320012190387087
    var1.mul_assign(&var10);
    //  525 : 59997675934669321907679019671458701337310689340562099511215696661349147283885513031581589361716046617876195865641247572480780184773568
    square!(var1, 6);
    //  531 : 59997675934669321907679019671458701337310689340562099511215696661349147283885513031581589361716046617876195865641247572480780184773593
    var1.mul_assign(&var6);
    //  532 : 1919925629909418301045728629486678442793942058897987184358902293163172713084336417010610859574913491772038267700519922319384965912754976
    square!(var1, 5);
    //  537 : 1919925629909418301045728629486678442793942058897987184358902293163172713084336417010610859574913491772038267700519922319384965912754985
    var1.mul_assign(&var14);
    //  538 : 245750480628405542533853264574294840677624583538942359597939493524886107274795061377358190025588926946820898265666550056881275636832638080
    square!(var1, 7);
    //  545 : 245750480628405542533853264574294840677624583538942359597939493524886107274795061377358190025588926946820898265666550056881275636832638103
    var1.mul_assign(&var7);
    //  546 : 983001922513622170135413058297179362710498334155769438391757974099544429099180245509432760102355707787283593062666200227525102547330552412
    square!(var1, 2);
    //  548 : 983001922513622170135413058297179362710498334155769438391757974099544429099180245509432760102355707787283593062666200227525102547330552413
    var1.mul_assign(var0);
    //  549 : 251648492163487275554665742924077916853887573543876976228290041369483373849390142850414786586203061193544599824042547258246426252116621417728
    square!(var1, 8);
    //  557 : 251648492163487275554665742924077916853887573543876976228290041369483373849390142850414786586203061193544599824042547258246426252116621417739
    var1.mul_assign(&var13);
    //  558 : 4026375874615796408874651886785246669662201176702031619652640661911733981590242285606636585379248979096713597184680756131942820033865942683824
    square!(var1, 4);
    //  562 : 4026375874615796408874651886785246669662201176702031619652640661911733981590242285606636585379248979096713597184680756131942820033865942683829
    var1.mul_assign(&var15);
    //  563 : 515376111950821940335955441508511573716761750617860047315538004724701949643551012557649482928543869324379340439639136784888680964334840663530112
    square!(var1, 7);
    //  570 : 515376111950821940335955441508511573716761750617860047315538004724701949643551012557649482928543869324379340439639136784888680964334840663530119
    var1.mul_assign(&var3);
    //  571 : 131936284659410416726004593026178962871491008158172172112777729209523699108749059214758267629707230547041111152547619016931502326869719209863710464
    square!(var1, 8);
    //  579 : 131936284659410416726004593026178962871491008158172172112777729209523699108749059214758267629707230547041111152547619016931502326869719209863710473
    var1.mul_assign(&var14);
    //  580 : 16887844436404533340928587907350907247550849044246038030435549338819033485919879579489058256602525510021262227526095234167232297839324058862554940544
    square!(var1, 7);
    //  587 : 16887844436404533340928587907350907247550849044246038030435549338819033485919879579489058256602525510021262227526095234167232297839324058862554940557
    var1.mul_assign(&var5);
    //  588 : 17293152702878242141110874017127329021492069421307942943166002522950690289581956689396795654760986122261772520986721519787245872987467836275256259130368
    square!(var1, 10);
    //  598 : 17293152702878242141110874017127329021492069421307942943166002522950690289581956689396795654760986122261772520986721519787245872987467836275256259130377
    var1.mul_assign(&var14);
    //  599 : 1106761772984207497031095937096149057375492442963708348362624161468844178533245228121394921904703111824753441343150177266383735871197941521616400584344128
    square!(var1, 6);
    //  605 : 1106761772984207497031095937096149057375492442963708348362624161468844178533245228121394921904703111824753441343150177266383735871197941521616400584344139
    var1.mul_assign(&var13);
    //  606 : 70832753470989279809990139974153539672031516349677334295207946334006027426127694599769275001900999156784220245961611345048559095756668257383449637398024896
    square!(var1, 6);
    //  612 : 70832753470989279809990139974153539672031516349677334295207946334006027426127694599769275001900999156784220245961611345048559095756668257383449637398024909
    var1.mul_assign(&var5);
    //  613 : 4533296222143313907839368958345826539010017046379349394893308565376385755272172454385233600121663946034190095741543126083107782128426768472540776793473594176
    square!(var1, 6);
    //  619 : 4533296222143313907839368958345826539010017046379349394893308565376385755272172454385233600121663946034190095741543126083107782128426768472540776793473594207
    var1.mul_assign(&var11);
    //  620 : 145065479108586045050859806667066449248320545484139180636585874092044344168709518540327475203893246273094083063729380034659449028109656591121304857391155014624
    square!(var1, 5);
    //  625 : 145065479108586045050859806667066449248320545484139180636585874092044344168709518540327475203893246273094083063729380034659449028109656591121304857391155014649
    var1.mul_assign(&var6);
    //  626 : 18568381325899013766510055253384505503785029821969815121482991883781676053594818373161916826098335522956042632157360644436409475598036043663527021746067841875072
    square!(var1, 7);
    //  633 : 18568381325899013766510055253384505503785029821969815121482991883781676053594818373161916826098335522956042632157360644436409475598036043663527021746067841875087
    var1.mul_assign(&var10);
    //  634 : 594188202428768440528321768108304176121120954303034083887455740281013633715034187941181338435146736734593364229035540621965103219137153397232864695874170940002784
    square!(var1, 5);
    //  639 : 594188202428768440528321768108304176121120954303034083887455740281013633715034187941181338435146736734593364229035540621965103219137153397232864695874170940002797
    var1.mul_assign(&var5);
    //  640 : 76056089910882360387625186317862934543503482150788362737594334755969745115524376056471211319698782302027950621316549199611533212049555634845806681071893880320358016
    square!(var1, 7);
    //  647 : 76056089910882360387625186317862934543503482150788362737594334755969745115524376056471211319698782302027950621316549199611533212049555634845806681071893880320358047
    var1.mul_assign(&var11);
    //  648 : 2433794877148235532404005962171613905392111428825227607603018712191031843696780033807078762230361033664894419882129574387569062785585780315065813794300604170251457504
    square!(var1, 5);
    //  653 : 2433794877148235532404005962171613905392111428825227607603018712191031843696780033807078762230361033664894419882129574387569062785585780315065813794300604170251457511
    var1.mul_assign(&var3);
    //  654 : 623051488549948296295425526315933159780380525779258267546372790320904151986375688654612163130972424618212971489825171043217680073109959760656848331340954667584373122816
    square!(var1, 8);
    //  662 : 623051488549948296295425526315933159780380525779258267546372790320904151986375688654612163130972424618212971489825171043217680073109959760656848331340954667584373122843
    var1.mul_assign(&var12);
    //  663 : 39875295267196690962907233684219722225944353649872529122967858580537865727128044073895178440382235175565630175348810946765931524679037424682038293205821098725399879861952
    square!(var1, 6);
    //  669 : 39875295267196690962907233684219722225944353649872529122967858580537865727128044073895178440382235175565630175348810946765931524679037424682038293205821098725399879861981
    var1.mul_assign(&var8);
    //  670 : 2552018897100588221626062955790062222460438633591841863869942949154423406536194820729291420184463051236200331222323900593019617579458395179650450765172550318425592311166784
    square!(var1, 6);
    //  676 : 2552018897100588221626062955790062222460438633591841863869942949154423406536194820729291420184463051236200331222323900593019617579458395179650450765172550318425592311166787
    var1.mul_assign(&var2);
    //  677 : 326658418828875292368136058341127964474936145099755758575352697491766196036632937053349301783611270558233642396457459275906511050170674582995257697942086440758475815829348736
    square!(var1, 7);
    //  684 : 326658418828875292368136058341127964474936145099755758575352697491766196036632937053349301783611270558233642396457459275906511050170674582995257697942086440758475815829348747
    var1.mul_assign(&var13);
    //  685 : 41812277610096037423121415467664379452791826572768737097645145278946073092689015942828710628302242631453906226746554787316033414421846346623392985336587064417084904426156639616
    square!(var1, 7);
    //  692 : 41812277610096037423121415467664379452791826572768737097645145278946073092689015942828710628302242631453906226746554787316033414421846346623392985336587064417084904426156639627
    var1.mul_assign(&var13);
    //  693 : 2675985767046146395079770589930520284978676900657199174249289297852548677932097020341037480211343528413049998511779506388226138522998166183897151061541572122693433883274024936128
    square!(var1, 6);
    //  699 : 2675985767046146395079770589930520284978676900657199174249289297852548677932097020341037480211343528413049998511779506388226138522998166183897151061541572122693433883274024936131
    var1.mul_assign(&var2);
    //  700 : 85631544545476684642552658877776649119317660821030373575977257531281557693827104650913199366762992909217599952376944204423236432735941317884708833969330307926189884264768797956192
    square!(var1, 5);
    //  705 : 85631544545476684642552658877776649119317660821030373575977257531281557693827104650913199366762992909217599952376944204423236432735941317884708833969330307926189884264768797956199
    var1.mul_assign(&var3);
    //  706 : 87686701614568125073973922690843288698181284680735102541800711712032315078478955162535116151565304739038822351233990865329394107121603909513941845984594235316418441487123249107147776
    square!(var1, 10);
    //  716 : 87686701614568125073973922690843288698181284680735102541800711712032315078478955162535116151565304739038822351233990865329394107121603909513941845984594235316418441487123249107147803
    var1.mul_assign(&var12);
    //  717 : 1402987225833090001183582763053492619170900554891761640668811387392517041255663282600561858425044875824621157619743853845270305713945662552223069535753507765062695063793971985714364848
    square!(var1, 4);
    //  721 : 1402987225833090001183582763053492619170900554891761640668811387392517041255663282600561858425044875824621157619743853845270305713945662552223069535753507765062695063793971985714364849
    var1.mul_assign(var0);
    //  722 : 718329459626542080605994374683388221015501084104581960022431430344968725122899600691487671513622976422206032701308853168778396525540179226738211602305795975712099872662513656685754802688
    square!(var1, 9);
    //  731 : 718329459626542080605994374683388221015501084104581960022431430344968725122899600691487671513622976422206032701308853168778396525540179226738211602305795975712099872662513656685754802705
    var1.mul_assign(&var9);
    //  732 : 45973085416098693158783639979736846144992069382693245441435611542077998407865574444255210976871870491021186092883766602801817377634571470511245542547570942445574391850400874027888307373120
    square!(var1, 6);
    //  738 : 45973085416098693158783639979736846144992069382693245441435611542077998407865574444255210976871870491021186092883766602801817377634571470511245542547570942445574391850400874027888307373135
    var1.mul_assign(&var10);
    //  739 : 5884554933260632724324305917406316306558984880984735416503758277385983796206793528864667005039599422850711819889122125158632624337225148225439429446089080633033522156851311875569703343761280
    square!(var1, 7);
    //  746 : 5884554933260632724324305917406316306558984880984735416503758277385983796206793528864667005039599422850711819889122125158632624337225148225439429446089080633033522156851311875569703343761311
    var1.mul_assign(&var11);
    //  747 : 188305757864340247178377789357002121809887516191511533328120264876351481478617392923669344161267181531222778236451908005076243978791204743214061742274850580257072709019241980018230507000361952
    square!(var1, 5);
    //  752 : 188305757864340247178377789357002121809887516191511533328120264876351481478617392923669344161267181531222778236451908005076243978791204743214061742274850580257072709019241980018230507000361973
    var1.mul_assign(&var4);
    //  753 : 3012892125829443954854044629712033948958200259064184533249924238021623703657878286778709506580274904499564451783230528081219903660659275891424987876397609284113163344307871680291688112005791568
    square!(var1, 4);
    //  757 : 3012892125829443954854044629712033948958200259064184533249924238021623703657878286778709506580274904499564451783230528081219903660659275891424987876397609284113163344307871680291688112005791583
    var1.mul_assign(&var10);
    //  758 : 385650192106168826221317712603140345466649633160215620255990302466767834068208420707674816842275187775944249828253507594396147668564387314102398448178893988366484908071407575077336078336741322624
    square!(var1, 7);
    //  765 : 385650192106168826221317712603140345466649633160215620255990302466767834068208420707674816842275187775944249828253507594396147668564387314102398448178893988366484908071407575077336078336741322653
    var1.mul_assign(&var8);
    //  766 : 12340806147397402439082166803300491054932788261126899848191689678936570690182669462645594138952806008830215994504112243020676725394060394051276750341724607627727517058285042402474754506775722324896
    square!(var1, 5);
    //  771 : 12340806147397402439082166803300491054932788261126899848191689678936570690182669462645594138952806008830215994504112243020676725394060394051276750341724607627727517058285042402474754506775722324917
    var1.mul_assign(&var4);
    //  772 : 394905796716716878050629337705615713757849224356060795142134069725970262085845422804659012446489792282566911824131591776661655212609932609640856010935187444087280545865121356879192144216823114397344
    square!(var1, 5);
    //  777 : 394905796716716878050629337705615713757849224356060795142134069725970262085845422804659012446489792282566911824131591776661655212609932609640856010935187444087280545865121356879192144216823114397365
    var1.mul_assign(&var4);
    //  778 : 12636985494934940097620138806579702840251175179393945444548290231231048386747053529749088398287673353042141178372210936853172966803517843508507392349925998210792977467683883420134148614938339660715680
    square!(var1, 5);
    //  783 : 12636985494934940097620138806579702840251175179393945444548290231231048386747053529749088398287673353042141178372210936853172966803517843508507392349925998210792977467683883420134148614938339660715697
    var1.mul_assign(&var9);
    //  784 : 202191767918959041561922220905275245444018802870303127112772643699696774187952856475985414372602773648674258853955374989650767468856285496136118277598815971372687639482942134722146377839013434571451152
    square!(var1, 4);
    //  788 : 202191767918959041561922220905275245444018802870303127112772643699696774187952856475985414372602773648674258853955374989650767468856285496136118277598815971372687639482942134722146377839013434571451165
    var1.mul_assign(&var5);
    //  789 : 12940273146813378659963022137937615708417203383699400135217449196780593548028982814463066519846577513515152566653143999337649118006802271752711569766324222167852008926908296622217368181696859812572874560
    square!(var1, 6);
    //  795 : 12940273146813378659963022137937615708417203383699400135217449196780593548028982814463066519846577513515152566653143999337649118006802271752711569766324222167852008926908296622217368181696859812572874589
    var1.mul_assign(&var8);
    //  796 : 25880546293626757319926044275875231416834406767398800270434898393561187096057965628926133039693155027030305133306287998675298236013604543505423139532648444335704017853816593244434736363393719625145749178
    var1 = var1.square();
    //  797 : 25880546293626757319926044275875231416834406767398800270434898393561187096057965628926133039693155027030305133306287998675298236013604543505423139532648444335704017853816593244434736363393719625145749179
    var1.mul_assign(var0);
    //  798 : 1656354962792112468475266833656014810677402033113523217307833497187915974147709800251272514540361921729939528531602431915219087104870690784347080930089500437485057142644261967643823127257198056009327947456
    square!(var1, 6);
    //  804 : 1656354962792112468475266833656014810677402033113523217307833497187915974147709800251272514540361921729939528531602431915219087104870690784347080930089500437485057142644261967643823127257198056009327947463
    var1.mul_assign(&var3);
    //  805 : 1696107481899123167718673237663759166133659681908247774523221501120425957527254835457303054889330607851458077216360890281184345195387587363171410872411648447984698514067724254867274882311370809353551818202112
    square!(var1, 10);
    //  815 : 1696107481899123167718673237663759166133659681908247774523221501120425957527254835457303054889330607851458077216360890281184345195387587363171410872411648447984698514067724254867274882311370809353551818202135
    var1.mul_assign(&var7);
    //  816 : 108550878841543882733995087210480586632554219642127857569486176071707261281744309469267395512917158902493316941847096977995798092504805591242970295834345500671020704900334352311505592467927731798627316364936640
    square!(var1, 6);
    //  822 : 108550878841543882733995087210480586632554219642127857569486176071707261281744309469267395512917158902493316941847096977995798092504805591242970295834345500671020704900334352311505592467927731798627316364936661
    var1.mul_assign(&var4);
    //  823 : 6947256245858808494975685581470757544483470057096182884447115268589264722031635806033113312826698169759572284278214206591731077920307557839550098933398112042945325113621398547936357917947374835112148247355946304
    square!(var1, 6);
    //  829 : 6947256245858808494975685581470757544483470057096182884447115268589264722031635806033113312826698169759572284278214206591731077920307557839550098933398112042945325113621398547936357917947374835112148247355946329
    var1.mul_assign(&var6);
    //  830 : 444624399734963743678443877214128482846942083654155704604615377189712942210024691586119252020908682864612626193805709221870788986899683701731206331737479170748500807271769507067926906748631989447177487830780565056
    square!(var1, 6);
    //  836 : 444624399734963743678443877214128482846942083654155704604615377189712942210024691586119252020908682864612626193805709221870788986899683701731206331737479170748500807271769507067926906748631989447177487830780565069
    var1.mul_assign(&var5);
    //  837 : 28455961583037679595420408141704222902204293353865965094695384140141628301441580261511632129338155703335208076403565390199730495161579756910797205231198666927904051665393248452347322031912447324619359221169956164416
    square!(var1, 6);
    //  843 : 28455961583037679595420408141704222902204293353865965094695384140141628301441580261511632129338155703335208076403565390199730495161579756910797205231198666927904051665393248452347322031912447324619359221169956164437
    var1.mul_assign(&var4);
    //  844 : 238705906983162543355580399100765177871214152862586865721082456961065184302499251714358569373223087638243353151383559860752580829556389241459968722180074986980751351032731127113348364375477010926880553717580063640645533696
    square!(var1, 23);
    //  867 : 238705906983162543355580399100765177871214152862586865721082456961065184302499251714358569373223087638243353151383559860752580829556389241459968722180074986980751351032731127113348364375477010926880553717580063640645533703
    var1.mul_assign(&var3);
    //  868 : 15277178046922402774757145542448971383757705783205559406149277245508171795359952109718948439886277608847574601688547831088165173091608911453437998219524799166768086466094792135254295320030528699320355437925124073001314156992
    square!(var1, 6);
    //  874 : 15277178046922402774757145542448971383757705783205559406149277245508171795359952109718948439886277608847574601688547831088165173091608911453437998219524799166768086466094792135254295320030528699320355437925124073001314156999
    var1.mul_assign(&var3);
    //  875 : 488869697501516888792228657358367084280246585062577900996776871856261497451518467511006350076360883483122387254033530594821285538931485166510015943024793573336578766915033348328137450240976918378251374013603970336042053023968
    square!(var1, 5);
    //  880 : 488869697501516888792228657358367084280246585062577900996776871856261497451518467511006350076360883483122387254033530594821285538931485166510015943024793573336578766915033348328137450240976918378251374013603970336042053023971
    var1.mul_assign(&var2);
    //  881 : 31287660640097080882702634070935493393935781444004985663793719798800735836897181920704406404887096542919832784258145958068562274491615050656641020353586788693541041082562134293000796815422522776208087936870654101506691393534144
    square!(var1, 6);
    //  887 : 31287660640097080882702634070935493393935781444004985663793719798800735836897181920704406404887096542919832784258145958068562274491615050656641020353586788693541041082562134293000796815422522776208087936870654101506691393534151
    var1.mul_assign(&var3);
    //  888 : 1001205140483106588246484290269935788605945006208159541241399033561623546780709821462541004956387089373434649096260670658193992783731681621012512651314777238193313314641988297376025498093520728838658813979860931248214124593092832
    square!(var1, 5);
    //  893 : 1001205140483106588246484290269935788605945006208159541241399033561623546780709821462541004956387089373434649096260670658193992783731681621012512651314777238193313314641988297376025498093520728838658813979860931248214124593092835
    var1 * var2
}
