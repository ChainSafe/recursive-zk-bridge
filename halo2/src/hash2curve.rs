use std::borrow::BorrowMut;
use std::cell::RefCell;
use std::cmp::min;
use std::convert::TryInto;
use std::{fmt, iter};
use std::ops::{Add, DerefMut, Div, Mul, Shl};
use std::rc::Rc;
use std::str::FromStr;
use std::sync::Arc;
use crypto_bigint::{CheckedSub, Encoding, Limb, NonZero, Pow, Uint};
use halo2_gadgets::sha256::{AssignedBits, Table16Chip};

use halo2_proofs::{arithmetic::FieldExt, circuit::{Chip, Layouter}, pairing, plonk::Error};
use halo2_proofs::arithmetic::{BaseExt, Field};

use halo2_proofs::circuit::Region;
use halo2_proofs::pairing::bls12_381::{Fq, G1, G1Affine, G2Affine};
use halo2_proofs::pairing::bn256::Fr;
use halo2_proofs::pairing::group::ff::PrimeField;
use halo2ecc_s::{circuit::{
    base_chip::{BaseChip, BaseChipConfig, BaseChipOps},
    range_chip::{RangeChip, RangeChipConfig, RangeChipOps},
}, context::{Context, Records}};
use halo2ecc_s::assign::{AssignedCondition, AssignedFq, AssignedFq2, AssignedG2Affine, AssignedInteger, AssignedValue, ValueSchema};
use halo2ecc_s::circuit::ecc_chip::{EccBaseIntegerChipWrapper, EccChipBaseOps};
use halo2ecc_s::circuit::fq12::Fq2ChipOps;
use halo2ecc_s::context::{GeneralScalarEccContext, IntegerContext};
use halo2ecc_s::utils::{bn_to_field, field_to_bn};
use itertools::Itertools;
use milagro_bls::amcl_utils::Big;
use num_bigint::BigUint;
use sha2::digest::typenum::private::IsEqualPrivate;
use num_integer::Integer;
use num_traits::{FromPrimitive, Num, One, ToPrimitive, Zero};
use subtle::ConditionallySelectable;
use crate::sha256::Sha256;

const SHA256_DIGEST_SIZE: usize = 32;

// G2 extension degree
const M: usize = 2;

const BLS12_LOG2P: usize = 381;

// section 5.1 of ietf draft link above
const L: usize = 64;

const NUM_REGISTER: usize = 10;

const BITS_PER_REGISTER: usize = 55;

/// A gadget that constrains a SHA-256 invocation. It supports input at a granularity of
/// 32 bits.
#[derive(Debug)]
pub struct HashToCurve {
    main_gate: Rc<RefCell<Context<Fr>>>,
    hash_chip: Table16Chip,
}

impl HashToCurve {
    /// Create a new hasher instance.
    pub fn new(ctx: Rc<RefCell<Context<Fr>>>, hash_chip: Table16Chip) -> Self {
        HashToCurve {
            main_gate: ctx,
            hash_chip
        }
    }

    pub fn hash_to_g2(
        &self,
        msg: [AssignedValue<Fr>; SHA256_DIGEST_SIZE],
        dst: impl AsRef<[u8]>,
        mut layouter: impl Layouter<Fr>
    ) -> Result<AssignedG2Affine<G1Affine, Fr>, Error> {
        let fields = self.hash_to_field(msg, dst, layouter)?;


        let point = AssignedG2Affine::new(
            (fields[0][0].clone(), fields[0][1].clone()),
            (fields[1][0].clone(), fields[1][1].clone()),
            self.main_gate.as_ref().borrow_mut().assign_bit(Fr::zero())
        );

        Ok(point)
    }

    pub fn hash_to_field(
        &self,
        msg: [AssignedValue<Fr>; SHA256_DIGEST_SIZE],
        dst: impl AsRef<[u8]>,
        mut layouter: impl Layouter<Fr>
    ) -> Result<[[AssignedFq<Fq, Fr>; 2]; 2], Error> {
        let main_gate = self.main_gate.clone();

        let assigned_dst = dst.as_ref().iter().cloned().map(|b| main_gate.as_ref().borrow_mut().assign_constant(Fr::from(b as u64))).collect_vec();

        let len_in_bytes = 2 * M * L;
        let extended_msg = self.expand_message_xmd(
            msg,
            assigned_dst,
            len_in_bytes,
            layouter.namespace(|| "expand_message_xmd")
        )?;

        let mut u = vec![];
        let mut u_d = vec![];

        let assigned_one = main_gate.as_ref().borrow_mut().assign_constant(Fr::one());
        for i in 0..2 {
            let mut e = vec![];
            let mut e_d = vec![];

            for j in 0..M {
                let elm_offset = L * (j + i * M);
                let tv = extended_msg[elm_offset..elm_offset + L].into_iter().rev().collect_vec();
                // println!("len_in {} tv {:?} => {:?}", tv.len(), tv.iter().map(|e| e.val.get_lower_128()).collect_vec(), self.os2ip(tv.clone()).val);

                let mut registers = iter::repeat_with(|| main_gate.as_ref().borrow_mut().assign(Fr::zero())).take(NUM_REGISTER).collect_vec();
                let mut cur_bits = 0;
                let mut idx = 0;
                for k in 0..L {
                    if cur_bits + 8 <= BITS_PER_REGISTER {
                        registers[idx] = main_gate.as_ref().borrow_mut().mul_add(&tv[k], &assigned_one, Fr::from(1 << cur_bits), &registers[idx], Fr::one());

                        cur_bits += 8;

                        if cur_bits == BITS_PER_REGISTER {
                            cur_bits = 0;
                            idx += 1;
                        }
                    } else {
                        let bits_1 = BITS_PER_REGISTER - cur_bits;
                        let bits_2 = 8 - bits_1;

                        let bits = self.byte_to_bits(&tv[k]);

                        let remainder_1 = self.bits_to_byte(bits.iter().cloned().take(bits_1).collect_vec());

                        let remainder_2 = self.bits_to_byte(bits.iter().cloned().skip(bits_1).take(bits_2).collect_vec());

                        registers[idx] = main_gate.as_ref().borrow_mut().mul_add(&remainder_1, &assigned_one, Fr::from(1 << cur_bits), &registers[idx], Fr::one());
                        registers[idx + 1] = remainder_2;
                        idx += 1;
                        cur_bits = bits_2;
                    }
                }

                let registers = self.prime_reduce(registers);

                let limbs = self.signed_fp_carry_modp(registers.clone());
                e_d.push(limbs.iter().map(|e| e.val.get_lower_128()).collect_vec());

                let mut modx = BigUint::one();
                for i in 0..55 {
                    modx = modx.mul(2u32)
                }
                let mut x = BigUint::zero();

                let ls = limbs.iter().map(|e| e.val.get_lower_128()).collect_vec();
                for i in (0..ls.len()).rev() {
                    x = x * modx.clone() + BigUint::from(ls[i])
                }

                println!("{}", x);

                let fq = {
                    let mut ecc_ctx = GeneralScalarEccContext::<G1Affine, Fr>::new(self.main_gate.clone());

                    let int_ctx = ecc_ctx.base_integer_chip();

                    println!("limb_bits={} limbs={}", int_ctx.range_chip().info().limb_bits, int_ctx.range_chip().info().limbs);

                    // println!("bn {}", bn);

                    //int_ctx.assign_w(&bn)

                    let schemas = limbs.iter().zip(int_ctx.range_chip().info().limb_coeffs.clone());
                    let native = int_ctx
                        .base_chip().sum_with_constant(schemas.collect(), None);
                    AssignedFq::new(limbs, native, 1)
                };

                e.push(fq);
            }

            let e: [_; 2] = e.try_into().unwrap();
            u.push(e);
            u_d.push(e_d);
        }


        Ok(u.try_into().unwrap())
    }

    pub fn expand_message_xmd(
        &self,
        msg: [AssignedValue<Fr>; SHA256_DIGEST_SIZE],
        mut dst: Vec<AssignedValue<Fr>>,
        len_in_bytes: usize,
        mut layouter: impl Layouter<Fr>
    ) -> Result<Vec<AssignedValue<Fr>>, Error> {
        let mut main_gate = self.main_gate();

        dst.push(main_gate.as_ref().borrow_mut().assign_constant(Fr::from(dst.len().to_le_bytes()[0] as u64)));

        let z_pad = iter::repeat_with(|| main_gate.as_ref().borrow_mut().assign_constant(Fr::zero())).take(63).collect_vec();

        let l_i_b_str = len_in_bytes.to_le_bytes().into_iter().take(3).map(|b| main_gate.as_ref().borrow_mut().assign_constant(Fr::from(b as u64))).collect_vec();

        let ell = len_in_bytes.div_ceil(SHA256_DIGEST_SIZE);

        let s256s_0_input = z_pad
            .into_iter()
            .chain(msg)
            .chain(l_i_b_str)
            .chain(iter::once(main_gate.as_ref().borrow_mut().assign_constant(Fr::zero())))
            .chain(dst.clone())
            .collect_vec();

        let mut b = vec![];
        let b_0 = Sha256::digest(self.hash_chip(), self.main_gate(), layouter.namespace(|| "sha256_0"), s256s_0_input)?;

        let s256s_1_input = b_0.into_iter()
            .chain(iter::once(main_gate.as_ref().borrow_mut().assign_constant(Fr::one())))
            .chain(dst.clone())
            .collect_vec();

        b.push(Sha256::digest(self.hash_chip(), self.main_gate(), layouter.namespace(|| "sha256_1"), s256s_1_input)?.to_vec());
        for i in 1..ell {
            let sha256_i_input = self.array_xor(b_0, b[i - 1].clone())
                .into_iter()
                .chain(iter::once(main_gate.as_ref().borrow_mut().assign_constant(Fr::from(i as u64 + 1))))
                .chain(dst.clone())
                .collect_vec();

            b.push(Sha256::digest(self.hash_chip(), self.main_gate(), layouter.namespace(|| format!("sha256_{}", i)), sha256_i_input)?.to_vec());
        }

        Ok(b.into_iter().flatten().take(len_in_bytes).collect_vec())
    }

    fn hash_chip(&self) -> Table16Chip {
        self.hash_chip.clone()
    }

    fn main_gate(&self) -> Rc<RefCell<Context<Fr>>> {
        self.main_gate.clone()
    }

    pub fn array_xor(&self, a: impl AsRef<[AssignedValue<Fr>]>, b: impl AsRef<[AssignedValue<Fr>]>) -> Vec<AssignedValue<Fr>> {
        a.as_ref().into_iter().zip(b.as_ref()).map(|(a, b)| {
            self.bits_to_byte(self.byte_to_bits(a).into_iter().zip(self.byte_to_bits(b)).map(
                |(a_b, b_b)| self.main_gate.as_ref().borrow_mut().xor(
                    &a_b, &b_b
                )
            ).collect_vec())
        }).collect_vec()
    }

    pub fn os2ip(&self, bytes: Vec<AssignedValue<Fr>>) -> AssignedValue<Fr> {
        let mut main_gate = self.main_gate.as_ref().borrow_mut();
        let mut result = main_gate.assign_constant(Fr::zero());
        let assigned_one = main_gate.assign_constant(Fr::from(256));


        for b in bytes {
            result = main_gate.mul_add(&result, &assigned_one, Fr::one(), &b, Fr::one());
        }

        result
    }

    pub fn byte_to_bits(&self, n: &AssignedValue<Fr>) -> Vec<AssignedCondition<Fr>> {
        let zero = Fr::zero();
        let one = Fr::one();
        let two = one + one;
        let two_inv = two.invert().unwrap();

        let mut bits = vec![];
        let v = field_to_bn(&n.val);
        let mut rest = n.clone();

        for i in 0..8 {
            let b = self.main_gate.as_ref().borrow_mut().assign_bit(v.bit(i).into());
            // let v = (rest.val - b.0.val) * two_inv;
            // rest = self.main_gate
            //     .as_ref()
            //     .borrow_mut()
            //     .one_line_with_last(
            //         vec![(ValueSchema::from(&rest), -one), (ValueSchema::from(&b.0), one)],
            //         (ValueSchema::from(v), two),
            //         None,
            //         (vec![], None),
            //     )
            //     .1;
            bits.push(b);

            //self.main_gate.as_ref().borrow_mut().assert_constant(&rest, zero);
        }

        bits
    }

    pub fn bits_to_byte(&self, bits: Vec<AssignedCondition<Fr>>) -> AssignedValue<Fr> {
        let mut main_gate = self.main_gate.as_ref().borrow_mut();
        let mut lc1 = main_gate.assign_constant(Fr::zero());
        let mut e2 = Fr::one();

        let one = main_gate.assign_constant(Fr::one());

        for b in bits {
            lc1 = main_gate.mul_add(&b.0, &one, e2, &lc1, Fr::one());
            e2 = e2 + e2
        }

        lc1
    }

    pub fn prime_reduce(&self, mut bns: Vec<AssignedValue<Fr>>) -> Vec<AssignedValue<Fr>> {
        let k = 7;
        let m = 3;

        // two ^ e mod p
        // let p = Uint::<7>::from([0xb9fe_ffff_ffff_aaab,
        //     0x1eab_fffe_b153_ffff,
        //     0x6730_d2a0_f6b0_f624,
        //     0x6477_4b84_f385_12bf,
        //     0x4b1b_a7b6_434b_acd7,
        //     0x1a01_11ea_397f_e69a, 0]);
        // let pow2n = Uint::<7>::from(2u8).pow(&Uint::<7>::from(BITS_PER_REGISTER));
        // let pow2nk = pow2n.pow(&BigUint::from(BITS_PER_REGISTER));
        //
        // let mut r = vec![];
        // r[0] = Uint::<7>::from_be_slice(&pow2nk.clone().to_bytes_be()).to_limbs().into_iter().map(|e| e.0.to_u128().unwrap()).collect_vec();
        // let t = &pow2nk * pow2n.clone().div(p.clone());
        // r[1] = Uint::<7>::from_be_slice(&t.to_bytes_be()).to_limbs().into_iter().map(|e| e.0.to_u128().unwrap()).collect_vec();
        // r[2] = Uint::<7>::from_be_slice(&(t * pow2n).div(p).to_bytes_be()).to_limbs().into_iter().map(|e| e.0.to_u128().unwrap()).collect_vec();
        // println!("{:?}", r);

        let mut r = [
            [Fr::from(5348024557917519), Fr::from(54621380807268), Fr::from(15414564296778992), Fr::from(29551429513052912), Fr::from(9781498950865438), Fr::from(22955184228343852), Fr::from(1261049230581880)],
            [Fr::from(30938049114109417), Fr::from(25069422147581717), Fr::from(28307001734588567), Fr::from(22392818961866772), Fr::from(2511700624859367), Fr::from(31094434456506070), Fr::from(1473601367038320)],
            [Fr::from(14446664148595727), Fr::from(10904152646835916), Fr::from(10624676166198448), Fr::from(32578590057284104), Fr::from(30830349559713612), Fr::from(15030327468622177), Fr::from(665335521685653)],
        ];

        let mut out_sum = bns.iter().map(|e| self.main_gate.as_ref().borrow_mut().assign(e.val)).collect_vec();
        let mut assigned_one = self.main_gate.as_ref().borrow_mut().assign_constant(Fr::one());

        for i in 0..m {
            for j in 0..k {
                out_sum[j] = self.main_gate.as_ref().borrow_mut().mul_add(&bns[i+k], &assigned_one, r[i][j], &out_sum[j], Fr::one())
            }
        }

        out_sum.into_iter().take(7).collect_vec()
    }

    // // a = a0 + a1 * X + ... + a[k-1] * X^{k-1} with X = 2^n
    pub fn signed_fp_carry_modp(&self, limbs: Vec<AssignedValue<Fr>>) -> Vec<AssignedValue<Fr>> {
        let m = 3;
        let k = 7;
        let n = BITS_PER_REGISTER;

        let limbs_bns = limbs.into_iter().map(|e| e.val.get_lower_128()).collect_vec();

        let p = [35747322042231467,
            36025922209447795,
            1084959616957103,
            7925923977987733,
            16551456537884751,
            23443114579904617,
            1829881462546425];

        let mut a = Self::signed_long_to_short(55, 7, limbs_bns);
        a.resize(10, 0);

        // println!("a {:?}", a);
        //println!("p {:?}", p);

        // let rem = a.wrapping_rem(&p);
        //
        // println!("reduced {:?}", rem.to_words());


        let mut remainder = a.clone();
        let mut dividend = vec![0; k+1];
        let mut quotient = vec![0; k];

        for i in (0..=m).rev() {
            if i == m {
                for j in (0..k).rev() {
                    dividend[j] = remainder[j + m];
                }
            } else {
                for j in (0..=k).rev() {
                    dividend[j] = remainder[j + i];
                }
            }

            // println!("dividend {:?}", dividend);


            quotient[i] = {
                let scale = (1 << n) / (1 + p[k - 1]);
                let norm_a = Self::long_scalar_mult::<8>(n, scale, &dividend.clone().try_into().unwrap());
                let norm_p = Self::long_scalar_mult::<7>(n, scale, &p);

                // println!("norm_a {:?} norm_p {:?}", norm_a, norm_p);

                if norm_p[k] != 0 {
                    Self::short_div_norm::<8>(n, k+1, &norm_a, &norm_p)
                } else {
                    Self::short_div_norm::<8>(n, k, &norm_a, &norm_p)
                }
            };

            // println!("short_div {}", quotient[i]);

            let mult_shift = Self::long_scalar_mult_big::<7>(n, quotient[i], &p);
            // println!("mult_shift {:?}", mult_shift);

            let mut subtrahend = vec![0; m+k];

            for j in 0..k {
                subtrahend[i+j] = mult_shift[j]
            }

            // println!("remainder {:?}", remainder);
            remainder = Self::long_sub::<10>(n, k + m, &remainder.try_into().unwrap(), &subtrahend.try_into().unwrap()).to_vec();
        }

        // println!("reduced {:?}", remainder);

        remainder.into_iter().take(k).map(|rem| self.main_gate.as_ref().borrow_mut().assign(Fr::from(rem))).collect_vec()
    }

    fn signed_long_to_short_2(n: usize, k: usize, a: Vec<u128>) -> Vec<u128> {

        let mut temp = a.iter().cloned().map(|e| i128::from_u128(e).unwrap()).collect_vec();
        (temp.len()..9).for_each(|_| temp.push(0));
        let x = 1 << n;
        let mut out = vec![];

        for i in 0..8 {
            if temp[i] >= 0 {
                out.push(u128::from_i128(temp[i] % x).unwrap());
                temp[i+1] += temp[i] / x;
            } else {
                let borrow = (-temp[i] + x - 1) / x;
                out.push(u128::from_i128(temp[i] + borrow * x).unwrap());
                temp[i+1] -= borrow;
            }
        }

        out
    }

    fn signed_long_to_short(n: usize, k: usize, a: Vec<u128>) -> Vec<u64> {
        let mut temp = a.iter().cloned().map(|e| i128::from_u128(e).unwrap()).collect_vec();
        (temp.len()..9).for_each(|_| temp.push(0));
        let x = 1 << n;
        let mut out = vec![];

        for i in 0..8 {
            if temp[i] >= 0 {
                out.push(u64::from_i128(temp[i] % x).unwrap());
                temp[i+1] += temp[i] / x;
            } else {
                let borrow = (-temp[i] + x - 1) / x;
                out.push(u64::from_i128(temp[i] + borrow * x).unwrap());
                temp[i+1] -= borrow;
            }
        }

        out
    }

    fn long_scalar_mult<const K: usize>(n: usize, a: u64, b: &[u64; K]) -> [u64; {K+1}] {
        let mut out = [0; K+1];

        for i in 0..K {
            let temp = out[i] + (a * b[i]);
            out[i] = temp % (1 << n);
            out[i + 1] = out[i + 1] + temp / (1 << n);
        }

        out
    }

    fn long_scalar_mult_big<const K: usize>(n: usize, a: u64, b: &[u64; K]) -> [u64; {K+1}] {
        let mut out = [0; K+1];

        for i in 0..K {
            let temp = out[i] + (a as u128 * b[i] as u128);
            out[i] = temp % (1u128 << n);
            out[i + 1] = out[i + 1] + temp / (1u128 << n);
            // println!("long_scalar_mult {} {} {} {}", b[i], temp, out[i], out[i + 1]);
        }

        out.map(|e| e as u64)
    }

    fn short_div_norm<const K: usize>(n: usize, k: usize, a: &[u64; {K+1}], b: &[u64; K]) -> u64 {
        let qhat = (a[k] as u128 * (1u128 << n) + a[k - 1] as u128) / b[k - 1] as u128;
        // println!("qhat calc k {k} {} * {} + {} = {} \\ {} = {}", a[k], (1u128 << n), a[k - 1] as u128, (a[k]as u128 * (1u128 << n) + a[k - 1]as u128), b[k - 1], qhat as u64);
        let qhat = qhat as u64;

        let mut mult = Self::long_scalar_mult_big::<K>(n, qhat, &b);

        if Self::long_gt(k+1, &mult, &a) {
            // println!("long_gt qhat {} mult {:?}", qhat, mult);
            mult = Self::long_sub(n, k+1, &mult, &a);
            if Self::long_gt(k+1, &mult, &a) {
                qhat - 2
            } else {
                qhat - 1
            }
        } else {
            // println!("not long_gt qhat {}", qhat);
            qhat
        }
    }

    fn long_sub<const K: usize>(n: usize, k: usize, a: &[u64; K], b: &[u64; K]) -> [u64; K] {
        let mut diff = [0; K];
        let mut borrow = [0; K];

        for i in 0..k {
            if i == 0 {
                if a[i] >= b[i] {
                    diff[i] = a[i] - b[i];
                    borrow[i] = 0;
                } else {
                    diff[i] = a[i] - b[i] + (1 << n);
                    borrow[i] = 1;
                }
            } else {
                if a[i] >= b[i] + borrow[i - 1] {
                    diff[i] = a[i] - b[i] - borrow[i - 1];
                    borrow[i] = 0;
                } else {
                    diff[i] = (1 << n) + a[i] - b[i] - borrow[i - 1];
                    borrow[i] = 1;
                }
            }
        }

        diff
    }

    fn long_gt<const K: usize>(k: usize, a: &[u64; K], b: &[u64; K]) -> bool {
        for i in (0..k).rev() {
            if a[i] > b[i] {
                return true;
            }

            if a[i] < b[i] {
                return false;
            }
        }

        return false;
    }
}

#[cfg(test)]
mod tests {
    use std::ptr::hash;
    use halo2_gadgets::sha256::Table16Config;
    use super::*;
    use halo2_proofs::{
        arithmetic::FieldExt,
        circuit::{Layouter, SimpleFloorPlanner},
        dev::MockProver,
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error},
    };
    use sha2::Digest;

    const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

    #[test]
    fn test_hash2curve_circuit() {
        struct MyCircuit {}

        impl Circuit<Fr> for MyCircuit {
            type Config = (BaseChipConfig, Table16Config);
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                MyCircuit {}
            }

            fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
                (BaseChip::configure(meta), Table16Chip::configure(meta))
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<Fr>,
            ) -> Result<(), Error> {
                let base_chip = BaseChip::<Fr>::new(config.0.clone());
                let hash_chip = Table16Chip::construct(config.1.clone());

                Table16Chip::load(config.1.clone(), &mut layouter)?;

                let ctx = Rc::new(RefCell::new(Context::new()));

                let hash2curve = HashToCurve::new(ctx.clone(), hash_chip);

                let input = [0; 32];

                let assigned_input = input.map(|i| ctx.as_ref().borrow_mut().assign(Fr::from(i)));

                let g2 = hash2curve.hash_to_field(assigned_input, DST, layouter.namespace(|| "hash_to_g2")).unwrap();

                drop(hash2curve);

                let records = Arc::try_unwrap(Rc::try_unwrap(ctx).unwrap().into_inner().records).unwrap().into_inner().unwrap();

                layouter.assign_region(
                    || "assign",
                    |mut region| {
                        records.assign_all_in_base(&mut region, &base_chip)?;
                        Ok(())
                    },
                )?;

                Ok(())
            }
        }

        let circuit = MyCircuit {};
        let prover = match MockProver::<Fr>::run(17, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:?}", e),
        };
        prover.verify().unwrap()
    }
}
