//! Gadget and chips for the [SHA-256] hash function.
//!
//! [SHA-256]: https://tools.ietf.org/html/rfc6234

use std::borrow::BorrowMut;
use std::cell::RefCell;
use std::cmp::min;
use std::convert::TryInto;
use std::{fmt, iter};
use std::ops::{DerefMut, Shl};
use std::rc::Rc;
use std::sync::Arc;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Chip, Layouter},
    plonk::Error,
};

pub use halo2_gadgets::sha256::{BlockWord, Table16Chip, Table16Config, Sha256Instructions};
use halo2_gadgets::sha256::{AssignedBits, RoundWordDense, State};
use halo2_proofs::circuit::Region;
use halo2_proofs::pairing::bn256::Fr;
use halo2_proofs::pairing::group::ff::PrimeField;
use halo2ecc_s::{
    circuit::{
        base_chip::{BaseChip, BaseChipConfig, BaseChipOps},
        range_chip::{RangeChip, RangeChipConfig, RangeChipOps},
    },
    context::{Context, Records},
};
use halo2ecc_s::assign::{AssignedValue, ValueSchema};
use halo2ecc_s::utils::{bn_to_field, field_to_bn};
use itertools::Itertools;
use num_bigint::BigUint;
use sha2::digest::typenum::private::IsEqualPrivate;
use num_integer::Integer;
use num_traits::Num;

/// The size of a SHA-256 block, in 32-bit words.
pub const BLOCK_SIZE: usize = 16;
/// The size of a SHA-256 digest, in 32-bit words.
const DIGEST_SIZE: usize = 8;

/// The output of a SHA-256 circuit invocation.
#[derive(Debug)]
pub struct Sha256Digest<BlockWord>(pub [BlockWord; DIGEST_SIZE]);

/// A gadget that constrains a SHA-256 invocation. It supports input at a granularity of
/// 32 bits.
#[derive(Debug)]
pub struct Sha256 {
    chip: Table16Chip,
    main_gate: Rc<RefCell<Context<Fr>>>,
    state: State,
    cur_block: Vec<BlockWord>,
    length: usize,
}

impl Sha256 {
    /// Create a new hasher instance.
    pub fn new(chip: Table16Chip, ctx: Rc<RefCell<Context<Fr>>>, mut layouter: impl Layouter<Fr>) -> Result<Self, Error> {
        let state = chip.initialization_vector(&mut layouter)?;
        Ok(Sha256 {
            chip,
            main_gate: ctx,
            state,
            cur_block: Vec::with_capacity(BLOCK_SIZE),
            length: 0,
        })
    }

    pub fn digest(
        chip: Table16Chip,
        ctx: Rc<RefCell<Context<Fr>>>,
        mut layouter: impl Layouter<Fr>,
        assinged_inputs: Vec<AssignedValue<Fr>>,
    ) -> Result<[AssignedValue<Fr>; DIGEST_SIZE * 4], Error> {
        assert_eq!(assinged_inputs.len(), 64);
        let mut hasher = Self::new(chip, ctx, layouter.namespace(|| "init"))?;

        let mut padding = [0u8; 64];
        padding[0] = 0x80;

        let mut input_len_bytes = [0; 8];
        let le_size_bytes = (8usize * assinged_inputs.len()).to_le_bytes();
        input_len_bytes[0..le_size_bytes.len()].copy_from_slice(&le_size_bytes);
        for (i, byte) in input_len_bytes.iter().rev().enumerate() {
            padding[56+i] = *byte;
        }

        let assigned_padded_inputs = {
            let assinged_padding = padding
                .iter()
                .map(|val| {
                    hasher.main_gate.as_ref().borrow_mut().assign(
                        Fr::from_u128(*val as u128)
                    )
                })
                .collect_vec();

            assinged_inputs.clone().into_iter().chain(assinged_padding).collect_vec()
        };

        for (i, assigned_input_block) in assigned_padded_inputs
            .chunks((32 / 8) * BLOCK_SIZE)
            .enumerate()
        {
            let input_block = assigned_input_block
                .iter()
                .map(|cell| cell.val.get_lower_128().try_into().unwrap())
                .collect::<Vec<u8>>();
            let blockword_inputs = input_block
                .chunks(32 / 8)
                .map(|chunk| BlockWord(Some(u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))))
                .collect_vec();

            hasher.state = hasher.compute_round(&mut layouter, blockword_inputs.as_slice().try_into().unwrap()).unwrap();
        }

        let digest =  hasher.state_to_assigned_halves(&hasher.state)?;

        hasher.decompose_digest_to_bytes(&mut layouter, &digest).map(|d| d.as_slice().try_into().unwrap())
    }

    pub fn digest_bytes(
        chip: Table16Chip,
        mut ctx: Rc<RefCell<Context<Fr>>>,
        mut layouter: impl Layouter<Fr>,
        inputs: impl AsRef<[u8]>,
    ) -> Result<[AssignedValue<Fr>; DIGEST_SIZE * 4], Error> {
        let assigned_inputs = inputs.as_ref()
            .iter()
            .map(|val| {
                ctx.as_ref().borrow_mut().assign(
                    Fr::from_u128(*val as u128)
                )
            })
            .collect_vec();

        Self::digest(chip, ctx, layouter, assigned_inputs)
    }

    pub fn main_gate(&self) -> Rc<RefCell<Context<Fr>>> {
        self.main_gate.clone()
    }

    fn state_to_assigned_halves(
        &self,
        state: &State,
    ) -> Result<[AssignedValue<Fr>; DIGEST_SIZE], Error> {
        let (a, b, c, d, e, f, g, h) = state.clone().split_state();

        let assigned_cells = [
            self.concat_word_halves(a.dense_halves())?,
            self.concat_word_halves(b.dense_halves())?,
            self.concat_word_halves(c.dense_halves())?,
            self.concat_word_halves(d)?,
            self.concat_word_halves(e.dense_halves())?,
            self.concat_word_halves(f.dense_halves())?,
            self.concat_word_halves(g.dense_halves())?,
            self.concat_word_halves(h)?,
        ];

        Ok(assigned_cells)
    }

    fn concat_word_halves(
        &self,
        // ctx: &mut Region<Fr>,
        word: RoundWordDense,
    ) -> Result<AssignedValue<Fr>, Error> {
        let (lo, hi) = word.halves();
        let mut main_gate = self.main_gate();
        let u16 = main_gate.as_ref().borrow_mut().assign_constant(Fr::from(1 << 16));

        let val_u32 = word.value();
        let val_lo = val_u32.map(|v| Fr::from_u128((v % (1 << 16)) as u128));
        let val_hi = val_u32.map(|v| Fr::from_u128((v >> 16) as u128));
        let assigned_lo = main_gate.as_ref().borrow_mut().assign(val_lo.unwrap());
        let assigned_hi = main_gate.as_ref().borrow_mut().assign(val_hi.unwrap());
        // TODO ctx.constrain_equal(lo.cell(), assigned_lo.cell)?;
        // ctx.constrain_equal(hi.cell(), assigned_hi.cell)?;

        let res = main_gate.as_ref().borrow_mut().mul_add(&assigned_hi, &u16, Fr::one(), &assigned_lo, Fr::one());

        Ok(res)
    }

    fn compute_round(
        &self,
        layouter: &mut impl Layouter<Fr>,
        input: [BlockWord; BLOCK_SIZE],
    ) -> Result<State, Error> {
        let mut main_gate = self.main_gate();

        let last_state = &self.state;
        let last_digest = self.state_to_assigned_halves(last_state)?;
        let compressed_state =
            self.chip.compress(layouter, last_state, input)?;

        let compressed_state_values =
            self.state_to_assigned_halves( &compressed_state)?;

        let word_sums = last_digest
            .iter()
            .zip(&compressed_state_values)
            .map(|(digest_word, comp_word)| main_gate.as_ref().borrow_mut().add(digest_word, comp_word))
            .collect_vec();

        let u32_mod = 1u128 << 32;
        let lo_his = word_sums
            .iter()
            .map(|sum| {
                (
                    Fr::from_u128(sum.val.get_lower_128() % u32_mod),
                    Fr::from_u128(sum.val.get_lower_128() >> 32),
                )
            })
            .collect_vec();
        let assigned_los = lo_his
            .iter()
            .map(|(lo, hi)| main_gate.as_ref().borrow_mut().assign(*lo))
            .collect_vec();
        let assigned_his = lo_his
            .iter()
            .map(|(lo, hi)| main_gate.as_ref().borrow_mut().assign(*hi))
            .collect_vec();
        let u32 = main_gate.as_ref().borrow_mut().assign_constant(Fr::from(1 << 32));

        let combines = assigned_los
            .iter()
            .zip(&assigned_his)
            .map(|(lo, hi)| main_gate.as_ref().borrow_mut().mul_add(hi, &u32, Fr::one(), lo, Fr::one()))
            .collect_vec();

        for (combine, word_sum) in combines.iter().zip(&word_sums) {
            //main_gate.as_ref().borrow_mut().assert_equal(combine, word_sum);
        }

        let mut new_state_word_vals = [0u32; 8];
        for i in 0..8 {
            new_state_word_vals[i] = assigned_los[i].val.get_lower_128().try_into().unwrap()
        }

        let new_state = self
            .chip.config().compression
            .initialize_with_iv(layouter, new_state_word_vals)?;

        Ok(new_state)
    }

    pub fn decompose_digest_to_bytes(
        &self,
        layouter: &mut impl Layouter<Fr>,
        digest: &[AssignedValue<Fr>],
    ) -> Result<Vec<AssignedValue<Fr>>, Error> {
        let main_gate = self.main_gate();
        let mut assigned_bytes = Vec::new();
        for word in digest.into_iter() {
            let mut bytes = self.decompose(word.val, 8, 32)?
                .1;
            bytes.reverse();
            assigned_bytes.append(&mut bytes);
        }

        // let u8 = main_gate.as_ref().borrow_mut().assign_constant(Fr::from_u128(1u128 << 8));
        // let u16 = main_gate.as_ref().borrow_mut().assign_constant(Fr::from_u128(1u128 << 16));
        // let u24 = main_gate.as_ref().borrow_mut().assign_constant(Fr::from_u128(1u128 << 24));
        // for (idx, bytes) in assigned_bytes.chunks(32 / 8).enumerate() {
        //     let assigned_u32 = main_gate.as_ref().borrow_mut().mul_add(&u8, &bytes[2], Fr::one(), &bytes[3], Fr::one());
        //     let assigned_u32 = main_gate.as_ref().borrow_mut().mul_add(&u16, &bytes[1], Fr::one(), &assigned_u32, Fr::one());
        //     let assigned_u32 = main_gate.as_ref().borrow_mut().mul_add(&u24, &bytes[0], Fr::one(), &assigned_u32, Fr::one());
        //     main_gate.as_ref().borrow_mut().assert_equal(&assigned_u32, &digest[idx]) == 1;
        // }
        Ok(assigned_bytes)
    }

    fn decompose(
        &self,
        unassigned: Fr,
        limb_bit_len: usize,
        bit_len: usize,
    ) -> Result<(AssignedValue<Fr>, Vec<AssignedValue<Fr>>), Error> {
        let (number_of_limbs, overflow_bit_len) = bit_len.div_rem(&limb_bit_len);

        let number_of_limbs = number_of_limbs + if overflow_bit_len > 0 { 1 } else { 0 };
        let decomposed = decompose(unassigned, number_of_limbs, limb_bit_len);

        let mut bases = vec![Fr::one()];
        for i in 1..31 {
            bases.push(bases[i-1].mul(&Fr::from(0x0000000000000000000000000000000000000000000000000000000000000100)));
        }

        let terms: Vec<_> = decomposed
            .into_iter()
            .zip(&bases)
            .map(|(limb, base)| (limb, *base))
            .collect();

        self.
            decompose_terms(&terms[..], Fr::zero())
    }

    /// Assigns a new witness composed of given array of terms
    /// `result = constant + term_0 + term_1 + ... `
    /// where `term_i = a_i * q_i`
    fn decompose_terms(
        &self,
        terms: &[(Fr, Fr)],
        constant: Fr,
    ) -> Result<(AssignedValue<Fr>, Vec<AssignedValue<Fr>>), Error> {
        assert!(!terms.is_empty(), "At least one term is expected");

        // Last cell will be allocated for result or intermediate sums.
        let number_of_chunks = (terms.len() - 1) / 4 + 1;

        // `remaining` at first set to the sum of terms.
        let mut remaining = {
            terms.iter().fold(constant, |acc, term| {
                acc + term.0 * term.1
            })
        };

        // `result` will be assigned in the first iteration.
        // First iteration is guaranteed to be present disallowing empty
        let mut result = None;
        let last_term_index: usize = 0;

        let mut assigned: Vec<AssignedValue<Fr>> = vec![];
        for (i, chunk) in terms.chunks(4).enumerate() {
            let intermediate = (remaining, -Fr::one());
            let constant = if i == 0 { constant } else { Fr::zero() };
            let mut chunk = chunk.to_vec();

            let composed = {
                chunk.iter().fold(constant, |acc, term| {
                    acc + term.0 * term.1
                })
            };

            remaining = remaining - composed;

            let is_final = i == number_of_chunks - 1;
            // Final round
            let mut chunk = if is_final {
                // Sanity check
               // remaining.assert_if_known(Field::is_zero_vartime);

                // Assign last term to the first column to enable overflow range check
                let last_term = chunk.pop().unwrap();
                chunk.insert(last_term_index, last_term);

                //self.main_gate.as_ref().borrow_mut().one_line_add(chunk.clone().into_iter().map(|(a,i)| (ValueSchema::Unassigned(a), i)).collect(), None)
                // Intermediate round should accumulate the sum
                chunk
            } else {
                chunk
            };

            let chunk_len = chunk.len();
            let mut combined: Vec<AssignedValue<Fr>> = chunk
                .iter()
                .cloned()
                // .chain(iter::repeat(Term::Zero).take(5 - chunk.len() - 1))
                .chain(iter::once(intermediate))
                .map(|(c, b)| self.main_gate.as_ref().borrow_mut().clone().assign(c)).collect_vec();

            // Set the result at the first iter
            if i == 0 {
                result = combined.pop();
            }

            let mut combined = combined[..chunk_len].to_vec();
            if is_final {
                // Rewind the overflow range trick
                let last_term = combined.remove(last_term_index);
                combined.push(last_term);
            }
            assigned.extend(combined.into_iter().take(chunk_len));
        }
        Ok((result.unwrap(), assigned))
    }
}

pub fn decompose<F: FieldExt>(e: F, number_of_limbs: usize, bit_len: usize) -> Vec<F> {
    decompose_big(fe_to_big(e), number_of_limbs, bit_len)
}

pub fn decompose_big<F: FieldExt>(e: BigUint, number_of_limbs: usize, bit_len: usize) -> Vec<F> {
    let mut e = e;
    let mask = BigUint::from(1usize).shl(bit_len) - 1usize;
    let limbs: Vec<F> = (0..number_of_limbs)
        .map(|_| {
            let limb = mask.clone() & e.clone();
            e = e.clone() >> bit_len;
            big_to_fe(limb)
        })
        .collect();

    limbs
}

pub fn fe_to_big<F: FieldExt>(fe: F) -> BigUint {
    BigUint::from_bytes_le(fe.to_repr().as_ref())
}

pub fn big_to_fe<F: FieldExt>(e: BigUint) -> F {
    let modulus = modulus::<F>();
    let e = e % modulus;
    F::from_str_vartime(&e.to_str_radix(10)[..]).unwrap()
}

pub fn modulus<F: FieldExt>() -> BigUint {
    BigUint::from_str_radix(&F::MODULUS[2..], 16).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{
        arithmetic::FieldExt,
        circuit::{Layouter, SimpleFloorPlanner},
        dev::MockProver,
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error},
    };
    use sha2::Digest;

    #[test]
    fn test_sha256_circuit() {
        struct MyCircuit {}

        impl Circuit<Fr> for MyCircuit {
            type Config = (BaseChipConfig, RangeChipConfig, Table16Config);
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                MyCircuit {}
            }

            fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
                (BaseChip::configure(meta), RangeChip::<Fr>::configure(meta), Table16Chip::configure(meta))
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<Fr>,
            ) -> Result<(), Error> {
                let base_chip = BaseChip::<Fr>::new(config.0.clone());
                //let range_chip = RangeChip::<Fr>::new(config.1.clone());

                // range_chip.init_table(&mut layouter)?;


                Table16Chip::load(config.2.clone(), &mut layouter)?;
                let hash_chip = Table16Chip::construct(config.2.clone());

                let ctx = Rc::new(RefCell::new(Context::new()));

                let inputs = [0; 64];

                let digest = Sha256::digest_bytes(hash_chip, ctx.clone(), layouter.namespace(|| "sha256"), inputs.clone()).unwrap();

                let bytes = digest.into_iter().map(|e| e.val.get_lower_128() as u8).collect::<Vec<_>>();

                println!("{:?}", bytes);

                // assert_eq!(
                //     bytes,
                //     sha2::Sha256::digest(inputs).to_vec(),
                // );

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
