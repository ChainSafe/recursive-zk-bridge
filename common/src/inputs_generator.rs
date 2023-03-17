use eyre::Result;
use std::fs;
use std::path::{Path, PathBuf};
// use bls12_381_plus::{ExpandMsgXmd, G1Projective, G2Projective};
use group::{Curve, GroupEncoding};
use itertools::Itertools;
use milagro_bls::amcl_utils::{hash_to_curve_g2, Big, DBig, GroupG1, GroupG2, FP, FP2, MODULUS};
use milagro_bls::{AggregatePublicKey, AggregateSignature, Signature};
use rand::rngs::OsRng;
use rand::{seq::IteratorRandom, thread_rng, Rng};
use sha2::digest::generic_array::typenum::Gr;

use ssz_rs::prelude::*;

use sha2::Sha256;

pub type BLSPubKey = Vector<u8, 48>;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SlotCommitteeRotation {
    pub old_committee_root: Vec<u8>,
    pub pubkeys: Vec<[Vec<String>; 2]>,
    pub pubkeybits: Vec<u8>,
    pub signature: [[Vec<String>; 2]; 2],
    pub Hm: [[Vec<String>; 2]; 2],
    pub pubkey_hexes: Vec<Vec<u8>>,
    pub agg_pubkey_hex: Vec<u8>,
    pub signature_hex: Vec<u8>,
    pub hm_hex: Vec<u8>,
}

#[derive(Debug, Clone, Default, SimpleSerialize)]
pub struct SyncCommittee<const N: usize> {
    pub pubkeys: Vector<BLSPubKey, N>,
    pub aggregate_pubkey: BLSPubKey,
}
//
// const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
//
// pub fn generate_mock_inputs<const V: usize>(t: usize, n: usize, out: impl AsRef<Path>) {
//     let mut result_slots = vec![];
//     let mut all_validators = vec![];
//
//     for i in 0..t {
//         all_validators.push(milagro_bls::Keypair::random(&mut OsRng));
//     }
//
//     let mut old_committee_root = [0; 32].to_vec();
//
//     let mut private_keys = vec![];
//
//     for i in 0..n {
//         let signing_kps = all_validators.iter().choose_multiple(&mut thread_rng(), V);
//         let mut agg_sig = AggregateSignature::new();
//         let mut public_keys = vec![];
//         let mut pubkey_hexes = vec![];
//         for keypair in signing_kps {
//             private_keys.push(hex::encode(keypair.sk.as_bytes()));
//             let sig = Signature::new(&old_committee_root, &keypair.sk);
//             agg_sig.add(&sig);
//             public_keys.push(keypair.pk.clone());
//             let pubkey_bytes = {
//                 let mut b = [0; 49];
//                 keypair.pk.point.to_bytes(&mut b, true);
//                 b[1..49].to_vec()
//             };
//
//             pubkey_hexes.push(pubkey_bytes);
//         }
//         let agg_pub_key = AggregatePublicKey::into_aggregate(&public_keys).unwrap();
//
//         let agg_pubkey_hex = {
//             let mut b = [0; 49];
//             agg_pub_key.point.to_bytes(&mut b, true);
//             b[1..49].to_vec()
//         };
//
//         // let hm = hash_to_curve_g2(&old_committee_root);
//         // println!("{}", hm.to_hex());
//
//         let g2 = bls12_381_plus::G2Projective::hash::<ExpandMsgXmd<Sha256>>(&old_committee_root, DST);
//         let mut hm = deserialize_zk_crypto_uncompressed(g2);
//
//         hm.affine();
//         println!("{:?}", g2_to_array(&hm));
//
//         let sc = SyncCommittee::<V> {
//             pubkeys: pubkey_hexes.iter().map(|h| Vector::from_iter(h.clone().into_iter())).collect(),
//             aggregate_pubkey: Vector::from_iter(agg_pubkey_hex.clone().into_iter())
//         };
//
//         println!("{}", agg_pubkey_hex.len());
//
//         result_slots.push(SlotCommitteeRotation{
//             old_committee_root: old_committee_root.to_vec(),
//             pubkeys: public_keys.iter().map(|pk| g1_to_array(&pk.point)).collect_vec(),
//             pubkeybits: (0..V).into_iter().map(|_| 1).collect_vec(),
//             signature: g2_to_array(&agg_sig.point),
//             Hm: g2_to_array(&hm),
//             pubkey_hexes,
//             agg_pubkey_hex,
//             signature_hex: vec![],
//             hm_hex: vec![]
//         });
//
//         old_committee_root = ssz_rs::serialize(&sc).unwrap().as_slice().to_vec();
//     }
//
//     let json_bytes = serde_json::to_vec(&result_slots).unwrap();
//
//     fs::write(out, json_bytes).unwrap();
//
//     fs::write("../private_keys.json", serde_json::to_vec(&private_keys).unwrap()).unwrap();
// }
//
// fn g2_to_array(g2: &GroupG2) -> [[Vec<String>; 2]; 2] {
//     let xa = g2.getx().geta().w.into_iter().map(|e| e.to_string()).collect_vec();
//     let xb = g2.getx().getb().w.into_iter().map(|e| e.to_string()).collect_vec();
//     let ya = g2.gety().geta().w.into_iter().map(|e| e.to_string()).collect_vec();
//     let yb = g2.gety().getb().w.into_iter().map(|e| e.to_string()).collect_vec();
//
//     [[xa, xb], [ya, yb]]
// }
//
// fn g1_to_array(g1: &GroupG1) -> [Vec<String>; 2] {
//     let x = g1.getx().w.into_iter().map(|e| e.to_string()).collect_vec();
//     let y = g1.gety().w.into_iter().map(|e| e.to_string()).collect_vec();
//
//     [x, y]
// }
// //
// // fn pubkey_deserialize<'de, D>(deserializer: D) -> Result<BLSPubKey, D::Error>
// //     where
// //         D: serde::Deserializer<'de>,
// // {
// //     let key: String = serde::Deserialize::deserialize(deserializer)?;
// //     let key_bytes = hex_str_to_bytes(&key).map_err(D::Error::custom)?;
// //     Ok(Vector::from_iter(key_bytes))
// // }
// //
// // fn pubkeys_deserialize<'de, D>(deserializer: D) -> Result<Vector<BLSPubKey, 512>, D::Error>
// //     where
// //         D: serde::Deserializer<'de>,
// // {
// //     let keys: Vec<String> = serde::Deserialize::deserialize(deserializer)?;
// //     keys.iter()
// //         .map(|key| {
// //             let key_bytes = hex_str_to_bytes(key)?;
// //             Ok(Vector::from_iter(key_bytes))
// //         })
// //         .collect::<Result<Vector<BLSPubKey, 512>>>()
// //         .map_err(D::Error::custom)
// // }
// //
// // pub fn hex_str_to_bytes(s: &str) -> Result<Vec<u8>> {
// //     let stripped = s.strip_prefix("0x").unwrap_or(s);
// //     Ok(hex::decode(stripped)?)
// // }
//
// fn deserialize_zk_crypto_uncompressed(g2: G2Projective) -> GroupG2 {
//     let xc1 = {
//         FP::from_okm(&g2.x.c1.to_bytes())
//     };
//
//     let xc0 = {
//         FP::from_okm(&g2.x.c0.to_bytes())
//     };
//
//     // Attempt to obtain the y-coordinate
//     let yc1 = {
//         FP::from_okm(&g2.y.c1.to_bytes())
//     };
//     let yc0 = {
//         FP::from_okm(&g2.y.c0.to_bytes())
//     };
//
//     // Attempt to obtain the y-coordinate
//     let zc1 = {
//         FP::from_okm(&g2.z.c1.to_bytes())
//     };
//     let zc0 = {
//         FP::from_okm(&g2.z.c0.to_bytes())
//     };
//
//     GroupG2::new_projective(
//         FP2::new_fps(xc0, xc1),
//         FP2::new_fps(yc0, yc1),
//         FP2::new_fps(zc0, zc1),
//     )
// }
