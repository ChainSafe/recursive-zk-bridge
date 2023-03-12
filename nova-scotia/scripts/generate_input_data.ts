import path from "path";
import fs from "fs";

import {
  toHexString,
  fromHexString,
  VectorCompositeType,
  ByteVectorType,
  CompositeType,
  ContainerType
} from "@chainsafe/ssz";
import { ssz } from "@lodestar/types";
import { PointG1, PointG2, aggregatePublicKeys } from "@noble/bls12-381";
import * as bls from "@noble/bls12-381";
import {
  utils,
  formatHex,
  bigint_to_array,
  msg_hash,
  sigHexAsSnarkInput,
  hexToIntArray,
} from "./bls_utils";

const wasm_tester = (await import("circom_tester")).wasm;
// const ff = require("ffjavascript");
// exports.p = ff.Scalar.fromString("21888242871839275222246405745257275088548364400416034343698204186575808495617");
// const Fr = new ff.F1Field(exports.p);

var n: number = 55;
var k: number = 7;


function point_to_bigint(point: PointG1): [bigint, bigint] {
  let [x, y] = point.toAffine();
  return [x.value, y.value];
}

const slots: number = 2;

function getMultipleRandom(arr: Uint8Array[], num: number): Uint8Array[] {
  const shuffled = [...arr].sort(() => 0.5 - Math.random());

  return shuffled.slice(0, num);
}

async function generate_data(b: number = 16) {
  // const sszCircuit = await wasm_tester("circuits/simple_serialize.circom");
  // await sszCircuit.loadConstraints();
  const privateKeys = [];

  for (let i = 0; i < b; i++) {
    privateKeys.push(bls.utils.randomPrivateKey());
  }

  var oldCommitteeRoot = Uint8Array.from(Array(32).fill(0));

  var resultSlots = [];

  for (let i = 0; i < slots; i++) {
    let signing_keys = getMultipleRandom(privateKeys, b);
    const publicKeys = signing_keys.map(bls.getPublicKey);
    const aggPubKey = bls.aggregatePublicKeys(publicKeys);

    const signatures = await Promise.all(privateKeys.map(p => bls.sign(oldCommitteeRoot, p)));
    const aggSignature = bls.aggregateSignatures(signatures);

    const pubkeys = publicKeys.map((pubkey, idx: number) => {
      const point = PointG1.fromHex(formatHex(toHexString(pubkey)));
      const bigints = point_to_bigint(point);
      return [
        bigint_to_array(n, k, bigints[0]),
        bigint_to_array(n, k, bigints[1]),
      ];
    });

    resultSlots.push({
      "old_committee_root": Array.from(oldCommitteeRoot),
      "pubkeys": pubkeys,
      "pubkeybits": new Array(b).fill(1),
      "signature": sigHexAsSnarkInput(toHexString(aggSignature), "array"),
      "Hm": await msg_hash(oldCommitteeRoot, "array"),
      "pubkey_hexes": publicKeys.map((pubkey) =>
          hexToIntArray(toHexString(pubkey))
      ),
      "agg_pubkey_hex": hexToIntArray(
          toHexString(aggPubKey)
      ),
      "signature_hex": hexToIntArray(toHexString(aggSignature)),
      "hm_hex": hexToIntArray(toHexString((await PointG2.hashToCurve(oldCommitteeRoot)).toRawBytes(true)))
    })

    console.log((await PointG2.hashToCurve(oldCommitteeRoot)).x.c0.value);

    const CustomSyncCommittee = new ContainerType({
      pubkeys: new VectorCompositeType(new ByteVectorType(48), b),
      aggregatePubkey: new ByteVectorType(48),
    });

    let sc = CustomSyncCommittee.defaultValue();
    sc.pubkeys = publicKeys;
    sc.aggregatePubkey = aggPubKey;
    console.log(sc.pubkeys.length);


    oldCommitteeRoot = CustomSyncCommittee.hashTreeRoot(sc);
    console.log("sync committee ssz", toHexString(oldCommitteeRoot));
  }

  fs.writeFileSync(
      "../input_nova_bls_verify.json",
      JSON.stringify(resultSlots, (_, v) => typeof v === 'bigint' ? v.toString() : v)
  );
}

generate_data(16);
