pragma circom 2.0.3;

include "./aggregate_bls_verify.circom";
include "./simple_serialize.circom";

template CommitteeRotationStep(b, n, k) {
    signal input step_in[32];

    signal output step_out[32];

    signal input pubkeys[b][2][k];
    signal input pubkeybits[b];
    signal input signature[2][2][k];
    signal input pubkeyHex[b][48];
    signal input aggregatePubkeyHex[48];

    // Convert the signing_root to a field element using hash_to_field
    // This requires k = 7 and n = 55
    component hashToField = HashToField(32, 2);
    for (var i=0; i < 32; i++) {
        hashToField.msg[i] <== step_in[i];
    }
    signal Hm[2][2][k];
    for (var i=0; i < 2; i++) {
        for (var j=0; j < 2; j++) {
            for (var l=0; l < k; l++) {
                Hm[i][j][l] <== hashToField.result[i][j][l];
            }
        }
    }

    // component aggregateVerify = AggregateVerify(b, n, k);

    // for (var i=0; i < b; i++) {
    //     aggregateVerify.pubkeybits[i] <== pubkeybits[i];
    //     for (var j=0; j < k; j++) {
    //         aggregateVerify.pubkeys[i][0][j] <== pubkeys[i][0][j];
    //         aggregateVerify.pubkeys[i][1][j] <== pubkeys[i][1][j];
    //     }
    // }
    // for (var j=0; j < k; j++) {
    //     aggregateVerify.signature[0][0][j] <== signature[0][0][j];
    //     aggregateVerify.signature[0][1][j] <== signature[0][1][j];
    //     aggregateVerify.signature[1][0][j] <== signature[1][0][j];
    //     aggregateVerify.signature[1][1][j] <== signature[1][1][j];
    //     aggregateVerify.Hm[0][0][j] <== Hm[0][0][j];
    //     aggregateVerify.Hm[0][1][j] <== Hm[0][1][j];
    //     aggregateVerify.Hm[1][0][j] <== Hm[1][0][j];
    //     aggregateVerify.Hm[1][1][j] <== Hm[1][1][j];
    // }

    component sszSyncCommittee = SSZPhase0SyncCommittee(b);
    for (var i=0; i < b; i++) {
        for (var j=0; j < 48; j++) {
            sszSyncCommittee.pubkeys[i][j] <== pubkeyHex[i][j];
        }
    }
    for (var j=0; j < 48; j++) {
        sszSyncCommittee.aggregate_pubkey[j] <== aggregatePubkeyHex[j];
    }

    for (var j=0; j < 32; j++) {
        step_out[j] <== sszSyncCommittee.out[j];
    }
}

component main { public [step_in] } = CommitteeRotationStep(16, 55, 7);