#!/bin/bash
PHASE1=~/=powersOfTau28_hez_final_16.ptau
BUILD_DIR=./build
CIRCUIT_NAME=aggregate_bls_verify
TEST_DIR=./test
OUTPUT_DIR="$BUILD_DIR"/"$CIRCUIT_NAME"_cpp

if [ ! -d "$BUILD_DIR" ]; then
    echo "No build directory found. Creating build directory..."
    mkdir -p "$BUILD_DIR"
fi

echo "****COMPILING CIRCUIT****"
circom "./circuits/$CIRCUIT_NAME.circom" --O1 --r1cs --sym --c --output "$BUILD_DIR"


# echo "****Running make to make witness generation binary****"
# make -C "$OUTPUT_DIR"

# echo "****Executing witness generation****"
# ./"$OUTPUT_DIR"/"$CIRCUIT_NAME" "$TEST_DIR"/input_aggregate_bls_verify_512.json witness.wtns

# echo "****Converting witness to json****"
# npx snarkjs wej "$OUTPUT_DIR"/witness.wtns "$OUTPUT_DIR"/witness.json

# echo "****GENERATING ZKEY 0****"
# npx --trace-gc --trace-gc-ignore-scavenger --max-old-space-size=2048000 --initial-old-space-size=2048000 --no-global-gc-scheduling --no-incremental-marking --max-semi-space-size=1024 --initial-heap-size=2048000 --expose-gc snarkjs zkey new "$BUILD_DIR"/"$CIRCUIT_NAME".r1cs "$PHASE1" "$OUTPUT_DIR"/"$CIRCUIT_NAME"_p1.zkey

# echo "****CONTRIBUTE TO PHASE 2 CEREMONY****"
# npx snarkjs zkey contribute "$OUTPUT_DIR"/"$CIRCUIT_NAME"_p1.zkey "$OUTPUT_DIR"/"$CIRCUIT_NAME"_p2.zkey -n="First phase2 contribution" -e="some random text for entropy"

# echo "****VERIFYING FINAL ZKEY****"
# npx --trace-gc --trace-gc-ignore-scavenger --max-old-space-size=2048000 --initial-old-space-size=2048000 --no-global-gc-scheduling --no-incremental-marking --max-semi-space-size=1024 --initial-heap-size=2048000 --expose-gc npx snarkjs zkey verify "$BUILD_DIR"/"$CIRCUIT_NAME".r1cs "$PHASE1" "$OUTPUT_DIR"/"$CIRCUIT_NAME"_p2.zkey

# echo "****EXPORTING VKEY****"
# npx snarkjs zkey export verificationkey "$OUTPUT_DIR"/"$CIRCUIT_NAME"_p2.zkey "$OUTPUT_DIR"/"$CIRCUIT_NAME"_vkey.json

# echo "****GENERATING PROOF FOR SAMPLE INPUT****"
# npx snarkjs groth16 prove "$OUTPUT_DIR"/"$CIRCUIT_NAME"_p2.zkey "$OUTPUT_DIR"/witness.wtns "$OUTPUT_DIR"/"$CIRCUIT_NAME"_proof.json "$OUTPUT_DIR"/"$CIRCUIT_NAME"_public.json

# echo "****VERIFYING PROOF FOR SAMPLE INPUT****"
# npx snarkjs groth16 verify "$OUTPUT_DIR"/"$CIRCUIT_NAME"_vkey.json "$OUTPUT_DIR"/"$CIRCUIT_NAME"_public.json "$OUTPUT_DIR"/"$CIRCUIT_NAME"_proof.json

# echo "****EXPORTING SOLIDITY SMART CONTRACT****"
# npx snarkjs zkey export solidityverifier "$OUTPUT_DIR"/"$CIRCUIT_NAME"_p2.zkey verifier.sol
