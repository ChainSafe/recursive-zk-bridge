#!/bin/bash
PHASE1_FILE=powersOfTau28_hez_final_26.ptau
BUILD_DIR=./build
PHASE1=$BUILD_DIR/$PHASE1_FILE
CIRCUIT_NAME=committee_rotation_step
TEST_DIR=./test
OUTPUT_DIR="$BUILD_DIR"/"$CIRCUIT_NAME"_js

if [ -f $PHASE1 ]; then
    echo "$PHASE1_FILE already exists. Skipping."
else
    echo "Downloading $PHASE1_FILE"
    wget https://hermez.s3-eu-west-1.amazonaws.com/$PHASE1_FILE -P ./
fi


if [ ! -d "$BUILD_DIR" ]; then
    echo "No build directory found. Creating build directory..."
    mkdir -p "$BUILD_DIR"
fi

#echo "****COMPILING CIRCUIT****"
#start=`date +%s`
#circom "./circuits/$CIRCUIT_NAME.circom" --O1 --r1cs --sym --c --output "$BUILD_DIR" -l ./node_modules/circomlib/
#sleep 10
#end=`date +%s`
#echo "DONE ($((end-start))s)"

echo "****Executing witness generation****"
start=`date +%s`
node ./"$OUTPUT_DIR"/generate_witness.js ./"$OUTPUT_DIR"/$CIRCUIT_NAME.wasm "$TEST_DIR"/input_step_0.json ./"$OUTPUT_DIR"/witness.wtns
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****Converting witness to json****"
start=`date +%s`
npx snarkjs wej ./"$OUTPUT_DIR"/witness.wtns ./"$OUTPUT_DIR"/witness.json
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****GENERATING ZKEY 0****"
start=`date +%s`
npx --trace-gc --trace-gc-ignore-scavenger --max-old-space-size=2048000 --initial-old-space-size=2048000 --no-global-gc-scheduling --no-incremental-marking --max-semi-space-size=1024 --initial-heap-size=2048000 --expose-gc snarkjs zkey new "$BUILD_DIR"/"$CIRCUIT_NAME".r1cs "$PHASE1" "$OUTPUT_DIR"/"$CIRCUIT_NAME"_p1.zkey
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****CONTRIBUTE TO PHASE 2 CEREMONY****"
start=`date +%s`
npx snarkjs zkey contribute "$OUTPUT_DIR"/"$CIRCUIT_NAME"_p1.zkey "$OUTPUT_DIR"/"$CIRCUIT_NAME"_p2.zkey -n="First phase2 contribution" -e="some random text for entropy"
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****VERIFYING FINAL ZKEY****"
start=`date +%s`
npx --trace-gc --trace-gc-ignore-scavenger --max-old-space-size=2048000 --initial-old-space-size=2048000 --no-global-gc-scheduling --no-incremental-marking --max-semi-space-size=1024 --initial-heap-size=2048000 --expose-gc npx snarkjs zkey verify "$BUILD_DIR"/"$CIRCUIT_NAME".r1cs "$PHASE1" "$OUTPUT_DIR"/"$CIRCUIT_NAME"_p2.zkey
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****EXPORTING VKEY****"
start=`date +%s`
npx snarkjs zkey export verificationkey "$OUTPUT_DIR"/"$CIRCUIT_NAME"_p2.zkey "$OUTPUT_DIR"/"$CIRCUIT_NAME"_vkey.json
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****GENERATING PROOF FOR SAMPLE INPUT****"
start=`date +%s`
npx snarkjs groth16 prove "$OUTPUT_DIR"/"$CIRCUIT_NAME"_p2.zkey "$OUTPUT_DIR"/witness.wtns "$OUTPUT_DIR"/"$CIRCUIT_NAME"_proof.json "$OUTPUT_DIR"/"$CIRCUIT_NAME"_public.json
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****VERIFYING PROOF FOR SAMPLE INPUT****"
start=`date +%s`
npx snarkjs groth16 verify "$OUTPUT_DIR"/"$CIRCUIT_NAME"_vkey.json "$OUTPUT_DIR"/"$CIRCUIT_NAME"_public.json "$OUTPUT_DIR"/"$CIRCUIT_NAME"_proof.json
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****EXPORTING SOLIDITY SMART CONTRACT****"
start=`date +%s`
npx snarkjs zkey export solidityverifier "$OUTPUT_DIR"/"$CIRCUIT_NAME"_p2.zkey "$OUTPUT_DIR"/verifier.sol
end=`date +%s`
echo "DONE ($((end-start))s)"
