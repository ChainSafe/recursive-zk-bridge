mod mock_generator;

use crate::mock_generator::generate_mock_inputs;
pub use crate::mock_generator::SlotCommitteeRotation;

#[test]
fn generate() {
    generate_mock_inputs::<16>(100, 2, "../input_nova_bls_verify.json")
}
