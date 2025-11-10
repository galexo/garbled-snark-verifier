use std::{path::PathBuf, time::Instant};

use bincode::config;
use sp1_core_executor::SP1ContextBuilder;
use sp1_core_machine::io::SP1Stdin;
use sp1_prover::{
    Groth16Bn254Proof, SP1Prover, SP1PublicValues, build, components::CpuProverComponents,
};
use sp1_stark::SP1ProverOpts;
use tracing::{info, instrument};

#[path = "../sp1-soldering-program/src/types.rs"]
mod types;

pub use types::{Sha256Commit, SolderedLabelsData as SolderedLabels};

use crate::{GarbledWire, S, circuit::CircuitInput};

/// Trait for inputs that can be soldered with deltas to create derived instances
pub trait SolderInput: CircuitInput {
    /// Apply per-wire deltas to create a new instance
    fn solder(&self, per_wire_deltas: &[(S, S)]) -> Self;
}

/// Returns the compiled soldering guest ELF bytes.
pub fn elf() -> &'static [u8] {
    include_bytes!(env!("SP1_ELF_sp1-soldering-guest"))
}

pub struct SolderingProof {
    pub proof: Groth16Bn254Proof,
    pub deltas: Vec<Vec<(u128, u128)>>,
}

/// Serializes the wires input into the format expected by the SP1 guest.
pub fn serialize_wires_input(
    input: &types::WiresInput,
) -> Result<Vec<u8>, bincode::error::EncodeError> {
    bincode::encode_to_vec(input, config::standard())
}

/// Serializes the soldering public parameters.
pub fn serialize_public_params(
    params: &types::SolderedLabelsData,
) -> Result<Vec<u8>, bincode::error::EncodeError> {
    bincode::encode_to_vec(params, config::standard())
}

/// Deserializes the soldering public parameters emitted by the SP1 guest.
pub fn deserialize_public_params(
    bytes: &[u8],
) -> Result<types::SolderedLabelsData, bincode::error::DecodeError> {
    let (decoded, _len) =
        bincode::decode_from_slice::<types::SolderedLabelsData, _>(bytes, config::standard())?;
    Ok(decoded)
}

fn groth16_artifacts_dir() -> PathBuf {
    std::env::var("SP1_GROTH16_CIRCUIT_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| dirs::home_dir().unwrap().join(".sp1/circuits/groth16"))
        .join(sp1_prover::SP1_CIRCUIT_VERSION.trim())
}

#[instrument(skip_all)]
pub fn prove_soldering(instances: Vec<Vec<GarbledWire>>, nonce: u128) -> SolderingProof {
    let input = types::WiresInput {
        instances_wires: instances
            .into_iter()
            .map(|instance| {
                instance
                    .into_iter()
                    .map(|gw| (gw.label0.to_u128(), gw.label1.to_u128()))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>(),
        nonce,
    };

    let prover = SP1Prover::<CpuProverComponents>::new();

    let input_bytes = serialize_wires_input(&input).expect("failed to serialize wires input");

    let mut stdin = SP1Stdin::new();
    stdin.write(&input_bytes); // example input

    // 3. Create proving/verification keys.
    let (_pk, pk_device, program, vk) = prover.setup(elf());

    // 4. Optional: customise proving opts/context.
    let opts = SP1ProverOpts::default();
    let context = SP1ContextBuilder::default().build();

    // 5. Prove the core execution.
    let prove_time = Instant::now();
    let core_proof = prover
        .prove_core(&pk_device, program, &stdin, opts, context)
        .unwrap();
    info!("Proved in {}", prove_time.elapsed().as_secs());
    let public_values = core_proof.public_values.clone();

    info!("Raw data from program is {public_values:?}");

    let data = deserialize_public_params(public_values.as_slice())
        .expect("failed to deserialize `SolderedLabelsData`");

    info!("Data from program is {data:?}");

    // 6. Compress → shrink → wrap (PLONK/STARK outer proof).
    let compress_time = Instant::now();
    let deferred = stdin.proofs.iter().map(|(p, _)| p.clone()).collect();
    let reduced = prover.compress(&vk, core_proof, deferred, opts).unwrap();
    let shrunk = prover.shrink(reduced, opts).unwrap();
    let wrapped = prover.wrap_bn254(shrunk, opts).unwrap();
    info!("Compressed in {}", compress_time.elapsed().as_secs());

    // 7. Build/download Groth16 artifacts and produce Groth16 proof.
    let wrap_time = Instant::now();

    let artifacts = if sp1_prover::build::sp1_dev_mode() {
        build::try_build_groth16_bn254_artifacts_dev(&wrapped.vk, &wrapped.proof)
    } else {
        groth16_artifacts_dir()
    };

    let groth16_proof = prover.wrap_groth16_bn254(wrapped, &artifacts);
    info!("Wrapped in {}", wrap_time.elapsed().as_secs());

    SolderingProof {
        proof: groth16_proof,
        deltas: data.deltas,
    }
}

#[instrument(skip_all)]
pub fn verify_soldering(
    proof: SolderingProof,
    base_commitment: Vec<(Sha256Commit, Sha256Commit)>,
    base_nonce_commitment: Vec<(Sha256Commit, Sha256Commit)>,
    nonce: u128,
    commitments: Vec<Vec<(Sha256Commit, Sha256Commit)>>,
) -> bool {
    info!("start");
    let SolderingProof { proof, deltas } = proof;

    let pp = types::SolderedLabelsData {
        deltas,
        base_commitment,
        base_nonce_commitment,
        nonce,
        commitments,
    };

    let input_bytes = serialize_public_params(&pp).expect("failed to serialize public params");

    let prover = SP1Prover::<CpuProverComponents>::new();
    let (_pk, _pk_device, _program, vk) = prover.setup(elf());

    let artifacts = groth16_artifacts_dir();

    prover
        .verify_groth16_bn254(
            &proof,
            &vk,
            &SP1PublicValues::from(&input_bytes[..]),
            &artifacts,
        )
        .unwrap();

    info!("end");

    true
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use rand::Rng;
    use sp1_core_executor::{ExecutionError, ExecutionReport, SP1Context};
    use test_log::test;
    use tracing::info;

    use super::*;
    use crate::S;

    /// Hash a label to create a commitment (internal helper for tests)
    fn hash_label(label: u128) -> Sha256Commit {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(label.to_be_bytes());
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        bytes
    }

    /// Build the expected public parameters for a set of raw wire labels.
    fn build_expected_public_params(
        raw_instances: &[Vec<(u128, u128)>],
        nonce: u128,
    ) -> SolderedLabels {
        let (base, rest) = raw_instances
            .split_first()
            .expect("at least one instance required");

        let mut base_commitment = Vec::with_capacity(base.len());
        let mut base_nonce_commitment = Vec::with_capacity(base.len());

        for &(label0, label1) in base {
            base_commitment.push((hash_label(label0), hash_label(label1)));
            base_nonce_commitment.push((hash_label(label0 ^ nonce), hash_label(label1 ^ nonce)));
        }

        let mut commitments = Vec::with_capacity(rest.len());
        let mut deltas = Vec::with_capacity(rest.len());

        for instance in rest {
            let mut instance_commitment = Vec::with_capacity(instance.len());
            let mut instance_deltas = Vec::with_capacity(instance.len());

            for ((base0, base1), (label0, label1)) in base.iter().zip(instance.iter()) {
                instance_commitment.push((hash_label(*label0), hash_label(*label1)));
                instance_deltas.push((base0 ^ label0, base1 ^ label1));
            }

            commitments.push(instance_commitment);
            deltas.push(instance_deltas);
        }

        SolderedLabels {
            deltas,
            base_commitment,
            base_nonce_commitment,
            nonce,
            commitments,
        }
    }

    #[test]
    #[ignore]
    fn test_core_public_params_roundtrip() {
        use rand::{Rng, SeedableRng, rngs::StdRng};

        let wires = 1;
        let instances = 1;

        let mut rng = StdRng::seed_from_u64(42);
        let nonce: u128 = rng.r#gen();
        let delta: u128 = rng.r#gen::<u128>() | 1;

        let mut raw_instances = Vec::with_capacity(1 + instances);

        for _ in 0..=instances {
            let mut raw_labels = Vec::with_capacity(wires);

            for _ in 0..wires {
                let label0: u128 = rng.r#gen();
                let label1: u128 = label0 ^ delta;
                raw_labels.push((label0, label1));
            }

            raw_instances.push(raw_labels);
        }

        let input = types::WiresInput {
            instances_wires: raw_instances.clone(),
            nonce,
        };

        let input_bytes =
            serialize_wires_input(&input).expect("failed to serialize wires input for core test");

        let mut stdin = SP1Stdin::new();
        stdin.write(&input_bytes);

        let prover = SP1Prover::<CpuProverComponents>::new();
        let (_pk, pk_device, program, _vk) = prover.setup(elf());
        let opts = SP1ProverOpts::default();
        let context = SP1ContextBuilder::default().build();

        let core_proof = prover
            .prove_core(&pk_device, program, &stdin, opts, context)
            .expect("core proving failed");

        let public_values = core_proof.public_values;

        let recovered =
            deserialize_public_params(public_values.as_slice()).expect("failed to deserialize pp");
        let expected = build_expected_public_params(&raw_instances, nonce);

        assert_eq!(
            recovered, expected,
            "deserialized public params differ from expected output"
        );

        let reserialized =
            serialize_public_params(&recovered).expect("failed to reserialize public params");
        let decoded = deserialize_public_params(&reserialized)
            .expect("failed to deserialize reserialized params");
        assert_eq!(
            decoded, recovered,
            "reserialized params differ from original deserialize output"
        );
    }

    fn execute_only(
        elf: &[u8],
        stdin: &SP1Stdin,
    ) -> Result<(SP1PublicValues, ExecutionReport), ExecutionError> {
        let prover = SP1Prover::<CpuProverComponents>::new();

        // Mirror the defaults from the SDK.
        let mut ctx_builder = SP1Context::builder();
        ctx_builder.calculate_gas(true);
        let context = ctx_builder.build();

        let (public_values, _digest, report) = prover.execute(elf, stdin, context)?;
        Ok((public_values, report))
    }

    #[test]
    fn execute_guest_emits_expected_public_values() {
        use rand::{Rng, SeedableRng, rngs::StdRng};

        let wires = 1019;
        let total_instances = 7;
        let additional_instances = total_instances - 1;

        let mut rng = StdRng::seed_from_u64(1337);
        let nonce: u128 = rng.r#gen();
        let delta: u128 = rng.r#gen::<u128>() | 1;

        let mut raw_instances = Vec::with_capacity(total_instances);

        for _ in 0..=additional_instances {
            let mut raw_labels = Vec::with_capacity(wires);

            for _ in 0..wires {
                let label0: u128 = rng.r#gen();
                let label1: u128 = label0 ^ delta;
                raw_labels.push((label0, label1));
            }

            raw_instances.push(raw_labels);
        }

        let input = types::WiresInput {
            instances_wires: raw_instances.clone(),
            nonce,
        };

        let input_bytes =
            serialize_wires_input(&input).expect("failed to serialize wires input for execution");

        let mut stdin = SP1Stdin::new();
        stdin.write_slice(&input_bytes);

        let (public_values, report) =
            execute_only(elf(), &stdin).expect("guest execution should succeed");

        assert!(
            report.total_instruction_count() > 0,
            "execution report should record instructions"
        );

        let recovered = deserialize_public_params(public_values.as_slice())
            .expect("failed to decode public params");
        let expected = build_expected_public_params(&raw_instances, nonce);
        assert_eq!(
            recovered, expected,
            "unexpected public params from execution"
        );
    }

    /// Helper function to test prove and verify with configurable parameters
    fn test_soldering_with_params(wires: usize, instances: usize) {
        use rand::Rng;

        let mut rng = rand::thread_rng();
        let nonce: u128 = rng.r#gen();

        // Generate garbled wires with consistent delta
        let delta: u128 = rng.r#gen::<u128>() | 1; // Ensure odd for Free-XOR

        let mut all_instances = Vec::with_capacity(1 + instances);
        let mut all_raw_labels = Vec::with_capacity(1 + instances);

        // Generate all instances (base + additional)
        for i in 0..=instances {
            let mut instance: Vec<GarbledWire> = Vec::with_capacity(wires);
            let mut raw_labels: Vec<(u128, u128)> = Vec::with_capacity(wires);

            for _ in 0..wires {
                let label0: u128 = rng.r#gen();
                let label1: u128 = label0 ^ delta;

                instance.push(GarbledWire {
                    label0: S::from_u128(label0),
                    label1: S::from_u128(label1),
                });

                raw_labels.push((label0, label1));
            }

            all_instances.push(instance);
            all_raw_labels.push(raw_labels);

            if i == 0 {
                info!("Generated base instance: {} wires", wires);
            }
        }

        info!("Generated {} additional instances", instances);

        // Prove using the public API
        let prove_start = Instant::now();
        let proof = prove_soldering(all_instances.clone(), nonce);
        info!(
            "Total proving time: {} seconds",
            prove_start.elapsed().as_secs()
        );

        // Now create the commitments exactly as the SP1 program does
        let SolderedLabels {
            base_commitment,
            base_nonce_commitment,
            commitments,
            ..
        } = build_expected_public_params(&all_raw_labels, nonce);

        // Verify using the public API
        let verify_start = Instant::now();
        let is_valid = verify_soldering(
            proof,
            base_commitment,
            base_nonce_commitment,
            nonce,
            commitments,
        );

        info!(
            "Verification time: {} ms",
            verify_start.elapsed().as_millis()
        );

        assert!(is_valid, "Proof verification failed");
        println!("Groth16 proof generated and verified successfully!");
    }

    #[test]
    fn test_serialization_consistency() {
        use rand::{SeedableRng, rngs::StdRng};

        // Use a fixed seed for deterministic output
        let mut rng = StdRng::seed_from_u64(12345);

        // Generate a small deterministic set of parameters
        let wires = 3;
        let instances = 2;
        let nonce: u128 = rng.r#gen();
        let delta: u128 = rng.r#gen::<u128>() | 1;

        let mut raw_instances = Vec::with_capacity(1 + instances);

        for _ in 0..=instances {
            let mut raw_labels = Vec::with_capacity(wires);

            for _ in 0..wires {
                let label0: u128 = rng.r#gen();
                let label1: u128 = label0 ^ delta;
                raw_labels.push((label0, label1));
            }

            raw_instances.push(raw_labels);
        }

        let expected_params = build_expected_public_params(&raw_instances, nonce);
        let serialized =
            serialize_public_params(&expected_params).expect("failed to serialize public params");

        const EXPECTED_BYTES: &[u8] = &[
            2, 3, 254, 84, 109, 203, 40, 102, 41, 191, 75, 209, 57, 43, 101, 15, 149, 7, 76, 254,
            84, 109, 203, 40, 102, 41, 191, 75, 209, 57, 43, 101, 15, 149, 7, 76, 254, 34, 19, 42,
            254, 185, 101, 187, 5, 27, 16, 105, 61, 97, 2, 116, 31, 254, 34, 19, 42, 254, 185, 101,
            187, 5, 27, 16, 105, 61, 97, 2, 116, 31, 254, 182, 21, 249, 25, 222, 31, 52, 60, 218,
            31, 155, 201, 149, 3, 99, 101, 254, 182, 21, 249, 25, 222, 31, 52, 60, 218, 31, 155,
            201, 149, 3, 99, 101, 3, 254, 251, 139, 135, 213, 90, 245, 72, 4, 83, 173, 70, 62, 202,
            128, 51, 35, 254, 251, 139, 135, 213, 90, 245, 72, 4, 83, 173, 70, 62, 202, 128, 51,
            35, 254, 25, 243, 32, 205, 28, 208, 76, 187, 21, 242, 94, 157, 189, 2, 174, 116, 254,
            25, 243, 32, 205, 28, 208, 76, 187, 21, 242, 94, 157, 189, 2, 174, 116, 254, 198, 24,
            113, 143, 100, 186, 14, 195, 176, 136, 142, 128, 71, 47, 129, 213, 254, 198, 24, 113,
            143, 100, 186, 14, 195, 176, 136, 142, 128, 71, 47, 129, 213, 3, 74, 18, 227, 81, 109,
            20, 32, 81, 167, 205, 13, 107, 67, 217, 120, 181, 127, 52, 96, 68, 40, 210, 214, 23,
            163, 182, 248, 147, 207, 165, 170, 180, 157, 50, 197, 242, 108, 168, 242, 228, 103,
            195, 51, 222, 137, 193, 220, 51, 118, 142, 201, 216, 117, 198, 253, 115, 15, 9, 231,
            32, 20, 206, 236, 212, 52, 115, 217, 150, 130, 99, 177, 29, 236, 242, 123, 57, 32, 136,
            1, 184, 22, 46, 13, 231, 47, 31, 236, 250, 196, 150, 145, 201, 122, 16, 94, 215, 6,
            254, 174, 197, 109, 209, 241, 75, 67, 112, 225, 212, 184, 230, 42, 62, 159, 61, 206,
            187, 204, 17, 177, 112, 35, 141, 151, 71, 91, 112, 35, 231, 69, 141, 240, 41, 145, 21,
            211, 40, 81, 45, 12, 65, 130, 174, 101, 247, 159, 51, 227, 198, 206, 136, 249, 89, 46,
            120, 2, 137, 145, 158, 69, 111, 205, 218, 100, 177, 142, 209, 92, 148, 117, 159, 45,
            15, 236, 179, 120, 132, 43, 129, 157, 203, 15, 21, 186, 203, 75, 252, 169, 254, 181,
            184, 157, 249, 3, 107, 214, 146, 201, 93, 102, 119, 125, 224, 42, 161, 46, 2, 0, 138,
            34, 151, 147, 122, 48, 53, 29, 82, 168, 222, 80, 62, 85, 161, 172, 38, 249, 241, 186,
            249, 141, 38, 79, 203, 41, 77, 219, 180, 195, 249, 125, 217, 205, 153, 90, 148, 2, 168,
            227, 243, 165, 21, 120, 255, 120, 156, 206, 231, 144, 215, 204, 209, 36, 24, 56, 150,
            7, 198, 194, 111, 8, 138, 125, 41, 93, 239, 41, 217, 249, 64, 17, 180, 217, 18, 84,
            217, 31, 41, 111, 126, 90, 58, 213, 36, 219, 148, 137, 101, 22, 52, 21, 117, 164, 139,
            203, 121, 118, 84, 216, 162, 213, 167, 130, 229, 103, 144, 203, 177, 108, 157, 126,
            207, 243, 54, 31, 120, 190, 154, 154, 11, 136, 18, 238, 144, 187, 97, 120, 192, 137,
            43, 207, 76, 79, 162, 77, 108, 228, 60, 38, 165, 2, 93, 49, 164, 42, 3, 238, 2, 222,
            220, 180, 233, 194, 154, 153, 197, 124, 142, 138, 148, 61, 17, 68, 45, 177, 153, 62,
            149, 142, 171, 221, 199, 185, 193, 130, 249, 159, 254, 86, 209, 93, 136, 38, 148, 81,
            78, 75, 84, 66, 238, 158, 221, 19, 226, 2, 3, 177, 86, 229, 61, 52, 32, 21, 65, 5, 188,
            104, 26, 189, 3, 83, 188, 30, 226, 128, 34, 158, 33, 184, 3, 65, 49, 201, 148, 223,
            142, 84, 161, 235, 34, 99, 16, 117, 213, 38, 19, 170, 21, 217, 78, 120, 174, 89, 28,
            127, 32, 196, 252, 25, 232, 56, 32, 181, 33, 186, 188, 159, 140, 200, 14, 13, 254, 55,
            104, 131, 173, 74, 130, 20, 71, 46, 245, 31, 50, 211, 164, 129, 132, 30, 2, 241, 61,
            91, 56, 36, 165, 54, 170, 109, 194, 146, 181, 136, 51, 172, 28, 151, 68, 169, 100, 48,
            69, 40, 105, 214, 86, 216, 20, 196, 8, 243, 168, 176, 126, 193, 125, 156, 84, 204, 237,
            125, 107, 80, 79, 122, 175, 57, 198, 200, 93, 82, 47, 144, 214, 184, 245, 34, 31, 178,
            61, 133, 199, 93, 180, 255, 166, 28, 130, 61, 51, 201, 125, 12, 160, 123, 237, 25, 239,
            18, 98, 160, 0, 34, 24, 198, 9, 254, 241, 131, 162, 31, 17, 105, 243, 249, 143, 16, 35,
            53, 174, 184, 224, 98, 39, 90, 193, 91, 94, 3, 28, 160, 248, 247, 58, 170, 100, 252,
            228, 229, 154, 252, 113, 9, 99, 206, 97, 73, 193, 16, 240, 168, 7, 228, 210, 164, 135,
            23, 70, 231, 72, 136, 34, 107, 215, 205, 168, 221, 123, 130, 192, 51, 69, 125, 30, 61,
            188, 144, 56, 186, 181, 178, 191, 109, 191, 20, 119, 59, 192, 5, 233, 27, 167, 125,
            238, 84, 195, 236, 209, 242, 248, 194, 79, 249, 154, 113, 122, 218, 111, 8, 241, 234,
            0, 97, 139, 177, 172, 92, 236, 112, 21, 250, 17, 58, 51, 51, 148, 175, 232, 127, 126,
            8, 48, 47, 231, 235, 35, 113, 149, 230, 173, 101, 255, 137, 21, 31, 236, 142, 203, 141,
            146, 103, 155, 154, 239, 35, 63, 116, 186, 79, 87, 37, 34, 195, 28, 119, 236, 222, 6,
            31, 51, 174, 117, 102, 221, 34, 156, 82, 99, 78, 146, 62, 177, 206, 117, 180, 130, 175,
            133, 105, 219, 168, 207, 6, 167, 15, 148, 205, 157, 184, 96, 122, 180, 101, 109, 57,
            216, 64, 29, 179, 224, 27, 93, 222, 109, 25, 219, 131, 50, 157, 36, 148,
        ];

        assert_eq!(serialized.as_slice(), EXPECTED_BYTES);

        // Also verify deserialization works correctly
        let deserialized = deserialize_public_params(&serialized).expect("failed to deserialize");
        assert_eq!(deserialized, expected_params);
    }

    #[test]
    #[ignore] // Run with: cargo test test_soldering_quick -- --ignored
    fn test_soldering_quick() {
        println!("Running quick soldering test with minimal parameters (1 wire, 1 instance)");
        println!("This test should complete in a few seconds");
        test_soldering_with_params(1, 1);
    }

    #[test]
    #[ignore] // Run with: cargo test test_soldering_full -- --ignored
    fn test_soldering_full() {
        println!("Running full soldering test with real payload size (1019 wires, 6 instances)");
        println!("WARNING: This test takes approximately 74 minutes to complete!");
        test_soldering_with_params(1019, 6);
    }
}
