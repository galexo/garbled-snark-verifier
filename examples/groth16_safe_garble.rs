// Demonstrates streaming garbling of a Groth16 verifier using the SafeGarbleMode
// (double-AES hasher). Run with:
//   RUST_LOG=info cargo run --example groth16_safe_garble --release

use std::{fmt::Write as _, time::Instant};

use garbled_snark_verifier::{
    AESAccumulatingHash, GarbledWire,
    ark::{self, CircuitSpecificSetupSNARK, SNARK, UniformRand},
    circuit::{CircuitBuilder, StreamingResult, modes::SafeGarbleMode},
    garbled_groth16,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use tracing::{info, info_span};

// Simple multiplicative circuit used to produce a valid Groth16 proof.
#[derive(Copy, Clone)]
struct DummyCircuit<F: ark::PrimeField> {
    pub a: Option<F>,
    pub b: Option<F>,
    pub num_variables: usize,
    pub num_constraints: usize,
}

impl<F: ark::PrimeField> ark::ConstraintSynthesizer<F> for DummyCircuit<F> {
    fn generate_constraints(
        self,
        cs: ark::ConstraintSystemRef<F>,
    ) -> Result<(), ark::SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(ark::SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(ark::SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            let a = self.a.ok_or(ark::SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(ark::SynthesisError::AssignmentMissing)?;
            Ok(a * b)
        })?;

        // pad witnesses
        for _ in 0..(self.num_variables - 3) {
            let _ =
                cs.new_witness_variable(|| self.a.ok_or(ark::SynthesisError::AssignmentMissing))?;
        }

        // repeat the same multiplicative constraint
        for _ in 0..self.num_constraints - 1 {
            cs.enforce_constraint(ark::lc!() + a, ark::lc!() + b, ark::lc!() + c)?;
        }

        // final no-op constraint keeps ark-relations happy
        cs.enforce_constraint(ark::lc!(), ark::lc!(), ark::lc!())?;
        Ok(())
    }
}

fn hash(inp: &impl AsRef<[u8]>) -> [u8; 32] {
    blake3::hash(inp.as_ref()).as_bytes().to_owned()
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut s, "{:02x}", byte);
    }
    s
}

const CAPACITY: usize = 150_000;

fn main() {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_ansi(false)
        .init();

    let garbling_seed = 12345u64;
    let k = 6; // 2^k constraints
    let mut rng = ChaCha20Rng::seed_from_u64(garbling_seed);
    let circuit = DummyCircuit::<ark::Fr> {
        a: Some(ark::Fr::rand(&mut rng)),
        b: Some(ark::Fr::rand(&mut rng)),
        num_variables: 10,
        num_constraints: 1 << k,
    };

    info!("Setting up Groth16 proof...");
    let (pk, vk) = ark::Groth16::<ark::Bn254>::setup(circuit, &mut rng).expect("setup");
    info!("Proof generated successfully");

    let inputs = garbled_groth16::GarblerInput {
        public_params_len: 1,
        vk: vk.clone(),
    };

    let garble_start = Instant::now();
    let garbling_result: StreamingResult<SafeGarbleMode<_>, _, GarbledWire> = {
        let _span = info_span!("garble").entered();
        CircuitBuilder::streaming_garbling(
            inputs.clone(),
            CAPACITY,
            garbling_seed,
            AESAccumulatingHash::default(),
            garbled_groth16::verify,
        )
    };
    info!("garbling: in {:.3}s", garble_start.elapsed().as_secs_f64());

    let GarbledWire { label0, label1 } = *garbling_result.output_labels();
    let ciphertext_hash = garbling_result.ciphertext_handler_result;
    let ciphertext_hash_hex = to_hex(&ciphertext_hash);

    // Produce a proof to show evaluator inputs hookup.
    let proof = ark::Groth16::<ark::Bn254>::prove(&pk, circuit, &mut rng).expect("prove");
    let public_param = vec![circuit.a.unwrap() * circuit.b.unwrap()];

    let input_labels = garbled_groth16::EvaluatorInput::new(
        public_param,
        proof,
        vk.clone(),
        garbling_result.input_wire_values.clone(),
    );

    info!(
        "SafeGarbleMode (double AES):\n  Label0: {:?}\n  Label1: {:?}\n  CiphertextHash: 0x{ciphertext_hash_hex}",
        label0, label1
    );

    info!(
        "Evaluator input prepared: output_label0_hash=0x{}, output_label1_hash=0x{}, input_labels={} wires",
        to_hex(&hash(&label0.to_bytes())),
        to_hex(&hash(&label1.to_bytes())),
        input_labels.public.iter().map(|w| w.0.len()).sum::<usize>()
            + input_labels.a.iter().count()
            + input_labels.b.x.iter().map(|fr| fr.0.len()).sum::<usize>()
            + input_labels.b.y.iter().map(|fr| fr.0.len()).sum::<usize>()
            + input_labels.c.iter().count()
    );
}
