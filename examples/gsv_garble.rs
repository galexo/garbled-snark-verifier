// Garble + evaluate a Boolean GC computing x^2, x^3, y^2, and xy.
// Run with:
//   Default (Swanky AES): `RUST_LOG=info cargo run --example gsv_garble --release`
//   Blake3:               `RUST_LOG=info cargo run --example gsv_garble --release -- --hasher blake3`

use std::{env, time::Instant};

use crossbeam::channel;
use garbled_snark_verifier::{
    EvaluatedWire, GarbledWire,
    ark::{self, PrimeField, UniformRand},
    circuit::{
        CircuitBuilder, StreamingResult,
        modes::{EvaluateMode, GarbleMode},
    },
    hashers::{AesCcrGateHasher, Blake3Hasher, GateHasher},
};
use num_bigint::BigUint;
use rand::{Rng, SeedableRng};
use rand_chacha::{ChaCha20Rng, ChaChaRng};
use tracing::info;

mod point_ops;
use point_ops::{
    OUTPUT_LABELS, PointEvalInput, PointInput, decode_outputs_from_bits, expected_outputs,
    point_ops_circuit,
};

const CAPACITY: usize = 500_000;

fn fq_to_string(v: &ark::Fq) -> String {
    BigUint::from(v.clone().into_bigint()).to_str_radix(10)
}

fn run_with_hasher<H: GateHasher + 'static>(garbling_seed: u64) {
    let mut rng = ChaCha20Rng::seed_from_u64(12345);
    let input = PointInput::new(ark::Fq::rand(&mut rng), ark::Fq::rand(&mut rng));
    let x_val = input.x.clone();
    let y_val = input.y.clone();
    let expected = expected_outputs(&x_val, &y_val);

    let (sender, receiver) = channel::unbounded();

    let garble_start = Instant::now();
    let garbling_result: StreamingResult<GarbleMode<H, _>, _, Vec<GarbledWire>> =
        CircuitBuilder::streaming_garbling_with_sender(
            input,
            CAPACITY,
            garbling_seed,
            sender,
            point_ops_circuit,
        );

    let StreamingResult {
        input_wire_values,
        true_wire_constant,
        false_wire_constant,
        gate_count,
        ..
    } = garbling_result;

    info!("garbling complete");
    info!("gate count: {}", gate_count);
    println!("garble_time_ms={}", garble_start.elapsed().as_millis());
    println!("gate_count={}", gate_count);
    let size_mib = (gate_count.nonfree_gate_count() as f64 * 16.0) / (1024.0 * 1024.0);
    println!("size_mib={:.2}", size_mib);

    let eval_input = PointEvalInput::new(x_val.clone(), y_val.clone(), input_wire_values);

    let gate_hasher = {
        let mut rng = ChaChaRng::seed_from_u64(garbling_seed);
        H::from_rng(&mut rng)
    };

    let true_wire = true_wire_constant.select(true).to_u128();
    let false_wire = false_wire_constant.select(false).to_u128();

    let eval_result: StreamingResult<EvaluateMode<H, _>, _, Vec<EvaluatedWire>> =
        CircuitBuilder::streaming_evaluation(
            eval_input,
            CAPACITY,
            true_wire,
            false_wire,
            gate_hasher,
            receiver,
            point_ops_circuit,
        );

    let eval_bits: Vec<bool> = eval_result.output_value.iter().map(|w| w.value).collect();
    let outputs = decode_outputs_from_bits(&eval_bits);
    assert_eq!(outputs, expected, "garbled evaluation mismatch");

    println!("\n=== INPUTS ===");
    println!("x: {}", fq_to_string(&x_val));
    println!("y: {}", fq_to_string(&y_val));
    println!("\n=== OUTPUTS ===");
    for (label, value) in OUTPUT_LABELS.iter().zip(outputs.iter()) {
        println!("{}: {}", label, fq_to_string(value));
    }
}

fn main() {
    // Initialize logging (default to info if RUST_LOG not set)
    garbled_snark_verifier::init_tracing();

    let garbling_seed: u64 = rand::thread_rng().r#gen();

    // Simple parser for `--hasher <name>` or `--hasher=<name>`; defaults to Swanky AES
    let mut hasher_choice: Option<String> = None;
    let mut args = env::args().skip(1); // skip binary name
    while let Some(arg) = args.next() {
        if let Some(value) = arg.strip_prefix("--hasher=") {
            hasher_choice = Some(value.to_lowercase());
            break;
        } else if arg == "--hasher" {
            if let Some(value) = args.next() {
                hasher_choice = Some(value.to_lowercase());
            }
            break;
        }
    }

    match hasher_choice.as_deref() {
        Some("blake3") => {
            info!("Using Blake3 hasher");
            run_with_hasher::<Blake3Hasher>(garbling_seed);
        }
        Some("swankyaes") | None => {
            info!("Using Swanky AES hasher");
            run_with_hasher::<AesCcrGateHasher>(garbling_seed);
        }
        Some(other) => {
            panic!(
                "Unknown hasher '{}'. Supported: aes/swankyaes, blake3. Defaulting to aes.",
                other
            );
        }
    }
}
