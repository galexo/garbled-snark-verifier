// Settlement-scale anchored garbling: run the seed-anchored garbler over the
// Groth16 verifier's own 10.4B gates and report garbling wall time and F bytes.
//
// These are the two setup numbers that were previously derived from Bristol
// circuits (a 2.30-2.41x F ratio and a 2.05-2.46x time factor). Running the
// real thing turns them into measurements.
//
// F is COUNTED, not written: the payload is 32 B per AND leaf and is fully
// determined by the leaf count, so writing ~87 GB would only add I/O to the
// timing. K-bounding is off here, so this measures the AND-anchor term exactly;
// the XOR-anchor term is a separate parameter (E4 measured the promotion rate).
//
// Usage: anchored_garble [--plain] [--capacity N]

use std::env;

use garbled_snark_verifier::{
    ark,
    ark::{CircuitSpecificSetupSNARK, SNARK, UniformRand},
    circuit::{
        CiphertextHandler, CircuitBuilder, StreamingResult,
        modes::garble_mode::GarbleMode,
    },
    garbled_groth16,
    hashers::AesCcrGateHasher,
    test_utils::DummyCircuit,
    GarbledWire, S,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

const K_CONSTRAINTS: usize = 6;

/// Counts ciphertexts instead of storing ~43 GB of them.
#[derive(Default)]
struct CountingSink {
    n: u64,
}

impl CiphertextHandler for CountingSink {
    type Result = u64;
    fn handle(&mut self, _ct: S) {
        self.n += 1;
    }
    fn finalize(self) -> u64 {
        self.n
    }
}

fn arg(args: &[String], name: &str, default: usize) -> usize {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let plain = args.iter().any(|a| a == "--plain");
    let capacity = arg(&args, "--capacity", 160_000);

    eprintln!(
        "settlement-scale garble: {}, capacity {capacity}",
        if plain { "PLAIN (unmodified scheme)" } else { "ANCHORED" }
    );

    let mut rng = ChaCha20Rng::seed_from_u64(12345);
    let circuit = DummyCircuit::<ark::Fr> {
        a: Some(ark::Fr::rand(&mut rng)),
        b: Some(ark::Fr::rand(&mut rng)),
        num_variables: 10,
        num_constraints: 1 << K_CONSTRAINTS,
    };
    let (_pk, vk) = ark::Groth16::<ark::Bn254>::setup(circuit, &mut rng).unwrap();

    let inputs = garbled_groth16::GarblerInput { public_params_len: 1, vk: vk.clone() };

    let mut mode: GarbleMode<AesCcrGateHasher, CountingSink> =
        GarbleMode::new(capacity, 12345, CountingSink::default());
    if !plain {
        mode = mode.with_anchoring([7u8; 32]);
    }

    let t = std::time::Instant::now();
    let result: StreamingResult<GarbleMode<AesCcrGateHasher, CountingSink>, _, GarbledWire> =
        CircuitBuilder::run_streaming(inputs, mode, garbled_groth16::verify);
    let wall = t.elapsed();

    let n_ct = result.ciphertext_handler_result;

    println!();
    println!("=== settlement-scale garble ({}) ===", if plain { "plain" } else { "anchored" });
    println!("ciphertexts (AND gates) : {n_ct}");
    println!("F bytes, tables only    : {} ({:.2} GB)", n_ct * 16, (n_ct * 16) as f64 / 1e9);
    if !plain {
        println!("F bytes, anchored       : {} ({:.2} GB)", n_ct * 32, (n_ct * 32) as f64 / 1e9);
    }
    println!("garbling wall           : {:.1} s", wall.as_secs_f64());
    println!("rate                    : {:.2}M gates/s", n_ct as f64 / wall.as_secs_f64() / 1e6);
}
