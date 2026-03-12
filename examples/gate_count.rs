// Gate-count example for a Boolean GC circuit computing x^2, x^3, y^2, and xy.

use std::env;

use garbled_snark_verifier::{
    Fp254Impl, FqWire,
    ark::{self, PrimeField, UniformRand},
    circuit::{CircuitBuilder, StreamingResult},
};
use num_bigint::BigUint;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

mod point_ops;
use point_ops::{
    OUTPUT_LABELS, PointInput, decode_outputs_from_bits, expected_outputs, point_ops_circuit,
};

// Human-readable number formatter
fn format_number(n: u64) -> String {
    if n >= 1_000_000_000 {
        format!("{:.1}B", n as f64 / 1_000_000_000.0)
    } else if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

const CAPACITY: usize = 500_000;

fn fq_to_string(v: &ark::Fq) -> String {
    BigUint::from(v.clone().into_bigint()).to_str_radix(10)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let json_output = args.iter().any(|a| a == "--json");
    if !json_output {
        println!(
            "Running gate-count example for x^2, x^3, y^2, xy (Fq {}-bit)",
            FqWire::N_BITS
        );
    }

    // Deterministic RNG for reproducibility
    let mut rng = ChaCha20Rng::seed_from_u64(12345);
    let input = PointInput::new(ark::Fq::rand(&mut rng), ark::Fq::rand(&mut rng));
    let x_val = input.x.clone();
    let y_val = input.y.clone();
    let expected = expected_outputs(&x_val, &y_val);

    let result: StreamingResult<_, _, Vec<bool>> =
        CircuitBuilder::streaming_execute(input, CAPACITY, point_ops_circuit);

    let outputs = decode_outputs_from_bits(&result.output_value);
    assert_eq!(outputs, expected, "circuit outputs mismatch");

    let total_gates = result.gate_count.total_gate_count();
    let nonfree_gates = result.gate_count.nonfree_gate_count();
    let free_gates = total_gates.saturating_sub(nonfree_gates);

    if json_output {
        let output_strings: Vec<String> = outputs.iter().map(fq_to_string).collect();
        let output = serde_json::json!({
            "field_bits": FqWire::N_BITS,
            "gate_count": {
                "nonfree": nonfree_gates,
                "nonfree_formatted": format_number(nonfree_gates),
                "free": free_gates,
                "free_formatted": format_number(free_gates),
                "total": total_gates,
                "total_formatted": format_number(total_gates),
                "breakdown": result.gate_count.0
            },
            "inputs": {
                "x": fq_to_string(&x_val),
                "y": fq_to_string(&y_val)
            },
            "outputs": {
                "x_sq": output_strings[0],
                "x_cu": output_strings[1],
                "y_sq": output_strings[2],
                "xy": output_strings[3]
            }
        });
        println!("{}", serde_json::to_string_pretty(&output).expect("json"));
    } else {
        println!("\n=== GATE COUNT ===");
        println!("non-free: {}", nonfree_gates);
        println!("free:     {}", free_gates);
        println!("total:    {}", total_gates);
        println!("\n=== INPUTS ===");
        println!("x: {}", fq_to_string(&x_val));
        println!("y: {}", fq_to_string(&y_val));
        println!("\n=== OUTPUTS ===");
        for (label, value) in OUTPUT_LABELS.iter().zip(outputs.iter()) {
            println!("{}: {}", label, fq_to_string(value));
        }
    }
}
