// E4: K-bounded anchor statistics on the real Groth16 verifier circuit.
//
// E1/E2/E3 were all parameterised by anchors_touched and topo_reads taken from
// the SHA-256 Bristol circuit standing in for the verifier. This measures them
// on the verifier's own 10.4B gates, in one streaming pass, so those results
// can be rescaled without re-proving anything.
//
// Usage: anchor_stats [--k N] [--capacity N]

use std::{
    env,
    sync::{Arc, Mutex},
};

use ark_ec::AffineRepr;
use garbled_snark_verifier::{
    ark,
    ark::{CircuitSpecificSetupSNARK, SNARK, UniformRand},
    circuit::{CircuitBuilder, StreamingResult, modes::{AnchorStats, AnchorStatsMode}},
    garbled_groth16,
    test_utils::DummyCircuit,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

const K_CONSTRAINTS: usize = 6;

fn arg(args: &[String], name: &str, default: usize) -> usize {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let k = arg(&args, "--k", 1024);
    let capacity = arg(&args, "--capacity", 160_000);

    eprintln!("E4: anchor statistics on the Groth16 verifier, K = {k}");

    let mut rng = ChaCha20Rng::seed_from_u64(12345);
    let circuit = DummyCircuit::<ark::Fr> {
        a: Some(ark::Fr::rand(&mut rng)),
        b: Some(ark::Fr::rand(&mut rng)),
        num_variables: 10,
        num_constraints: 1 << K_CONSTRAINTS,
    };
    let (pk, vk) = ark::Groth16::<ark::Bn254>::setup(circuit, &mut rng).unwrap();
    let c_val = circuit.a.unwrap() * circuit.b.unwrap();
    let proof = ark::Groth16::<ark::Bn254>::prove(&pk, circuit, &mut rng).unwrap();

    let verify = garbled_groth16::VerifierInput {
        public: vec![c_val],
        a: proof.a.into_group(),
        b: proof.b.into_group(),
        c: proof.c.into_group(),
        vk: vk.clone(),
    };

    let handle = Arc::new(Mutex::new(AnchorStats::default()));
    let t = std::time::Instant::now();
    let result: StreamingResult<AnchorStatsMode, _, bool> = CircuitBuilder::run_streaming(
        verify,
        AnchorStatsMode::new(capacity, k, handle.clone()),
        garbled_groth16::verify,
    );
    let elapsed = t.elapsed();

    let s = *handle.lock().unwrap();
    println!();
    println!("=== E4: Groth16 verifier, K = {k} ===");
    println!("gates seen          : {}", s.gates);
    println!("  non-free (AND)    : {}", s.nonfree_gates);
    println!("  free              : {}", s.free_gates);
    println!("promoted to anchors : {}", s.promoted);
    println!("max support held    : {} (bound is 2K = {})", s.max_support, 2 * k);
    println!();
    println!("ANCHORS  max/mean   : {} / {:.1}", s.max_anchors, s.mean_anchors());
    println!("XOR NODES max       : {}", s.max_xor_nodes);
    println!("TOPO READS max/mean : {} / {:.1}", s.max_reads, s.mean_reads());
    println!();
    println!("wall                : {:.1} s", elapsed.as_secs_f64());
    println!("verified            : {}", result.output_value);
}
