// Item 2: does the verifier's component structure admit an O(1)
// gate-index -> descriptor mapping? Streams the Groth16 verifier and reports
// template count, instance spans, contiguity and nesting depth.
use std::{env, sync::{Arc, Mutex}};

use garbled_snark_verifier::{
    ark,
    ark::{CircuitSpecificSetupSNARK, SNARK, UniformRand},
    circuit::{CircuitBuilder, StreamingResult, modes::{ComponentStats, ComponentStatsMode}},
    garbled_groth16,
    test_utils::DummyCircuit,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use ark_ec::AffineRepr;

fn main() {
    let args: Vec<String> = env::args().collect();
    let capacity = args.iter().position(|a| a == "--capacity")
        .and_then(|i| args.get(i+1)).and_then(|v| v.parse().ok()).unwrap_or(160_000);

    let mut rng = ChaCha20Rng::seed_from_u64(12345);
    let circuit = DummyCircuit::<ark::Fr> {
        a: Some(ark::Fr::rand(&mut rng)), b: Some(ark::Fr::rand(&mut rng)),
        num_variables: 10, num_constraints: 1 << 6,
    };
    let (pk, vk) = ark::Groth16::<ark::Bn254>::setup(circuit, &mut rng).unwrap();
    let c_val = circuit.a.unwrap() * circuit.b.unwrap();
    let proof = ark::Groth16::<ark::Bn254>::prove(&pk, circuit, &mut rng).unwrap();
    let verify = garbled_groth16::VerifierInput {
        public: vec![c_val], a: proof.a.into_group(), b: proof.b.into_group(),
        c: proof.c.into_group(), vk: vk.clone(),
    };

    let handle = Arc::new(Mutex::new(ComponentStats::default()));
    let t = std::time::Instant::now();
    let _r: StreamingResult<ComponentStatsMode, _, bool> = CircuitBuilder::run_streaming(
        verify, ComponentStatsMode::new(capacity, handle.clone()), garbled_groth16::verify);
    let wall = t.elapsed();

    let s = handle.lock().unwrap().clone();
    println!("\n=== component structure of the Groth16 verifier ===");
    println!("gates                : {}", s.gates);
    println!("component instances  : {}", s.instances);
    println!("DISTINCT TEMPLATES   : {}", s.distinct_templates);
    println!("max nesting depth    : {}", s.max_depth);
    println!("gates per instance   : min {} max {} mean {:.1}", s.min_span, s.max_span, s.mean_span());
    println!("empty instances      : {}", s.empty_instances);
    println!("OVERLAPPING top-level: {}  (0 => contiguous, O(1) mapping possible)", s.overlapping_top);
    let mut v: Vec<_> = s.per_template.iter().map(|(k,n)| (*n, *k)).collect();
    v.sort_unstable_by(|a,b| b.0.cmp(&a.0));
    println!("top templates by instance count:");
    for (n, k) in v.iter().take(8) { println!("   {:>12} x  key {:02x?}", n, k); }
    println!("wall                 : {:.1} s", wall.as_secs_f64());
}
