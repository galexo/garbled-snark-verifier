// Export a prefix of the REAL Groth16 verifier's gate-indexed topology, so a
// dispute can be run against the verifier's own gates and wiring rather than a
// synthetic stand-in.
//
// Usage: topo_export <out.bin> [--limit N] [--capacity N]

use std::{env, fs::File, io::BufWriter, sync::{Arc, Mutex}};

use garbled_snark_verifier::{
    ark,
    ark::{CircuitSpecificSetupSNARK, SNARK, UniformRand},
    circuit::{CircuitBuilder, StreamingResult, modes::{TopoExportMode, TopoStats}},
    garbled_groth16,
    test_utils::DummyCircuit,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use ark_ec::AffineRepr;

const K_CONSTRAINTS: usize = 6;

fn arg(args: &[String], name: &str, default: usize) -> usize {
    args.iter().position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let out_path = args.get(1).cloned().unwrap_or_else(|| "topo.bin".into());
    let limit = arg(&args, "--limit", 1_000_000) as u64;
    let capacity = arg(&args, "--capacity", 160_000);
    let skip = arg(&args, "--skip", 0) as u64;

    eprintln!("exporting {limit} gates from offset {skip} of the Groth16 verifier -> {out_path}");

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
    let inputs = garbled_groth16::VerifierInput {
        public: vec![c_val], a: proof.a.into_group(), b: proof.b.into_group(),
        c: proof.c.into_group(), vk: vk.clone(),
    };

    let handle = Arc::new(Mutex::new(TopoStats::default()));
    let w = BufWriter::with_capacity(1 << 22, File::create(&out_path).expect("create"));
    let mode = TopoExportMode::new(capacity, limit, skip, w, handle.clone());

    let t = std::time::Instant::now();
    let _r: StreamingResult<_, _, bool> =
        CircuitBuilder::run_streaming(inputs, mode, garbled_groth16::verify);
    let wall = t.elapsed();

    let s = *handle.lock().unwrap();
    println!("gates {} inputs {} and {} free {} other {} in {:.1}s",
             s.gates, s.inputs, s.and_gates, s.free_gates, s.nonfree_other,
             wall.as_secs_f64());
}
