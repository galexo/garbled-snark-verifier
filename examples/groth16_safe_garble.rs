// Demonstrates streaming garbling of a Groth16 verifier with selectable gate and ciphertext hashers.
// Instances mode: single (default, 1 instance), cpu_count (parallel instances pinned to physical cores).
// Gate hasher options: blake3 (default), sha256, swankyaes.
// Ciphertext hasher options: aes (default), blake3, sha256, swankyaes.
// Run with e.g.:
//   RUST_LOG=info cargo run --example groth16_safe_garble --release -- \\
//     --instances cpu_count --gate-hasher blake3 --ciphertext-hasher blake3

use std::{env, fmt::Write as _, time::Instant};

use garbled_snark_verifier::{
    AESAccumulatingHash, GarbledWire, S,
    ark::{self, CircuitSpecificSetupSNARK, SNARK, UniformRand},
    circuit::{CiphertextHandler, CircuitBuilder, StreamingResult, modes::GarbleMode},
    garbled_groth16,
    hashers::{Blake3Hasher, GateHasher, HashWithGate, Sha256GateHasher},
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rayon::{ThreadPool, ThreadPoolBuilder, prelude::*};
use sha2::{Digest, Sha256};
use swanky_aes_hash::TweakableCircularCorrelationRobustHash;
use swanky_block::Block;
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

fn build_pinned_pool(n_threads: usize) -> ThreadPool {
    let chosen_cores = match core_affinity::get_core_ids() {
        Some(cores) if cores.len() >= 2 * n_threads => {
            cores.into_iter().step_by(2).take(n_threads).collect()
        }
        Some(cores) => cores.into_iter().take(n_threads).collect(),
        None => Vec::new(),
    };

    ThreadPoolBuilder::new()
        .num_threads(n_threads)
        .start_handler(move |thread_idx| {
            if let Some(core_id) = chosen_cores.get(thread_idx).cloned() {
                let _ = core_affinity::set_for_current(core_id);
            }
        })
        .build()
        .unwrap_or_else(|_| {
            ThreadPoolBuilder::new()
                .num_threads(n_threads)
                .build()
                .expect("failed to create fallback thread pool")
        })
}

#[derive(Clone, Debug, Default)]
struct SwankyAesHasher;

#[inline(always)]
fn swanky_gate_prf(label: S, gate_id: usize, domain: u8) -> S {
    // Domain-separate the two half-gates by tacking on the domain byte.
    let tweak = ((gate_id as u128) << 8) | domain as u128;
    let block = Block::from_array(label.to_bytes());
    let hashed = TweakableCircularCorrelationRobustHash::fixed_key().hash(block, tweak);

    // vectoreyes::U8x16 is a 16-byte block; transmute to a byte array.
    const _: [u8; 16] = [0u8; core::mem::size_of::<Block>()];
    let out: [u8; 16] = unsafe { core::mem::transmute(hashed) };
    S::from_bytes(out)
}

impl HashWithGate<2> for SwankyAesHasher {
    fn hash_with_gate(labels: &[S; 2], gate_id: usize) -> [S; 2] {
        [
            swanky_gate_prf(labels[0], gate_id, 0),
            swanky_gate_prf(labels[1], gate_id, 1),
        ]
    }
}

impl HashWithGate<1> for SwankyAesHasher {
    fn hash_with_gate(label: &[S; 1], gate_id: usize) -> [S; 1] {
        [swanky_gate_prf(label[0], gate_id, 0)]
    }
}

#[derive(Default)]
struct Blake3CiphertextHasher {
    hasher: blake3::Hasher,
}

impl garbled_snark_verifier::circuit::MultiCiphertextHandler<1> for Blake3CiphertextHasher {
    type Result = [u8; 32];

    fn handle(&mut self, cts: [S; 1]) {
        self.hasher.update(&cts[0].to_bytes());
    }

    fn finalize(self) -> Self::Result {
        let out = self.hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(out.as_slice());
        bytes
    }
}

#[derive(Default)]
struct Sha256CiphertextHasher {
    hasher: Sha256,
}

impl garbled_snark_verifier::circuit::MultiCiphertextHandler<1> for Sha256CiphertextHasher {
    type Result = [u8; 32];

    fn handle(&mut self, cts: [S; 1]) {
        self.hasher.update(cts[0].to_bytes());
    }

    fn finalize(self) -> Self::Result {
        let digest = self.hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }
}

struct SwankyCiphertextHasher {
    state: S,
    counter: u128,
}

impl Default for SwankyCiphertextHasher {
    fn default() -> Self {
        Self {
            state: S::ZERO,
            counter: 0,
        }
    }
}

impl garbled_snark_verifier::circuit::MultiCiphertextHandler<1> for SwankyCiphertextHasher {
    type Result = [u8; 16];

    fn handle(&mut self, cts: [S; 1]) {
        let mixed = self.state ^ &cts[0];
        let block = Block::from_array(mixed.to_bytes());
        let hashed = TweakableCircularCorrelationRobustHash::fixed_key().hash(block, self.counter);
        const _: [u8; 16] = [0u8; core::mem::size_of::<Block>()];
        let out: [u8; 16] = unsafe { core::mem::transmute(hashed) };
        self.state = S::from_bytes(out);
        self.counter = self.counter.wrapping_add(1);
    }

    fn finalize(self) -> Self::Result {
        self.state.to_bytes()
    }
}

fn run_with_hashers<
    H: GateHasher + Send + 'static,
    CTH: CiphertextHandler + Default + Send + 'static,
>(
    gate_hasher_label: &str,
    ct_hasher_label: &str,
    garbling_seed: u64,
    instance: usize,
) where
    <CTH as CiphertextHandler>::Result: Send + Eq + AsRef<[u8]>,
{
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
    let garbling_result: StreamingResult<GarbleMode<H, CTH>, _, GarbledWire> = {
        let _span = info_span!("garble", instance, seed = garbling_seed).entered();
        CircuitBuilder::streaming_garbling(
            inputs.clone(),
            CAPACITY,
            garbling_seed,
            CTH::default(),
            garbled_groth16::verify,
        )
    };
    info!("garbling: in {:.3}s", garble_start.elapsed().as_secs_f64());

    let GarbledWire { label0, label1 } = *garbling_result.output_labels();
    let ciphertext_hash = garbling_result.ciphertext_handler_result;
    let ciphertext_hash_hex = to_hex(ciphertext_hash.as_ref());

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
        "SafeGarbleMode (gate={gate_hasher_label}, ct={ct_hasher_label}):\n  Label0: {:?}\n  Label1: {:?}\n  CiphertextHash: 0x{ciphertext_hash_hex}",
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

struct CliArgs {
    instances: String,
    gate_hasher: String,
    ciphertext_hasher: String,
}

fn parse_args() -> CliArgs {
    let mut instances: Option<String> = None;
    let mut gate_hasher: Option<String> = None;
    let mut ct_hasher: Option<String> = None;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if let Some(value) = arg.strip_prefix("--instances=") {
            instances = Some(value.to_lowercase());
            continue;
        }
        if let Some(value) = arg.strip_prefix("--gate-hasher=") {
            gate_hasher = Some(value.to_lowercase());
            continue;
        }
        if let Some(value) = arg.strip_prefix("--ciphertext-hasher=") {
            ct_hasher = Some(value.to_lowercase());
            continue;
        }
        if arg == "--instances" {
            if let Some(value) = args.next() {
                instances = Some(value.to_lowercase());
            }
            continue;
        }
        if arg == "--gate-hasher" {
            if let Some(value) = args.next() {
                gate_hasher = Some(value.to_lowercase());
            }
            continue;
        }
        if arg == "--ciphertext-hasher" {
            if let Some(value) = args.next() {
                ct_hasher = Some(value.to_lowercase());
            }
        }
    }

    CliArgs {
        instances: instances.unwrap_or_else(|| "single".to_string()),
        gate_hasher: gate_hasher.unwrap_or_else(|| "blake3".to_string()),
        ciphertext_hasher: ct_hasher.unwrap_or_else(|| "aes".to_string()),
    }
}

fn run_with_ciphertext_hasher<H: GateHasher + Send + 'static>(
    ciphertext_hasher: &str,
    gate_hasher_label: &str,
    seeds: &[u64],
    pool: &ThreadPool,
) {
    pool.install(|| match ciphertext_hasher {
        "blake3" => {
            info!("Using BLAKE3 ciphertext hasher");
            seeds.par_iter().enumerate().for_each(|(idx, seed)| {
                run_with_hashers::<H, Blake3CiphertextHasher>(
                    gate_hasher_label,
                    "BLAKE3",
                    *seed,
                    idx,
                )
            });
        }
        "sha256" => {
            info!("Using SHA-256 ciphertext hasher");
            seeds.par_iter().enumerate().for_each(|(idx, seed)| {
                run_with_hashers::<H, Sha256CiphertextHasher>(
                    gate_hasher_label,
                    "SHA-256",
                    *seed,
                    idx,
                )
            });
        }
        "swankyaes" => {
            info!("Using SwankyAES ciphertext hasher");
            seeds.par_iter().enumerate().for_each(|(idx, seed)| {
                run_with_hashers::<H, SwankyCiphertextHasher>(
                    gate_hasher_label,
                    "SwankyAES",
                    *seed,
                    idx,
                )
            });
        }
        "aes" | "" => {
            info!("Using AES ciphertext hasher");
            seeds.par_iter().enumerate().for_each(|(idx, seed)| {
                run_with_hashers::<H, AESAccumulatingHash>(gate_hasher_label, "AES", *seed, idx)
            });
        }
        other => {
            panic!(
                "Unknown ciphertext hasher '{other}'. Supported: aes, blake3, sha256, swankyaes."
            );
        }
    })
}

fn main() {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_ansi(false)
        .init();

    let CliArgs {
        instances,
        gate_hasher,
        ciphertext_hasher,
    } = parse_args();

    let num_instances = match instances.as_str() {
        "single" => 1,
        "cpu_count" => num_cpus::get_physical().max(1),
        other => {
            panic!("Unknown instances mode '{other}'. Supported: single, cpu_count.");
        }
    };

    info!("Running with {} garbling instance(s)", num_instances);

    let seeds: Vec<u64> = (0..num_instances)
        .map(|i| 12345u64.wrapping_add(i as u64))
        .collect();
    let n_threads = num_instances;
    let pool = build_pinned_pool(n_threads);

    // Add new hashers by extending these matches.
    match gate_hasher.as_str() {
        "sha256" => {
            info!("Using SHA-256 gate hasher");
            run_with_ciphertext_hasher::<Sha256GateHasher>(
                &ciphertext_hasher,
                "SHA-256",
                &seeds,
                &pool,
            );
        }
        "swankyaes" => {
            info!("Using SwankyAES (fixed-key AES TCCR) gate hasher");
            run_with_ciphertext_hasher::<SwankyAesHasher>(
                &ciphertext_hasher,
                "SwankyAES",
                &seeds,
                &pool,
            );
        }
        "blake3" => {
            info!("Using BLAKE3 gate hasher");
            run_with_ciphertext_hasher::<Blake3Hasher>(&ciphertext_hasher, "BLAKE3", &seeds, &pool);
        }
        other => {
            panic!("Unknown gate hasher '{other}'. Supported: blake3, sha256, swankyaes.");
        }
    }
}
