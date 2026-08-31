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
use rayon::prelude::*;
use sha2::{Digest, Sha256};

/// leaves hashed per parallel batch; a power of two so each batch collapses to
/// exactly one mountain-range node of height log2(BATCH)
const BATCH: usize = 1 << 16;

#[inline]
fn node(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(a);
    h.update(b);
    h.finalize().into()
}

const K_CONSTRAINTS: usize = 6;

/// Counts ciphertexts and, when `commit` is set, folds each leaf into a
/// streaming Merkle root. 2.7B leaf hashes are ~87 GB and will not fit in
/// memory, so this keeps a mountain-range stack of at most 64 partial nodes:
/// push a leaf, then while the top two nodes are the same height, combine.
/// Result is Com(F_i) in one pass with O(log n) memory.
#[derive(Default)]
struct CountingSink {
    n: u64,
    commit: bool,
    /// (hash, height) stack
    stack: Vec<([u8; 32], u32)>,
    /// leaves awaiting a parallel batch
    buf: Vec<S>,
}

impl CountingSink {
    /// Collapse a full batch in parallel: hash every leaf, then combine level
    /// by level. Leaf hashing is embarrassingly parallel and dominates; only
    /// the log(BATCH) combining levels have dependencies, and each level is
    /// itself parallel across pairs.
    fn flush_batch(&mut self) {
        if self.buf.is_empty() {
            return;
        }
        let mut level: Vec<[u8; 32]> = self
            .buf
            .par_iter()
            .map(|ct| {
                let mut h = Sha256::new();
                h.update([0x06u8, 0x00]);          // TAG_LEAF, LEAF_AND
                h.update(ct.to_bytes());
                h.update(ct.to_bytes());
                h.finalize().into()
            })
            .collect();
        self.buf.clear();

        let mut height = 0u32;
        while level.len() > 1 {
            if level.len() % 2 == 1 {
                let last = *level.last().unwrap();
                level.push(last);
            }
            level = level.par_chunks(2).map(|p| node(&p[0], &p[1])).collect();
            height += 1;
        }

        // push into the mountain range, combining equal heights
        let mut cur = (level[0], height);
        while let Some(&(top, hh)) = self.stack.last() {
            if hh != cur.1 {
                break;
            }
            self.stack.pop();
            cur = (node(&top, &cur.0), hh + 1);
        }
        self.stack.push(cur);
    }
}

impl CiphertextHandler for CountingSink {
    type Result = u64;
    fn handle(&mut self, ct: S) {
        self.n += 1;
        if self.commit {
            self.buf.push(ct);
            if self.buf.len() == BATCH {
                self.flush_batch();
            }
        }
    }
    fn finalize(mut self) -> u64 {
        if self.commit {
            self.flush_batch();
        }
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
    let commit = args.iter().any(|a| a == "--commit");
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
        GarbleMode::new(capacity, 12345,
                        CountingSink { commit, ..Default::default() });
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
    println!("commitment built        : {}", commit);
    println!("garbling wall           : {:.1} s", wall.as_secs_f64());
    println!("rate                    : {:.2}M gates/s", n_ct as f64 / wall.as_secs_f64() / 1e6);
}
