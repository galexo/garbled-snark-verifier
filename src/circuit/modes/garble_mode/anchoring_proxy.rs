//! Seed-anchored garbling: small-circuit proxy (SEED_ANCHORING_BRIEF.md, Phases 1-2).
//!
//! Validates the design on a small circuit before touching the settlement path:
//! indexed-PRF label derivation, one 16-byte anchor offset per non-free gate, a
//! single Merkle commitment over `(T_g, r_g)` leaves, and a predicate that
//! re-derives any wire from the seed and the public wiring alone.

use super::halfgates_garbling::{degarble_gate, garble_gate};
use crate::{AesCcrGateHasher, Delta, GateType, S, hashers::{GateHasher, HashWithGate}};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;

// ---------- indexed PRF (brief §2.1); tags are domain separators ----------
const TAG_WIRE: u8 = 0x01;
const TAG_DELTA: u8 = 0x02;
const TAG_ANCHOR: u8 = 0x03;
const TAG_HASHER: u8 = 0x04;
/// Spec §1: XOR gates promoted by K-bounding get their OWN tag, distinct from
/// TAG_ANCHOR, so no anchor encoding can collide with an AND anchor.
const TAG_XANCH: u8 = 0x05;
/// Spec §3: domain separation for leaf hashes.
const TAG_LEAF: u8 = 0x06;
const LEAF_AND: u8 = 0x00;
const LEAF_X: u8 = 0x01;

fn prf32(seed: &[u8; 32], tag: u8, idx: u64) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(seed);
    h.update(&[tag]);
    h.update(&idx.to_le_bytes());
    *h.finalize().as_bytes()
}

fn prf(seed: &[u8; 32], tag: u8, idx: u64) -> S {
    let mut b = [0u8; 16];
    b.copy_from_slice(&prf32(seed, tag, idx)[..16]);
    S::from_bytes(b)
}

fn label0(seed: &[u8; 32], wire: usize) -> S { prf(seed, TAG_WIRE, wire as u64) }
/// Anchor PRF over AES-CCR rather than BLAKE3.
///
/// One anchor is drawn per non-free gate, so this is the hot path of the whole
/// garbling sweep; a BLAKE3 call per gate cost 4-5x plain garbling. AES-CCR is
/// the same primitive the gate hasher already uses, so an anchor is one AES
/// block. Domain separation is by construction: this hasher's salt is drawn at
/// a different PRF index from the gate hasher's, and the AND and XOR anchors
/// use distinct seed-derived bases, so no anchor can collide with a gate hash
/// or with the other anchor kind.
#[derive(Clone, Debug)]
pub struct AnchorPrf { h: AesCcrGateHasher, base_and: S, base_x: S }

impl AnchorPrf {
    pub fn new(seed: &[u8; 32]) -> Self {
        let mut rng = ChaChaRng::from_seed(prf32(seed, TAG_HASHER, 1));
        Self {
            h: AesCcrGateHasher::from_rng(&mut rng),
            base_and: prf(seed, TAG_ANCHOR, 0),
            base_x: prf(seed, TAG_XANCH, 0),
        }
    }
    #[inline(always)]
    pub fn and(&self, gate: usize) -> S {
        HashWithGate::<1>::hash_with_gate(&self.h, &[self.base_and], gate)[0]
    }
    #[inline(always)]
    pub fn xor(&self, gate: usize) -> S {
        HashWithGate::<1>::hash_with_gate(&self.h, &[self.base_x], gate)[0]
    }
    #[inline(always)]
    pub fn of(&self, c: &PCircuit, g: usize) -> S {
        if c.gates[g].t.is_free() { self.xor(g) } else { self.and(g) }
    }
}

fn anchor(seed: &[u8; 32], gate: usize) -> S { AnchorPrf::new(seed).and(gate) }
/// Anchor label of an XOR gate selected by K-bounding (spec §1, TAG_XANCH).
fn xanchor(seed: &[u8; 32], gate: usize) -> S { AnchorPrf::new(seed).xor(gate) }
/// The anchor label of whichever kind `g` is; both parties agree because
/// `plan.anchored` is computed from the public circuit and public K.
pub fn anchor_of(seed: &[u8; 32], c: &PCircuit, g: usize) -> S {
    AnchorPrf::new(seed).of(c, g)
}

/// Delta's inner field is private, so derive it deterministically through its
/// own constructor from an indexed-PRF stream. Still a function of the seed only.
fn delta_of(seed: &[u8; 32]) -> Delta {
    let mut rng = ChaChaRng::from_seed(prf32(seed, TAG_DELTA, 0));
    Delta::generate(&mut rng)
}

fn hasher_of(seed: &[u8; 32]) -> AesCcrGateHasher {
    let mut rng = ChaChaRng::from_seed(prf32(seed, TAG_HASHER, 0));
    AesCcrGateHasher::from_rng(&mut rng)
}

// ---------- proxy circuit ----------
#[derive(Clone, Copy, Debug)]
pub struct PGate { pub t: GateType, pub a: usize, pub b: usize, pub c: usize }

pub struct PCircuit { pub n_in: usize, pub n_wires: usize, pub gates: Vec<PGate> }

impl PCircuit {
    /// Load a Bristol-fashion circuit. Wire ids are already topological, inputs
    /// occupy `0..n_in`, and every later wire is produced by exactly one gate.
    pub fn from_bristol(path: &str) -> std::io::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let mut lines = text.lines();
        let _hdr = lines.next().unwrap_or("");
        let iv: Vec<usize> = lines.next().unwrap_or("").split_whitespace()
            .filter_map(|t| t.parse().ok()).collect();
        let n_in: usize = if iv.len() > 1 { iv[1..].iter().sum() } else { 0 };
        let mut gates = Vec::new();
        let mut n_wires = n_in;
        for line in lines {
            let p: Vec<&str> = line.split_whitespace().collect();
            if p.len() < 4 { continue; }
            let (ni, no) = (p[0].parse::<usize>().unwrap_or(0), p[1].parse::<usize>().unwrap_or(0));
            if p.len() < 2 + ni + no + 1 { continue; }
            let ins: Vec<usize> = p[2..2 + ni].iter().filter_map(|t| t.parse().ok()).collect();
            let out: usize = p[2 + ni].parse().unwrap_or(0);
            if ins.len() != ni { continue; }
            let t = match p[p.len() - 1] {
                "XOR" => GateType::Xor,
                "XNOR" => GateType::Xnor,
                "INV" | "NOT" => GateType::Not,
                "AND" => GateType::And,
                "NAND" => GateType::Nand,
                "OR" => GateType::Or,
                "NOR" => GateType::Nor,
                _ => continue,
            };
            // INV has one input; mirror it so the gate shape stays uniform.
            let (a, b) = (ins[0], if ni > 1 { ins[1] } else { ins[0] });
            n_wires = n_wires.max(out + 1).max(a + 1).max(b + 1);
            gates.push(PGate { t, a, b, c: out });
        }
        Ok(PCircuit { n_in, n_wires, gates })
    }

    pub fn n_nonfree(&self) -> usize { self.gates.iter().filter(|g| !g.t.is_free()).count() }

    /// Alternating AND / XOR-chain circuit. `xor_depth` sets the XOR ancestry a
    /// contested AND gate must be expanded through, which is what `derive` pays for.
    pub fn synthetic(n_in: usize, n_and: usize, xor_depth: usize) -> Self {
        let mut gates = Vec::new();
        let mut next = n_in;
        // Outputs of previous AND gates, so XOR chains are rooted at anchors and
        // `derive` must resolve through them rather than bottoming out at inputs.
        let mut ands: Vec<usize> = Vec::new();
        for i in 0..n_and {
            let mut cur = if ands.is_empty() { i % n_in } else { ands[i % ands.len()] };
            for d in 0..xor_depth {
                // alternate between an earlier AND output and a circuit input
                let rhs = if !ands.is_empty() && d % 2 == 0 {
                    ands[(i + d) % ands.len()]
                } else {
                    (i + d + 1) % n_in
                };
                gates.push(PGate { t: GateType::Xor, a: cur, b: rhs, c: next });
                cur = next;
                next += 1;
            }
            let rhs = if ands.is_empty() { (i + 3) % n_in } else { ands[(i + 1) % ands.len()] };
            gates.push(PGate { t: GateType::And, a: cur, b: rhs, c: next });
            ands.push(next);
            next += 1;
        }
        PCircuit { n_in, n_wires: next, gates }
    }
}

// ---------- support-bounding plan (brief §C) ----------
/// Which free gates carry an anchor. Depends only on the public topology, so
/// both parties and the predicate compute the same plan without the seed.
pub struct AnchorPlan { pub anchored: Vec<bool>, pub n_xor_anchors: usize }

/// Greedy: bound every wire's anchor support at `k`, anchoring a free gate's
/// output whenever its support would exceed it. One topological pass.
pub fn plan_anchors(c: &PCircuit, k: usize) -> AnchorPlan {
    use std::collections::BTreeSet;
    let singleton = |id: usize| { let mut s = BTreeSet::new(); s.insert(id); Some(s) };

    // Consumer counts. A gate that reads the same wire twice (INV mirrors its
    // single input) must count and release it exactly once, or the support is
    // freed while still live.
    let mut left = vec![0u32; c.n_wires];
    for g in c.gates.iter() {
        left[g.a] += 1;
        if g.b != g.a { left[g.b] += 1; }
    }

    // Any wire no gate produces is a circuit input and is its own anchor.
    let mut produced = vec![false; c.n_wires];
    for g in c.gates.iter() { produced[g.c] = true; }
    let mut supp: Vec<Option<BTreeSet<usize>>> = vec![None; c.n_wires];
    for w in 0..c.n_wires { if !produced[w] { supp[w] = singleton(w); } }

    let mut anchored = vec![false; c.gates.len()];
    let mut n = 0usize;

    for (g, gate) in c.gates.iter().enumerate() {
        // A missing support here means it was released while still live, which
        // is a bug in the accounting rather than a circuit input.
        let sa = supp[gate.a].as_ref().expect("support released while still live").clone();
        let sb = if gate.b == gate.a { sa.clone() }
                 else { supp[gate.b].as_ref().expect("support released while still live").clone() };

        if !gate.t.is_free() {
            supp[gate.c] = singleton(c.n_in + g);
        } else {
            let mut u = sa; u.extend(sb.iter().copied());
            if u.len() > k { supp[gate.c] = singleton(c.n_in + g); anchored[g] = true; n += 1; }
            else { supp[gate.c] = Some(u); }
        }

        left[gate.a] -= 1;
        if left[gate.a] == 0 && gate.a != gate.c { supp[gate.a] = None; }
        if gate.b != gate.a {
            left[gate.b] -= 1;
            if left[gate.b] == 0 && gate.b != gate.c { supp[gate.b] = None; }
        }
    }
    AnchorPlan { anchored, n_xor_anchors: n }
}

/// A wire is an anchor boundary if a non-free gate produced it, or the plan
/// anchored the free gate that produced it.
fn is_anchor_gate(c: &PCircuit, plan: &AnchorPlan, g: usize) -> bool {
    !c.gates[g].t.is_free() || plan.anchored[g]
}

// ---------- anchored garbling (brief §2.2, §2.4, §C) ----------
pub struct Garbled {
    pub labels0: Vec<S>,
    /// `(T_g, r_g)`. For an anchored free gate there is no table, so `T` is ZERO
    /// and only `r` is meaningful; the gate index in the leaf hash binds which.
    pub leaves: Vec<(S, S)>,
    pub leaf_gate: Vec<usize>,
    pub gate_of_wire: Vec<Option<usize>>,
}

pub fn garble_anchored(c: &PCircuit, seed: &[u8; 32], plan: &AnchorPlan) -> Garbled {
    let delta = delta_of(seed);
    let gh = hasher_of(seed);
    let ap = AnchorPrf::new(seed);
    let mut labels0 = vec![S::ZERO; c.n_wires];
    let mut gate_of_wire = vec![None; c.n_wires];
    for w in 0..c.n_in { labels0[w] = label0(seed, w); }

    let (mut leaves, mut leaf_gate) = (Vec::new(), Vec::new());
    for (g, gate) in c.gates.iter().enumerate() {
        let (c_base, ct) = garble_gate(&gh, gate.t, labels0[gate.a], labels0[gate.b], &delta, g);
        gate_of_wire[gate.c] = Some(g);
        match ct {
            Some(t) => {
                let a_g = ap.and(g);
                leaves.push((t, c_base ^ &a_g));
                leaf_gate.push(g);
                labels0[gate.c] = a_g;
            }
            None if plan.anchored[g] => {
                // free gate promoted to an anchor: publish only the offset,
                // under TAG_XANCH so it cannot collide with an AND anchor
                let a_g = ap.xor(g);
                leaves.push((S::ZERO, c_base ^ &a_g));
                leaf_gate.push(g);
                labels0[gate.c] = a_g;
            }
            None => labels0[gate.c] = c_base,
        }
    }
    Garbled { labels0, leaves, leaf_gate, gate_of_wire }
}

// ---------- derive(w) (brief §3.1) ----------
#[derive(Default, Debug, Clone, Copy)]
pub struct DeriveStats { pub anchors_touched: usize, pub xor_nodes_visited: usize, pub max_depth: usize }

pub fn derive(c: &PCircuit, seed: &[u8; 32], gate_of_wire: &[Option<usize>], plan: &AnchorPlan,
              w: usize, memo: &mut Vec<Option<S>>, st: &mut DeriveStats) -> S {
    let delta = delta_of(seed);
    let ap = AnchorPrf::new(seed);
    // `memo` is only written once a free gate's children are resolved, so a wire
    // reachable by two paths could be expanded twice and counted twice. `open`
    // marks expansion start, making each free gate cost exactly one visit.
    let mut open = vec![false; c.n_wires];
    let mut stack: Vec<(usize, bool)> = vec![(w, false)];
    while let Some((cur, expanded)) = stack.pop() {
        st.max_depth = st.max_depth.max(stack.len());
        if memo[cur].is_some() { continue; }
        if cur < c.n_in { st.anchors_touched += 1; memo[cur] = Some(label0(seed, cur)); continue; }
        let g = gate_of_wire[cur].expect("wire has no producing gate");
        if is_anchor_gate(c, plan, g) {
            st.anchors_touched += 1;
            memo[cur] = Some(ap.of(c, g));
            continue;
        }
        let gate = c.gates[g];
        if !expanded {
            if open[cur] { continue; }
            open[cur] = true;
            st.xor_nodes_visited += 1;
            stack.push((cur, true));
            stack.push((gate.a, false));
            stack.push((gate.b, false));
            continue;
        }
        let (a, b) = (memo[gate.a].expect("a"), memo[gate.b].expect("b"));
        memo[cur] = Some(match gate.t {
            GateType::Xor => a ^ &b,
            GateType::Xnor => (a ^ &b) ^ &*delta,
            GateType::Not => a ^ &*delta,
            _ => unreachable!("free-gate branch"),
        });
    }
    memo[w].expect("derive failed")
}

/// Longest XOR chain feeding each anchor leaf, by dynamic programming.
/// `max_depth` in `DeriveStats` is traversal stack depth and is NOT this; using
/// a shared visited set there truncates path lengths and under-reports.
pub fn xor_depth_stats(c: &PCircuit, plan: &AnchorPlan) -> (usize, f64, usize) {
    let mut d = vec![0usize; c.n_wires];
    let mut per_leaf = Vec::new();
    for (g, gate) in c.gates.iter().enumerate() {
        let din = d[gate.a].max(d[gate.b]);
        if is_anchor_gate(c, plan, g) { per_leaf.push(din); d[gate.c] = 0; }
        else { d[gate.c] = 1 + din; }
    }
    per_leaf.sort_unstable();
    let max = *per_leaf.last().unwrap_or(&0);
    let mean = per_leaf.iter().sum::<usize>() as f64 / per_leaf.len().max(1) as f64;
    let p95 = per_leaf[(per_leaf.len() * 95 / 100).saturating_sub(1).min(per_leaf.len() - 1)];
    (max, mean, p95)
}

// ---------- commitment ----------
/// Spec §3 leaf encoding: `H(TAG_LEAF || type || id || payload)`, fixed widths.
/// AND payload is `T_g || r_g`; an XOR anchor's payload is `r_x` alone -- it has
/// no table, so no placeholder is committed.
pub fn leaf_hash_and(g: usize, t: S, r: S) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&[TAG_LEAF, LEAF_AND]);
    h.update(&(g as u64).to_le_bytes());
    h.update(&t.to_bytes());
    h.update(&r.to_bytes());
    *h.finalize().as_bytes()
}

pub fn leaf_hash_x(g: usize, r: S) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&[TAG_LEAF, LEAF_X]);
    h.update(&(g as u64).to_le_bytes());
    h.update(&r.to_bytes());
    *h.finalize().as_bytes()
}

/// Leaf hash for gate `g`, dispatching on whether it is an AND or an XOR anchor.
pub fn leaf_hash_of(c: &PCircuit, g: usize, t: S, r: S) -> [u8; 32] {
    if c.gates[g].t.is_free() { leaf_hash_x(g, r) } else { leaf_hash_and(g, t, r) }
}

fn node(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new(); h.update(a); h.update(b); *h.finalize().as_bytes()
}

pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() { return [0u8; 32]; }
    let mut lvl = leaves.to_vec();
    while lvl.len() > 1 {
        if lvl.len() % 2 == 1 { let l = *lvl.last().unwrap(); lvl.push(l); }
        lvl = lvl.chunks(2).map(|p| node(&p[0], &p[1])).collect();
    }
    lvl[0]
}

pub fn merkle_path(leaves: &[[u8; 32]], mut idx: usize) -> Vec<[u8; 32]> {
    let (mut path, mut lvl) = (Vec::new(), leaves.to_vec());
    while lvl.len() > 1 {
        if lvl.len() % 2 == 1 { let l = *lvl.last().unwrap(); lvl.push(l); }
        path.push(lvl[idx ^ 1]);
        idx /= 2;
        lvl = lvl.chunks(2).map(|p| node(&p[0], &p[1])).collect();
    }
    path
}

pub fn merkle_ok(leaf: [u8; 32], mut idx: usize, path: &[[u8; 32]], root: [u8; 32]) -> bool {
    let mut cur = leaf;
    for sib in path {
        cur = if idx % 2 == 0 { node(&cur, sib) } else { node(sib, &cur) };
        idx /= 2;
    }
    cur == root
}

// ---------- output-label commitments (brief §3.1 step 7) ----------
pub fn output_commit(l0: S, delta: &Delta) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&l0.to_bytes());
    h.update(&(l0 ^ &**delta).to_bytes());
    *h.finalize().as_bytes()
}

pub fn output_commits(gb: &Garbled, seed: &[u8; 32], outs: &[usize]) -> Vec<[u8; 32]> {
    let delta = delta_of(seed);
    outs.iter().map(|&w| output_commit(gb.labels0[w], &delta)).collect()
}

pub fn phi_settle_output(c: &PCircuit, seed: &[u8; 32], gate_of_wire: &[Option<usize>],
                         plan: &AnchorPlan, outs: &[usize], i: usize,
                         published: &[[u8; 32]]) -> u8 {
    if i >= outs.len() || i >= published.len() { return 0; }
    let delta = delta_of(seed);
    let mut memo = vec![None; c.n_wires];
    let mut st = DeriveStats::default();
    let l0 = derive(c, seed, gate_of_wire, plan, outs[i], &mut memo, &mut st);
    if output_commit(l0, &delta) != published[i] { 1 } else { 0 }
}

// ---------- the predicate (brief §3.1, extended for XOR anchors) ----------
pub fn phi_settle_v2(c: &PCircuit, seed: &[u8; 32], plan: &AnchorPlan, root: [u8; 32],
                     leaf_idx: usize, g: usize, leaf: (S, S), path: &[[u8; 32]],
                     gate_of_wire: &[Option<usize>]) -> (u8, DeriveStats) {
    let mut st = DeriveStats::default();
    if g >= c.gates.len() { return (0, st); }
    if !merkle_ok(leaf_hash_of(c, g, leaf.0, leaf.1), leaf_idx, path, root) { return (0, st); }
    if !is_anchor_gate(c, plan, g) { return (0, st); }

    let gate = c.gates[g];
    let mut memo: Vec<Option<S>> = vec![None; c.n_wires];
    let a0 = derive(c, seed, gate_of_wire, plan, gate.a, &mut memo, &mut st);
    let b0 = derive(c, seed, gate_of_wire, plan, gate.b, &mut memo, &mut st);
    let delta = delta_of(seed);
    let gh = hasher_of(seed);

    let (c_base, ct) = garble_gate(&gh, gate.t, a0, b0, &delta, g);
    let r_exp = c_base ^ &anchor_of(seed, c, g);
    let t_exp = ct.unwrap_or(S::ZERO);      // anchored free gate publishes no table
    if t_exp != leaf.0 || r_exp != leaf.1 { return (1, st); }
    (0, st)
}

// ---------- Ve (brief §2.5) ----------
#[derive(Debug, PartialEq, Eq)]
pub enum VeFault { Leaf { gate: usize }, Output { index: usize } }

pub fn ve(c: &PCircuit, seed: &[u8; 32], plan: &AnchorPlan, recv_leaves: &[(S, S)],
          outs: &[usize], recv_outs: &[[u8; 32]]) -> Option<VeFault> {
    let gb = garble_anchored(c, seed, plan);
    if recv_leaves.len() != gb.leaves.len() { return Some(VeFault::Leaf { gate: 0 }); }
    for (i, (got, want)) in recv_leaves.iter().zip(gb.leaves.iter()).enumerate() {
        if got != want { return Some(VeFault::Leaf { gate: gb.leaf_gate[i] }); }
    }
    let want = output_commits(&gb, seed, outs);
    if recv_outs.len() != want.len() { return Some(VeFault::Output { index: 0 }); }
    for (i, (got, w)) in recv_outs.iter().zip(want.iter()).enumerate() {
        if got != w { return Some(VeFault::Output { index: i }); }
    }
    None
}

// ---------- size accounting ----------
pub struct Sizes { pub n_leaf: usize, pub f_bytes: usize, pub witness: usize }

/// Spec §3: an AND leaf carries `T_g || r_g` (32 B); an XOR anchor carries
/// `r_x` alone (16 B). Charging 32 B for every leaf overstates F.
pub fn sizes(c: &PCircuit, gb: &Garbled, path_len: usize) -> Sizes {
    let f_bytes: usize = gb.leaf_gate.iter()
        .map(|&g| if c.gates[g].t.is_free() { 16 } else { 32 })
        .sum();
    Sizes { n_leaf: gb.leaves.len(), f_bytes,
            witness: 32 + 8 + 32 + 32 * path_len }
}

#[cfg(test)]
mod tests {
    use super::*;

    const K: usize = 1024;
    fn seed_a() -> [u8; 32] { [7u8; 32] }

    fn setup(n_in: usize, n_and: usize, depth: usize, k: usize)
        -> (PCircuit, [u8; 32], AnchorPlan, Garbled) {
        let c = PCircuit::synthetic(n_in, n_and, depth);
        let seed = seed_a();
        let plan = plan_anchors(&c, k);
        let gb = garble_anchored(&c, &seed, &plan);
        (c, seed, plan, gb)
    }

    fn commit(c: &PCircuit, gb: &Garbled) -> (Vec<[u8; 32]>, [u8; 32]) {
        let hs: Vec<_> = gb.leaves.iter().enumerate()
            .map(|(i, (t, r))| leaf_hash_of(c, gb.leaf_gate[i], *t, *r)).collect();
        let root = merkle_root(&hs);
        (hs, root)
    }

    fn outs_of(gb: &Garbled, c: &PCircuit, k: usize) -> Vec<usize> {
        gb.leaf_gate.iter().rev().take(k).map(|&g| c.gates[g].c).collect()
    }

    #[test]
    fn t1_determinism() {
        let (c, seed, plan, x) = setup(64, 200, 3, K);
        let y = garble_anchored(&c, &seed, &plan);
        assert_eq!(x.leaves, y.leaves);
        assert_eq!(x.labels0, y.labels0);
    }

    #[test]
    fn t3_translation_invariant() {
        let (c, seed, plan, gb) = setup(64, 200, 3, K);
        for &g in gb.leaf_gate.iter() {
            assert_eq!(gb.labels0[c.gates[g].c], anchor(&seed, g), "gate {g} not anchored");
        }
    }

    /// Brief §3.4 test 4, the decisive one.
    #[test]
    fn t4_derive_matches_garbler_labels() {
        for k in [64usize, 256, K] {
            let (c, seed, plan, gb) = setup(64, 400, 6, k);
            let mut memo = vec![None; c.n_wires];
            let mut st = DeriveStats::default();
            for w in 0..c.n_wires {
                let d = derive(&c, &seed, &gb.gate_of_wire, &plan, w, &mut memo, &mut st);
                assert_eq!(d, gb.labels0[w], "derive disagrees at wire {w}, K={k}");
            }
        }
    }

    #[test]
    fn t_predicate_honest_and_cheats() {
        let (c, seed, plan, gb) = setup(64, 200, 3, K);
        let (hs, root) = commit(&c, &gb);
        let li = hs.len() / 2;
        let g = gb.leaf_gate[li];
        let path = merkle_path(&hs, li);

        let (v, _) = phi_settle_v2(&c, &seed, &plan, root, li, g, gb.leaves[li], &path, &gb.gate_of_wire);
        assert_eq!(v, 0, "honest leaf must acquit");

        for mutate_t in [true, false] {
            let bad = if mutate_t { (gb.leaves[li].0 ^ &S::one(), gb.leaves[li].1) }
                      else { (gb.leaves[li].0, gb.leaves[li].1 ^ &S::one()) };
            let hs2: Vec<_> = hs.iter().cloned().enumerate()
                .map(|(i, h)| if i == li { leaf_hash_of(&c, g, bad.0, bad.1) } else { h }).collect();
            let (v, _) = phi_settle_v2(&c, &seed, &plan, merkle_root(&hs2), li, g, bad,
                                       &merkle_path(&hs2, li), &gb.gate_of_wire);
            assert_eq!(v, 1, "corrupt leaf must convict (table={mutate_t})");
        }

        let (v, _) = phi_settle_v2(&c, &seed, &plan, root, li, g, gb.leaves[li], &[], &gb.gate_of_wire);
        assert_eq!(v, 0, "bad path must acquit");
        let (v, _) = phi_settle_v2(&c, &seed, &plan, root, li, c.gates.len() + 5, gb.leaves[li],
                                   &path, &gb.gate_of_wire);
        assert_eq!(v, 0, "out-of-range gate must acquit");
    }

    /// An anchored free gate is contestable exactly like an AND leaf.
    #[test]
    fn t9_xor_anchor_leaf_is_contestable() {
        let (c, seed, plan, gb) = setup(32, 400, 40, 8);   // small K forces XOR anchors
        assert!(plan.n_xor_anchors > 0, "test needs XOR anchors");
        let (hs, root) = commit(&c, &gb);
        let li = gb.leaf_gate.iter().position(|&g| c.gates[g].t.is_free())
            .expect("expected an anchored free gate leaf");
        let g = gb.leaf_gate[li];

        let (v, _) = phi_settle_v2(&c, &seed, &plan, root, li, g, gb.leaves[li],
                                   &merkle_path(&hs, li), &gb.gate_of_wire);
        assert_eq!(v, 0, "honest XOR-anchor leaf must acquit");

        let bad = (gb.leaves[li].0, gb.leaves[li].1 ^ &S::one());
        let hs2: Vec<_> = hs.iter().cloned().enumerate()
            .map(|(i, h)| if i == li { leaf_hash_of(&c, g, bad.0, bad.1) } else { h }).collect();
        let (v, _) = phi_settle_v2(&c, &seed, &plan, merkle_root(&hs2), li, g, bad,
                                   &merkle_path(&hs2, li), &gb.gate_of_wire);
        assert_eq!(v, 1, "corrupt XOR-anchor offset must convict");
    }

    #[test]
    fn t6_ve_detection() {
        let (c, seed, plan, gb) = setup(64, 200, 3, K);
        let outs = outs_of(&gb, &c, 8);
        let oc = output_commits(&gb, &seed, &outs);
        assert_eq!(ve(&c, &seed, &plan, &gb.leaves, &outs, &oc), None);

        let k = gb.leaves.len() / 3;
        let mut m = gb.leaves.clone();
        m[k].1 = m[k].1 ^ &S::one();
        assert_eq!(ve(&c, &seed, &plan, &m, &outs, &oc), Some(VeFault::Leaf { gate: gb.leaf_gate[k] }));

        let mut mo = oc.clone();
        mo[3][0] ^= 1;
        assert_eq!(ve(&c, &seed, &plan, &gb.leaves, &outs, &mo), Some(VeFault::Output { index: 3 }));
    }

    #[test]
    fn t7_output_check() {
        let (c, seed, plan, gb) = setup(64, 200, 3, K);
        let outs = outs_of(&gb, &c, 8);
        let oc = output_commits(&gb, &seed, &outs);
        for i in 0..outs.len() {
            assert_eq!(phi_settle_output(&c, &seed, &gb.gate_of_wire, &plan, &outs, i, &oc), 0);
        }
        let mut bad = oc.clone();
        bad[5][0] ^= 1;
        assert_eq!(phi_settle_output(&c, &seed, &gb.gate_of_wire, &plan, &outs, 5, &bad), 1);
    }

    #[test]
    fn t2_evaluation_correctness() {
        let (c, seed, plan, gb) = setup(32, 120, 4, 16);   // K small enough to include XOR anchors
        let delta = delta_of(&seed);
        let gh = hasher_of(&seed);
        let bits: Vec<bool> = (0..c.n_in).map(|i| i % 3 == 0).collect();
        let mut val = vec![false; c.n_wires];
        let mut act = vec![S::ZERO; c.n_wires];
        for w in 0..c.n_in {
            val[w] = bits[w];
            act[w] = if bits[w] { gb.labels0[w] ^ &*delta } else { gb.labels0[w] };
        }
        let mut li = 0usize;
        for (g, gate) in c.gates.iter().enumerate() {
            let out = (gate.t.f())(val[gate.a], val[gate.b]);
            let free = gate.t.is_free();
            let mut lab = if free {
                degarble_gate(&gh, gate.t, || unreachable!(), act[gate.a], val[gate.a], act[gate.b], g)
            } else {
                let t = gb.leaves[li].0;
                degarble_gate(&gh, gate.t, || t, act[gate.a], val[gate.a], act[gate.b], g)
            };
            if !free || plan.anchored[g] {
                lab = lab ^ &gb.leaves[li].1;   // evaluator translates by the offset
                li += 1;
            }
            val[gate.c] = out;
            act[gate.c] = lab;
            let expect = if out { gb.labels0[gate.c] ^ &*delta } else { gb.labels0[gate.c] };
            assert_eq!(act[gate.c], expect, "wrong active label at gate {g} ({:?})", gate.t);
        }
    }

    const BRISTOL: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../ndss/phi_mis/");

    fn bristol(name: &str) -> Option<PCircuit> {
        PCircuit::from_bristol(&format!("{BRISTOL}{name}")).ok().filter(|c| !c.gates.is_empty())
    }

    /// The proxy on a real circuit: derive must reproduce every wire of SHA-256.
    #[test]
    fn t10_real_circuit_derive() {
        let Some(c) = bristol("aes_128.txt") else { eprintln!("skip: circuit missing"); return };
        let seed = seed_a();
        let plan = plan_anchors(&c, K);
        let gb = garble_anchored(&c, &seed, &plan);
        println!("AES-128 gates={} wires={} non-free={} xor_anchors={} leaves={}",
                 c.gates.len(), c.n_wires, c.n_nonfree(), plan.n_xor_anchors, gb.leaves.len());
        let mut memo = vec![None; c.n_wires];
        let mut st = DeriveStats::default();
        for w in 0..c.n_wires {
            if gb.gate_of_wire[w].is_none() && w >= c.n_in { continue; }
            let d = derive(&c, &seed, &gb.gate_of_wire, &plan, w, &mut memo, &mut st);
            assert_eq!(d, gb.labels0[w], "derive disagrees at wire {w}");
        }
    }

    /// The predicate on a real circuit, honest and both cheats.
    #[test]
    fn t11_real_circuit_predicate() {
        let Some(c) = bristol("aes_128.txt") else { eprintln!("skip: circuit missing"); return };
        let seed = seed_a();
        let plan = plan_anchors(&c, K);
        let gb = garble_anchored(&c, &seed, &plan);
        let (hs, root) = commit(&c, &gb);
        for li in [0usize, hs.len() / 2, hs.len() - 1] {
            let g = gb.leaf_gate[li];
            let (v, st) = phi_settle_v2(&c, &seed, &plan, root, li, g, gb.leaves[li],
                                        &merkle_path(&hs, li), &gb.gate_of_wire);
            assert_eq!(v, 0, "honest leaf {li} must acquit");
            if li == hs.len() / 2 {
                println!("AES-128 contested gate {g}: anchors={} xor_nodes={}",
                         st.anchors_touched, st.xor_nodes_visited);
            }
            let bad = (gb.leaves[li].0, gb.leaves[li].1 ^ &S::one());
            let hs2: Vec<_> = hs.iter().cloned().enumerate()
                .map(|(i, h)| if i == li { leaf_hash_of(&c, g, bad.0, bad.1) } else { h }).collect();
            let (v, _) = phi_settle_v2(&c, &seed, &plan, merkle_root(&hs2), li, g, bad,
                                       &merkle_path(&hs2, li), &gb.gate_of_wire);
            assert_eq!(v, 1, "corrupt leaf {li} must convict");
        }
    }

    /// Real-circuit K sweep, worst case over every leaf. This is the sweep that
    /// means something; the synthetic one below does not promote any XOR wire.
    #[test]
    #[ignore = "minutes on SHA-256; run with --ignored"]
    fn t12_real_k_sweep() {
        for name in ["aes_128.txt", "sha256.txt"] {
            let Some(c) = bristol(name) else { continue };
            for k in [256usize, 1024, 4096] {
                let seed = seed_a();
                let plan = plan_anchors(&c, k);
                let gb = garble_anchored(&c, &seed, &plan);
                let (mut a_max, mut x_max, mut a_sum) = (0usize, 0usize, 0usize);
                for &g in gb.leaf_gate.iter() {
                    let gate = c.gates[g];
                    let mut memo = vec![None; c.n_wires];
                    let mut st = DeriveStats::default();
                    derive(&c, &seed, &gb.gate_of_wire, &plan, gate.a, &mut memo, &mut st);
                    derive(&c, &seed, &gb.gate_of_wire, &plan, gate.b, &mut memo, &mut st);
                    a_max = a_max.max(st.anchors_touched);
                    x_max = x_max.max(st.xor_nodes_visited);
                    a_sum += st.anchors_touched;
                }
                println!("{name:14} K={k:<5} xor_anchors={:<7} leaves={:<7} anchors max={a_max:<6} mean={:<8.1} xor_nodes max={x_max}",
                         plan.n_xor_anchors, gb.leaves.len(),
                         a_sum as f64 / gb.leaf_gate.len() as f64);
                assert!(a_max <= 2 * k, "2K bound violated: {a_max} > 2*{k}");
            }
        }
    }

    /// Pin down the xor_nodes discrepancy: report the argmax gate and probe a
    /// specific gate that the Python analysis maxes on.
    #[test]
    #[ignore = "diagnostic; run with --ignored"]
    fn t13_xor_nodes_argmax() {
        let Some(c) = bristol("aes_128.txt") else { return };
        let seed = seed_a();
        let plan = plan_anchors(&c, 1024);
        let gb = garble_anchored(&c, &seed, &plan);
        let (mut x_max, mut arg) = (0usize, 0usize);
        for &g in gb.leaf_gate.iter() {
            let gate = c.gates[g];
            let mut memo = vec![None; c.n_wires];
            let mut st = DeriveStats::default();
            derive(&c, &seed, &gb.gate_of_wire, &plan, gate.a, &mut memo, &mut st);
            derive(&c, &seed, &gb.gate_of_wire, &plan, gate.b, &mut memo, &mut st);
            if st.xor_nodes_visited > x_max { x_max = st.xor_nodes_visited; arg = g; }
        }
        println!("rust argmax gate={arg} xor_nodes={x_max}");

        // the gate Python maxes on
        let g = 34466usize;
        if g < c.gates.len() {
            let gate = c.gates[g];
            let mut memo = vec![None; c.n_wires];
            let mut st = DeriveStats::default();
            derive(&c, &seed, &gb.gate_of_wire, &plan, gate.a, &mut memo, &mut st);
            derive(&c, &seed, &gb.gate_of_wire, &plan, gate.b, &mut memo, &mut st);
            println!("rust gate 34466: type={:?} a={} b={} xor_nodes={} anchors={}",
                     gate.t, gate.a, gate.b, st.xor_nodes_visited, st.anchors_touched);
        }
        println!("rust circuit: gates={} n_in={} n_wires={} nonfree={}",
                 c.gates.len(), c.n_in, c.n_wires, c.n_nonfree());

        // Is the SHA-256 argmax an anchored FREE gate? If so, Rust and Python
        // simply max over different gate sets.
        let Some(c2) = bristol("sha256.txt") else { return };
        let plan2 = plan_anchors(&c2, 1024);
        let gb2 = garble_anchored(&c2, &seed, &plan2);
        let (mut m_all, mut arg_all) = (0usize, 0usize);
        let (mut m_nf, mut arg_nf) = (0usize, 0usize);
        for &g in gb2.leaf_gate.iter() {
            let gate = c2.gates[g];
            let mut memo = vec![None; c2.n_wires];
            let mut st = DeriveStats::default();
            derive(&c2, &seed, &gb2.gate_of_wire, &plan2, gate.a, &mut memo, &mut st);
            derive(&c2, &seed, &gb2.gate_of_wire, &plan2, gate.b, &mut memo, &mut st);
            if st.anchors_touched > m_all { m_all = st.anchors_touched; arg_all = g; }
            if !gate.t.is_free() && st.anchors_touched > m_nf { m_nf = st.anchors_touched; arg_nf = g; }
        }
        println!("sha256 K=1024: max over ALL leaves = {m_all} at gate {arg_all} (free={})",
                 c2.gates[arg_all].t.is_free());
        println!("sha256 K=1024: max over NON-FREE only = {m_nf} at gate {arg_nf}");
    }

    /// Dump the anchored gate positions so they can be diffed against the
    /// independent Python planner.
    #[test]
    #[ignore = "diagnostic; run with --ignored"]
    fn t14_dump_anchor_positions() {
        let Some(c) = bristol("sha256.txt") else { return };
        let plan = plan_anchors(&c, 1024);
        let idx: Vec<usize> = plan.anchored.iter().enumerate()
            .filter(|&(_, a)| *a).map(|(i, _)| i).collect();
        println!("rust: gates={} anchored_free={} first={:?} last={:?}",
                 c.gates.len(), idx.len(), &idx[..6.min(idx.len())],
                 &idx[idx.len().saturating_sub(3)..]);
        let body: Vec<String> = idx.iter().map(|v| v.to_string()).collect();
        std::fs::write("/tmp/rs_anchors.txt", body.join("\n")).unwrap();
    }

    /// Single source of truth for the cost model. Emits every figure the paper
    /// needs, over all leaves, for each circuit and K. Supersedes the external
    /// Python planner, which is retired.
    #[test]
    #[ignore = "minutes; run with --ignored"]
    fn t15_cost_model() {
        println!("{:<12} {:>6} {:>8} {:>8} {:>18} {:>18} {:>16} {:>10} {:>8}",
                 "circuit", "K", "anchors", "leaves", "derive_anchors m/mn",
                 "topo_reads m/mn", "xor_depth m/mn", "F(MB)", "wit(B)");
        for name in ["aes_128.txt", "sha256.txt", "Keccak_f.txt"] {
            let Some(c) = bristol(name) else { continue };
            let seed = seed_a();
            for k in [256usize, 512, 1024, 2048, 4096] {
                let plan = plan_anchors(&c, k);
                let gb = garble_anchored(&c, &seed, &plan);
                let (mut a_max, mut x_max, mut a_sum, mut x_sum) = (0usize, 0usize, 0usize, 0usize);
                for &g in gb.leaf_gate.iter() {
                    let gate = c.gates[g];
                    let mut memo = vec![None; c.n_wires];
                    let mut st = DeriveStats::default();
                    derive(&c, &seed, &gb.gate_of_wire, &plan, gate.a, &mut memo, &mut st);
                    derive(&c, &seed, &gb.gate_of_wire, &plan, gate.b, &mut memo, &mut st);
                    a_max = a_max.max(st.anchors_touched);
                    x_max = x_max.max(st.xor_nodes_visited);
                    a_sum += st.anchors_touched;
                    x_sum += st.xor_nodes_visited;
                }
                let n = gb.leaf_gate.len().max(1);
                let (d_max, d_mean, _) = xor_depth_stats(&c, &plan);
                let path = merkle_path(&commit(&c, &gb).0, 0).len();
                let s = sizes(&c, &gb, path);
                println!("{name:<12} {k:>6} {:>8} {:>8} {:>9}/{:<8.1} {:>9}/{:<8.1} {:>7}/{:<8.1} {:>10.2} {:>8}",
                         plan.n_xor_anchors, s.n_leaf,
                         a_max, a_sum as f64 / n as f64,
                         x_max, x_sum as f64 / n as f64,
                         d_max, d_mean,
                         s.f_bytes as f64 / 1e6, s.witness);
                assert!(a_max <= 2 * k, "2K bound violated: {a_max} > 2*{k}");
            }
        }
    }

    /// t16: the streaming ancestry recurrence must agree with derive().
    ///
    /// `AnchorStatsMode` computes anchors_touched / xor_nodes_visited in one
    /// forward pass, because the Groth16 verifier's 10.4B gates cannot be held
    /// in memory for plan_anchors + derive. E4's numbers are only worth
    /// anything if that recurrence reproduces the trusted path exactly, so
    /// check it against derive() on a real circuit at every K.
    #[test]
    #[ignore = "minutes on SHA-256; run with --ignored"]
    fn t16_streaming_matches_derive() {
        use std::collections::BTreeSet;
        let Some(c) = bristol("sha256.txt") else { return };
        let seed = seed_a();

        for k in [256usize, 512, 1024] {
            let plan = plan_anchors(&c, k);
            let gb = garble_anchored(&c, &seed, &plan);

            // trusted: derive() per contestable gate
            let (mut a_ref, mut x_ref) = (0usize, 0usize);
            for &g in gb.leaf_gate.iter() {
                let gate = c.gates[g];
                let mut memo = vec![None; c.n_wires];
                let mut st = DeriveStats::default();
                derive(&c, &seed, &gb.gate_of_wire, &plan, gate.a, &mut memo, &mut st);
                derive(&c, &seed, &gb.gate_of_wire, &plan, gate.b, &mut memo, &mut st);
                a_ref = a_ref.max(st.anchors_touched);
                x_ref = x_ref.max(st.xor_nodes_visited);
            }

            // streaming: one forward pass carrying (anchors, xors) per live wire
            let mut left = vec![0u32; c.n_wires];
            for g in c.gates.iter() {
                left[g.a] += 1;
                if g.b != g.a { left[g.b] += 1; }
            }
            let mut produced = vec![false; c.n_wires];
            for g in c.gates.iter() { produced[g.c] = true; }
            let mut anc: Vec<Option<(BTreeSet<usize>, BTreeSet<usize>)>> = vec![None; c.n_wires];
            for w in 0..c.n_wires {
                if !produced[w] {
                    let mut a = BTreeSet::new();
                    a.insert(w);
                    anc[w] = Some((a, BTreeSet::new()));
                }
            }
            let (mut a_str, mut x_str) = (0usize, 0usize);
            let leaf: BTreeSet<usize> = gb.leaf_gate.iter().copied().collect();

            for (gi, gate) in c.gates.iter().enumerate() {
                let (sa, xa) = anc[gate.a].clone().expect("live");
                let (sb, xb) = if gate.b == gate.a { (sa.clone(), xa.clone()) }
                               else { anc[gate.b].clone().expect("live") };

                if leaf.contains(&gi) {
                    a_str = a_str.max(sa.union(&sb).count());
                    x_str = x_str.max(xa.union(&xb).count());
                }

                let out = if !gate.t.is_free() {
                    let mut a = BTreeSet::new();
                    a.insert(c.n_in + gi);
                    (a, BTreeSet::new())
                } else {
                    let merged: BTreeSet<usize> = sa.union(&sb).copied().collect();
                    if merged.len() > k {
                        let mut a = BTreeSet::new();
                        a.insert(c.n_in + gi);
                        (a, BTreeSet::new())
                    } else {
                        let mut xs: BTreeSet<usize> = xa.union(&xb).copied().collect();
                        xs.insert(gi);
                        (merged, xs)
                    }
                };
                anc[gate.c] = Some(out);

                left[gate.a] -= 1;
                if left[gate.a] == 0 && gate.a != gate.c { anc[gate.a] = None; }
                if gate.b != gate.a {
                    left[gate.b] -= 1;
                    if left[gate.b] == 0 && gate.b != gate.c { anc[gate.b] = None; }
                }
            }

            println!("K={k:>5}  derive: {a_ref}/{x_ref}   streaming: {a_str}/{x_str}");
            assert_eq!(a_str, a_ref, "anchors_touched disagree at K={k}");
            assert_eq!(x_str, x_ref, "xor_nodes_visited disagree at K={k}");
        }
    }

    /// t17: setup cost, before vs after anchoring, on real Bristol circuits.
    ///
    /// "Before" is the unmodified scheme: call garble_gate, store the natural
    /// C0, keep the table. "After" is garble_anchored: same garble_gate, plus
    /// one PRF and one XOR per non-free gate, and the anchor stored downstream.
    /// Reports garbling wall time and F bytes for both, which are the setup
    /// numbers the paper needs and which no measurement covered before.
    #[test]
    #[ignore = "timing; run with --ignored"]
    fn t17_setup_cost_before_after() {
        println!("{:<14} {:>6} {:>10} {:>12} {:>12} {:>10} {:>10} {:>8}",
                 "circuit", "K", "gates", "plain_ms", "anchored_ms", "F_plain",
                 "F_anch", "ratio");
        for name in ["aes_128.txt", "sha256.txt", "Keccak_f.txt"] {
            let Some(c) = bristol(name) else { continue };
            let seed = seed_a();
            for k in [256usize, 1024] {
                let plan = plan_anchors(&c, k);

                // ---- before: the unmodified sweep ----
                let t0 = std::time::Instant::now();
                let delta = delta_of(&seed);
                let gh = hasher_of(&seed);
                let mut l0 = vec![S::ZERO; c.n_wires];
                for w in 0..c.n_in { l0[w] = label0(&seed, w); }
                let mut n_ct = 0usize;
                for (g, gate) in c.gates.iter().enumerate() {
                    let (cb, ct) = garble_gate(&gh, gate.t, l0[gate.a], l0[gate.b], &delta, g);
                    if ct.is_some() { n_ct += 1; }
                    l0[gate.c] = cb;           // natural C0 stored, no translation
                }
                let plain_ms = t0.elapsed().as_secs_f64() * 1000.0;
                let f_plain = n_ct * 16;       // table rows only

                // ---- after: anchored ----
                let t1 = std::time::Instant::now();
                let gb = garble_anchored(&c, &seed, &plan);
                let anchored_ms = t1.elapsed().as_secs_f64() * 1000.0;
                let sz = sizes(&c, &gb, 32);

                println!("{name:<14} {k:>6} {:>10} {:>12.1} {:>12.1} {:>10} {:>10} {:>8.2}",
                         c.gates.len(), plain_ms, anchored_ms,
                         f_plain, sz.f_bytes, sz.f_bytes as f64 / f_plain as f64);
            }
        }
    }

    /// K sweep on the synthetic circuit: cost per dispute and the 2K bound.
    #[test]
    fn t5_k_sweep() {
        for k in [64usize, 128, 256, 512, 1024] {
            let (c, seed, plan, gb) = setup(64, 400, 24, k);
            let (mut a_max, mut x_max, mut a_sum, mut n) = (0usize, 0usize, 0usize, 0usize);
            for &g in gb.leaf_gate.iter() {
                let gate = c.gates[g];
                let mut memo = vec![None; c.n_wires];
                let mut st = DeriveStats::default();
                derive(&c, &seed, &gb.gate_of_wire, &plan, gate.a, &mut memo, &mut st);
                derive(&c, &seed, &gb.gate_of_wire, &plan, gate.b, &mut memo, &mut st);
                a_max = a_max.max(st.anchors_touched);
                x_max = x_max.max(st.xor_nodes_visited);
                a_sum += st.anchors_touched;
                n += 1;
            }
            let s = sizes(&c, &gb, merkle_path(&commit(&c, &gb).0, 0).len());
            println!("K={k:<5} xor_anchors={:<5} leaves={:<5} F={:<7}B  anchors max={a_max:<5} mean={:<7.1}  xor_nodes max={x_max}",
                     plan.n_xor_anchors, s.n_leaf, s.f_bytes, a_sum as f64 / n as f64);
            assert!(a_max <= 2 * k, "gate-level bound is 2K, got {a_max} at K={k}");
        }
    }
}
