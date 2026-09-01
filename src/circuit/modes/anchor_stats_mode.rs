//! E4: K-bounded anchor statistics at settlement scale, streaming.
//!
//! `anchoring_proxy::plan_anchors` and `derive` need the whole circuit in
//! memory, which is fine for a 34k-gate Bristol file and impossible for the
//! Groth16 verifier's 10.4B gates. This mode computes the same two quantities
//! in one streaming pass, holding only the live wire set:
//!
//!   anchors_touched   = |support(a) u support(b)|
//!   xor_nodes_visited = |free-gate ancestry of a u that of b|
//!   topo_reads        = anchors_touched + xor_nodes_visited
//!
//! The planner rule is `plan_anchors` verbatim: a non-free gate's output is its
//! own anchor; a free gate's output inherits the union of its inputs' supports
//! unless that union would exceed K, in which case the wire is promoted to an
//! anchor. Storage credits release a wire's ancestry when its last consumer
//! reads it, which is the streaming equivalent of `plan_anchors`'s `left[]`
//! counters.
//!
//! Maxima are taken over every gate, including anchored free gates, per the
//! report's standing rule that those are contestable too.

use std::{
    collections::{BTreeSet, HashMap},
    num::NonZero,
    sync::{Arc, Mutex},
};

use crate::{
    Gate, GateType, WireId,
    circuit::{CircuitMode, CircuitOutput, FALSE_WIRE, TRUE_WIRE},
    storage::{Credits, Storage},
};

/// The K-bounded ancestry of one wire: which anchors it derives from, and which
/// free gates the walk must expand to get there.
#[derive(Clone, Debug, Default)]
pub struct Ancestry {
    pub anchors: BTreeSet<u64>,
    pub xors: BTreeSet<u64>,
}

impl Ancestry {
    fn anchor(id: u64) -> Self {
        let mut anchors = BTreeSet::new();
        anchors.insert(id);
        Self { anchors, xors: BTreeSet::new() }
    }
}

fn union_len(a: &BTreeSet<u64>, b: &BTreeSet<u64>) -> usize {
    a.union(b).count()
}

#[derive(Debug, Default, Clone, Copy)]
pub struct AnchorStats {
    pub gates: u64,
    pub free_gates: u64,
    pub nonfree_gates: u64,
    /// free wires promoted to anchors because their support would exceed K
    pub promoted: u64,
    pub max_anchors: usize,
    pub max_reads: usize,
    pub max_xor_nodes: usize,
    sum_anchors: u128,
    sum_reads: u128,
    /// largest support actually held by any wire (asserts the 2K bound)
    pub max_support: usize,
}

impl AnchorStats {
    pub fn mean_anchors(&self) -> f64 {
        if self.gates == 0 { 0.0 } else { self.sum_anchors as f64 / self.gates as f64 }
    }
    pub fn mean_reads(&self) -> f64 {
        if self.gates == 0 { 0.0 } else { self.sum_reads as f64 / self.gates as f64 }
    }
}

#[derive(Debug)]
pub struct AnchorStatsMode {
    storage: Storage<WireId, Option<bool>>,
    /// ancestry runs alongside the boolean value; entries are dropped when the
    /// storage releases the wire, so this tracks the live set exactly
    anc: HashMap<WireId, Arc<Ancestry>>,
    k: usize,
    gate_index: u64,
    next_input_id: u64,
    pub stats: AnchorStats,
    /// stop after this many gates (0 = no limit), so a prefix of a
    /// settlement-scale circuit can be measured in bounded time
    pub gate_limit: u64,
    /// shared so the caller can read the result: `run_streaming` consumes the mode
    handle: Arc<Mutex<AnchorStats>>,
}

impl AnchorStatsMode {
    pub fn new(capacity: usize, k: usize, handle: Arc<Mutex<AnchorStats>>) -> Self {
        Self {
            storage: Storage::new(capacity),
            anc: HashMap::new(),
            k,
            gate_index: 0,
            next_input_id: 1 << 62, // input anchors live above gate ids
            stats: AnchorStats::default(),
            gate_limit: 0,
            handle,
        }
    }

    fn publish(&self) {
        if let Ok(mut h) = self.handle.lock() {
            *h = self.stats;
        }
    }
}

impl CircuitMode for AnchorStatsMode {
    type WireValue = bool;
    type CiphertextAcc = ();

    fn false_value(&self) -> Self::WireValue {
        false
    }

    fn true_value(&self) -> Self::WireValue {
        true
    }

    fn allocate_wire(&mut self, credits: Credits) -> WireId {
        // A wire no gate produces is a circuit input, and is its own anchor.
        let id = self.next_input_id;
        self.next_input_id += 1;
        let w = self.storage.allocate(None, credits);
        self.anc.insert(w, Arc::new(Ancestry::anchor(id)));
        w
    }

    fn evaluate_gate(&mut self, gate: &Gate) {
        let anc_a = self.anc.get(&gate.wire_a).cloned().unwrap_or_default();
        let anc_b = self.anc.get(&gate.wire_b).cloned().unwrap_or_default();

        // Always consume input credits, exactly as the other modes do.
        let a = self.lookup_wire(gate.wire_a).unwrap_or(false);
        let b = self.lookup_wire(gate.wire_b).unwrap_or(false);

        if gate.wire_c == WireId::UNREACHABLE {
            return;
        }

        let g = self.gate_index;
        self.gate_index += 1;

        // Cost of contesting THIS gate: the walk derives both input labels
        // against one shared memo, so distinct nodes are counted once.
        let anchors = union_len(&anc_a.anchors, &anc_b.anchors);
        let xors = union_len(&anc_a.xors, &anc_b.xors);
        let reads = anchors + xors;

        let s = &mut self.stats;
        s.gates += 1;
        s.sum_anchors += anchors as u128;
        s.sum_reads += reads as u128;
        if anchors > s.max_anchors { s.max_anchors = anchors; }
        if xors > s.max_xor_nodes { s.max_xor_nodes = xors; }
        if reads > s.max_reads { s.max_reads = reads; }

        let out = if !gate.gate_type.is_free() {
            self.stats.nonfree_gates += 1;
            Arc::new(Ancestry::anchor(g))
        } else {
            self.stats.free_gates += 1;
            let merged: BTreeSet<u64> = anc_a.anchors.union(&anc_b.anchors).copied().collect();
            if merged.len() > self.k {
                self.stats.promoted += 1;
                Arc::new(Ancestry::anchor(g))
            } else {
                let mut xs: BTreeSet<u64> = anc_a.xors.union(&anc_b.xors).copied().collect();
                xs.insert(g);
                if merged.len() > self.stats.max_support {
                    self.stats.max_support = merged.len();
                }
                Arc::new(Ancestry { anchors: merged, xors: xs })
            }
        };

        #[inline(always)]
        fn eval(g: &GateType, a: bool, b: bool) -> bool {
            use GateType::*;
            match g {
                And => a & b, Nand => !(a & b), Nimp => a & !b, Imp => !a | b,
                Ncimp => !a & b, Cimp => !b | a, Nor => !(a | b), Or => a | b,
                Xor => a ^ b, Xnor => !(a ^ b), Not => !a,
            }
        }
        self.feed_wire(gate.wire_c, eval(&gate.gate_type, a, b));
        self.anc.insert(gate.wire_c, out);
        if self.gate_index % (1 << 22) == 0 {
            self.publish();
            eprintln!(
                "  [anchor_stats] {} gates free={} nonfree={} promoted={} anc_live={} max_anchors={} max_xor={} support={}",
                self.gate_index, self.stats.free_gates, self.stats.nonfree_gates,
                self.stats.promoted, self.anc.len(), self.stats.max_anchors,
                self.stats.max_xor_nodes, self.stats.max_support
            );
        }
        if self.gate_limit != 0 && self.gate_index >= self.gate_limit {
            self.publish();
            eprintln!("  [anchor_stats] gate limit {} reached", self.gate_limit);
            std::process::exit(0);
        }
    }

    fn lookup_wire(&mut self, wire: WireId) -> Option<Self::WireValue> {
        match wire {
            TRUE_WIRE => return Some(true),
            FALSE_WIRE => return Some(false),
            WireId::UNREACHABLE => return None,
            _ => (),
        }
        let v = match self.storage.get(wire).as_deref() {
            Ok(Some(v)) => Some(*v),
            Ok(None) => None,
            Err(_) => None,
        };
        // The storage drops a wire once its last consumer has read it; mirror
        // that here so the ancestry map holds exactly the live set.
        if !self.storage.contains(wire) {
            self.anc.remove(&wire);
        }
        v
    }

    fn feed_wire(&mut self, wire: WireId, value: Self::WireValue) {
        if matches!(wire, TRUE_WIRE | FALSE_WIRE | WireId::UNREACHABLE) {
            return;
        }
        self.storage.set(wire, |entry| *entry = Some(value)).unwrap();
    }

    fn finalize_ciphertext_accumulator(self) -> Self::CiphertextAcc {
        self.publish();
    }

    fn add_credits(&mut self, wires: &[WireId], credits: NonZero<Credits>) {
        for w in wires {
            self.storage.add_credits(*w, credits.get()).unwrap();
        }
    }
}

impl CircuitOutput<AnchorStatsMode> for bool {
    type WireRepr = WireId;

    fn decode(wire: Self::WireRepr, cache: &mut AnchorStatsMode) -> Self {
        cache.lookup_wire(wire).unwrap_or_else(|| panic!("Can't find {wire:?}"))
    }
}
