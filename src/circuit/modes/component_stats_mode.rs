//! Item 2: the topology generator at real scale.
//!
//! The BitVMX predicate replaces a ~125 GB descriptor array with a generator
//! that computes a gate's descriptor from its index. That rests on a claim
//! never checked against the verifier: that `gate index -> (template, instance,
//! offset)` is O(1). It is O(1) only if component instances occupy contiguous,
//! non-overlapping gate-index ranges and the number of distinct templates is
//! small enough to index directly.
//!
//! This mode records, per component instance, the gate index at entry and exit,
//! and the ComponentKey. From that it reports:
//!
//!   * distinct templates (how big the template table must be)
//!   * instance count and gates per instance
//!   * whether top-level instances are contiguous and non-overlapping
//!   * nesting depth, since a nested hierarchy makes the mapping a search
//!     rather than a division
//!
//! Wire values are booleans so the existing `EncodeInput`/`CircuitOutput` impls
//! apply unchanged; this mode measures structure, not garbling.

use std::{
    collections::HashMap,
    num::NonZero,
    sync::{Arc, Mutex},
};

use crate::{
    Gate, GateType, WireId,
    circuit::{CircuitMode, CircuitOutput, FALSE_WIRE, TRUE_WIRE},
    storage::{Credits, Storage},
};

#[derive(Debug, Default, Clone)]
pub struct ComponentStats {
    pub gates: u64,
    /// distinct ComponentKeys seen
    pub distinct_templates: usize,
    /// component instances entered
    pub instances: u64,
    /// deepest nesting observed
    pub max_depth: usize,
    /// instances whose gate range is empty (pure wiring, no gates)
    pub empty_instances: u64,
    /// gates directly in an instance, min/max/mean over non-empty instances
    pub min_span: u64,
    pub max_span: u64,
    sum_span: u128,
    pub n_span: u64,
    /// top-level (depth-1) instances that started before the previous one ended
    pub overlapping_top: u64,
    /// per-template instance counts, for the size of the template table
    pub per_template: HashMap<[u8; 8], u64>,
    /// Is wire_c monotonically increasing with gate index? If the streaming
    /// allocator recycles wire ids, topology cannot be expressed in wire ids
    /// and descriptors must reference producing GATES instead.
    pub wire_c_monotonic: bool,
    pub wire_c_reused: u64,
    pub max_wire_id: u64,
    pub last_wire_c: u64,
    /// gates whose inputs are not both produced earlier in this instance,
    /// i.e. they cross an instance boundary and need a per-instance binding
    pub cross_boundary_inputs: u64,
}

impl ComponentStats {
    pub fn mean_span(&self) -> f64 {
        if self.n_span == 0 { 0.0 } else { self.sum_span as f64 / self.n_span as f64 }
    }
}

#[derive(Debug)]
pub struct ComponentStatsMode {
    storage: Storage<WireId, Option<bool>>,
    gate_index: u64,
    /// stack of (key, gate_index at entry)
    open: Vec<([u8; 8], u64)>,
    last_top_end: u64,
    pub stats: ComponentStats,
    handle: Arc<Mutex<ComponentStats>>,
}

impl ComponentStatsMode {
    pub fn new(capacity: usize, handle: Arc<Mutex<ComponentStats>>) -> Self {
        Self {
            storage: Storage::new(capacity),
            gate_index: 0,
            open: Vec::new(),
            last_top_end: 0,
            stats: ComponentStats::default(),
            handle,
        }
    }

    fn publish(&self) {
        if let Ok(mut h) = self.handle.lock() {
            *h = self.stats.clone();
        }
    }
}

impl CircuitMode for ComponentStatsMode {
    type WireValue = bool;
    type CiphertextAcc = ();

    fn false_value(&self) -> bool { false }
    fn true_value(&self) -> bool { true }

    fn allocate_wire(&mut self, credits: Credits) -> WireId {
        self.storage.allocate(None, credits)
    }

    fn note_component_enter(&mut self, key: [u8; 8]) {
        self.open.push((key, self.gate_index));
        self.stats.instances += 1;
        *self.stats.per_template.entry(key).or_insert(0) += 1;
        self.stats.distinct_templates = self.stats.per_template.len();
        if self.open.len() > self.stats.max_depth {
            self.stats.max_depth = self.open.len();
        }
        // a top-level instance starting before the previous one ended would
        // break the contiguity the O(1) mapping needs
        if self.open.len() == 1 && self.gate_index < self.last_top_end {
            self.stats.overlapping_top += 1;
        }
    }

    fn note_component_exit(&mut self, _key: [u8; 8]) {
        if let Some((_k, start)) = self.open.pop() {
            let span = self.gate_index.saturating_sub(start);
            if span == 0 {
                self.stats.empty_instances += 1;
            } else {
                if self.stats.n_span == 0 || span < self.stats.min_span {
                    self.stats.min_span = span;
                }
                if span > self.stats.max_span { self.stats.max_span = span; }
                self.stats.sum_span += span as u128;
                self.stats.n_span += 1;
            }
            if self.open.is_empty() {
                self.last_top_end = self.gate_index;
            }
        }
    }

    fn evaluate_gate(&mut self, gate: &Gate) {
        let a = self.lookup_wire(gate.wire_a).unwrap_or(false);
        let b = self.lookup_wire(gate.wire_b).unwrap_or(false);
        if gate.wire_c == WireId::UNREACHABLE {
            return;
        }
        self.gate_index += 1;
        self.stats.gates += 1;

        // wire-id stability: decisive for how descriptors can be encoded
        let wc = gate.wire_c.0 as u64;
        if self.stats.gates == 1 { self.stats.wire_c_monotonic = true; }
        if wc <= self.stats.last_wire_c && self.stats.gates > 1 {
            self.stats.wire_c_monotonic = false;
            self.stats.wire_c_reused += 1;
        }
        self.stats.last_wire_c = wc;
        if wc > self.stats.max_wire_id { self.stats.max_wire_id = wc; }

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

        if self.gate_index % (1 << 23) == 0 {
            self.publish();
            eprintln!(
                "  [component_stats] {} gates, instances={} templates={} depth={} span {}..{}",
                self.gate_index, self.stats.instances, self.stats.distinct_templates,
                self.stats.max_depth, self.stats.min_span, self.stats.max_span
            );
        }
    }

    fn lookup_wire(&mut self, wire: WireId) -> Option<bool> {
        match wire {
            TRUE_WIRE => return Some(true),
            FALSE_WIRE => return Some(false),
            WireId::UNREACHABLE => return None,
            _ => (),
        }
        match self.storage.get(wire).as_deref() {
            Ok(Some(v)) => Some(*v),
            _ => None,
        }
    }

    fn feed_wire(&mut self, wire: WireId, value: bool) {
        if matches!(wire, TRUE_WIRE | FALSE_WIRE | WireId::UNREACHABLE) {
            return;
        }
        self.storage.set(wire, |e| *e = Some(value)).unwrap();
    }

    fn add_credits(&mut self, wires: &[WireId], credits: NonZero<Credits>) {
        for w in wires {
            self.storage.add_credits(*w, credits.get()).unwrap();
        }
    }

    fn finalize_ciphertext_accumulator(self) -> Self::CiphertextAcc {
        self.publish();
    }
}

impl CircuitOutput<ComponentStatsMode> for bool {
    type WireRepr = WireId;
    fn decode(wire: Self::WireRepr, cache: &mut ComponentStatsMode) -> Self {
        cache.lookup_wire(wire).unwrap_or_else(|| panic!("Can't find {wire:?}"))
    }
}
