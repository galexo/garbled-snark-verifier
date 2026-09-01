//! Export the verifier's REAL gate-indexed topology.
//!
//! Wire ids on this circuit are recycled slab indices (max id 144,527 across
//! 10.3e9 gates, 5.17e9 reuses), so a descriptor keyed on wire ids is
//! meaningless. The only sound encoding is gate-indexed:
//!
//!     gate g -> (type, src_a, src_b),  src in { GATE(j<g), INPUT(i) }
//!
//! This mode builds exactly that in one streaming pass, by keeping a live map
//! from wire id to whatever produced it. A wire that no gate has produced is a
//! circuit input and gets the next input index.
//!
//! It stops after `limit` gates so a prefix of a settlement-scale circuit can
//! be exported in bounded time and space: the full 10.4e9 gates would be 125 GB
//! of descriptors, while a prefix is a real, self-contained sub-circuit whose
//! gates and wiring are the verifier's own.
//!
//! Record format, little-endian, 12 bytes per gate:
//!     u32 type_code, u32 src_a, u32 src_b
//! with sources tagged by the high bit: INPUT_FLAG set = input index, clear =
//! producing gate index. The consumer rewrites these into the predicate's
//! `wire = NIN + gate` convention once NIN is known.

use std::{
    collections::HashMap,
    io::Write,
    num::NonZero,
    sync::{Arc, Mutex},
};

use crate::{
    Gate, GateType, WireId,
    circuit::{CircuitMode, CircuitOutput, FALSE_WIRE, TRUE_WIRE},
    storage::{Credits, Storage},
};

pub const INPUT_FLAG: u32 = 0x8000_0000;

/// The GateType discriminant itself, so the predicate sees the verifier's real
/// gate and not a lossy bucket. This circuit compiles to Nand and Cimp, never
/// to a literal And, so an AND-only encoding cannot contest any of its gates.
/// Odd-parity gates 0..=7 are all non-free and all cost one ciphertext under
/// privacy-free garbling; 8..=10 (Xor, Xnor, Not) are free.
fn type_code(t: &GateType) -> u32 {
    *t as u32
}

#[derive(Debug, Default, Clone, Copy)]
pub struct TopoStats {
    pub gates: u64,
    pub inputs: u64,
    pub and_gates: u64,
    pub free_gates: u64,
    pub nonfree_other: u64,
    /// sources that resolved to a circuit input rather than an earlier gate
    pub input_srcs: u64,
}

#[derive(Debug)]
pub struct TopoExportMode<W: Write + Send> {
    storage: Storage<WireId, Option<bool>>,
    /// wire id -> encoded source (INPUT_FLAG|idx, or gate index)
    src: HashMap<WireId, u32>,
    next_input: u32,
    gate_index: u64,
    limit: u64,
    skip: u64,
    out: W,
    pub stats: TopoStats,
    handle: Arc<Mutex<TopoStats>>,
}

impl<W: Write + Send> TopoExportMode<W> {
    pub fn new(capacity: usize, limit: u64, skip: u64, out: W, handle: Arc<Mutex<TopoStats>>) -> Self {
        Self {
            storage: Storage::new(capacity),
            src: HashMap::new(),
            next_input: 0,
            gate_index: 0,
            limit,
            skip,
            out,
            stats: TopoStats::default(),
            handle,
        }
    }

    fn publish(&self) {
        if let Ok(mut h) = self.handle.lock() {
            *h = self.stats;
        }
    }

    /// A wire no gate has produced is a circuit input; give it the next index.
    fn source_of(&mut self, w: WireId) -> u32 {
        if let Some(s) = self.src.get(&w) {
            return *s;
        }
        let s = INPUT_FLAG | self.next_input;
        self.next_input += 1;
        self.stats.inputs += 1;
        self.src.insert(w, s);
        s
    }
}

impl<W: Write + Send + std::fmt::Debug> CircuitMode for TopoExportMode<W> {
    type WireValue = bool;
    type CiphertextAcc = ();

    fn false_value(&self) -> bool { false }
    fn true_value(&self) -> bool { true }

    fn allocate_wire(&mut self, credits: Credits) -> WireId {
        self.storage.allocate(None, credits)
    }

    fn evaluate_gate(&mut self, gate: &Gate) {
        let a = self.source_of(gate.wire_a);
        let b = self.source_of(gate.wire_b);

        let _va = self.lookup_wire(gate.wire_a).unwrap_or(false);
        let _vb = self.lookup_wire(gate.wire_b).unwrap_or(false);
        if gate.wire_c == WireId::UNREACHABLE {
            return;
        }

        let g = self.gate_index;
        self.gate_index += 1;

        let ty = type_code(&gate.gate_type);
        if gate.gate_type.is_free() { self.stats.free_gates += 1; }
        else if ty == 0 { self.stats.and_gates += 1; }
        else { self.stats.nonfree_other += 1; }
        if a & INPUT_FLAG != 0 { self.stats.input_srcs += 1; }
        if b & INPUT_FLAG != 0 { self.stats.input_srcs += 1; }

        if g >= self.skip {
            let mut rec = [0u8; 12];
            rec[0..4].copy_from_slice(&ty.to_le_bytes());
            rec[4..8].copy_from_slice(&a.to_le_bytes());
            rec[8..12].copy_from_slice(&b.to_le_bytes());
            self.out.write_all(&rec).expect("write descriptor");
            self.stats.gates += 1;
        }

        // this gate now produces wire_c; later gates referencing it resolve here
        self.src.insert(gate.wire_c, g as u32);
        self.feed_wire(gate.wire_c, false);

        if self.gate_index % (1 << 20) == 0 {
            self.publish();
            eprintln!(
                "  [topo_export] {} gates, inputs={} and={} free={} other={}",
                self.gate_index, self.stats.inputs, self.stats.and_gates,
                self.stats.free_gates, self.stats.nonfree_other
            );
        }
        if self.gate_index >= self.skip + self.limit {
            self.out.flush().expect("flush");
            self.publish();
            eprintln!("  [topo_export] limit {} reached", self.limit);
            std::process::exit(0);
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

impl<W: Write + Send + std::fmt::Debug> CircuitOutput<TopoExportMode<W>> for bool {
    type WireRepr = WireId;
    fn decode(wire: Self::WireRepr, cache: &mut TopoExportMode<W>) -> Self {
        cache.lookup_wire(wire).unwrap_or(false)
    }
}
