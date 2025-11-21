//! Safer garbling mode that uses BLAKE3 for half-gate hashing.
//! Uses the existing streaming garbling pipeline but binds the hasher to
//! [`Blake3Hasher`] for domain-separated hashing of labels and gate ids.

pub use garble_mode::{GarbledTableEntry, GarbledWire};

use crate::{
    circuit::{CiphertextHandler, modes::garble_mode},
    core::progress::maybe_log_progress,
    hashers::Blake3Hasher,
};

/// Streaming garbling mode that hashes each half-gate input with BLAKE3.
///
/// This is a thin alias over the existing [`garble_mode::GarbleMode`] with
/// a fixed `Blake3Hasher`. It keeps the same API surface, so existing
/// builders can use it by plugging the type parameter.
pub type SafeGarbleMode<CTH> = garble_mode::GarbleMode<Blake3Hasher, CTH>;

impl<CTH: CiphertextHandler> SafeGarbleMode<CTH> {
    /// Progress hook used by `.scripts/garble_monitor.py` to mirror the original garble logging.
    #[inline(always)]
    #[allow(dead_code)]
    pub(crate) fn log_progress(gate_id: usize) {
        maybe_log_progress("garbled", gate_id);
    }
}
