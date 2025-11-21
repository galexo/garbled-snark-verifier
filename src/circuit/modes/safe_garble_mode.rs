//! Safer garbling mode that forces two AES invocations per half-gate hash.
//! Uses the existing streaming garbling pipeline but binds the hasher to
//! [`DoubleAesNiHasher`] to compute `AES(AES(label ^ tweak))`.

pub use garble_mode::{GarbledTableEntry, GarbledWire};

use crate::{
    circuit::{CiphertextHandler, modes::garble_mode},
    core::progress::maybe_log_progress,
    hashers::DoubleAesNiHasher,
};

/// Streaming garbling mode that always performs two AES calls per gate.
///
/// This is a thin alias over the existing [`garble_mode::GarbleMode`] with
/// a fixed `DoubleAesNiHasher`. It keeps the same API surface, so existing
/// builders can use it by plugging the type parameter.
pub type SafeGarbleMode<CTH> = garble_mode::GarbleMode<DoubleAesNiHasher, CTH>;

impl<CTH: CiphertextHandler> SafeGarbleMode<CTH> {
    /// Progress hook used by `.scripts/garble_monitor.py` to mirror the original garble logging.
    #[inline(always)]
    #[allow(dead_code)]
    pub(crate) fn log_progress(gate_id: usize) {
        maybe_log_progress("garbled", gate_id);
    }
}
