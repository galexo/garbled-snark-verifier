//! Gate hashers used by garbling/degabbling, moved to crate root.
//! These mirror the previous implementations under core::gate::garbling::hashers
//! without functional changes.

use sha2::{Digest, Sha256};

use crate::{S, core::s::S_SIZE};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HasherKind {
    Blake3,
    AesNi,
}

pub mod aes_ni;
pub mod sha256;

// Re-export label commit hashers and trait for public API
pub use sha256::{
    AesLabelCommitHasher, Commit, DefaultLabelCommitHasher, LabelCommitHasher,
    Sha256LabelCommitHasher, commit_label_with,
};

pub trait GateHasher: HashWithGate<1> + HashWithGate<2> {}
impl<H: HashWithGate<1> + HashWithGate<2>> GateHasher for H {}

pub trait HashWithGate<const N: usize>: Clone + Send + Sync {
    fn hash_with_gate(labels: &[S; N], gate_id: usize) -> [S; N];
}

#[derive(Clone, Debug, Default)]
pub struct Blake3Hasher;

#[inline(always)]
fn blake3_gate_prf(label: S, gate_id: usize) -> S {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&label.to_bytes());
    hasher.update(&gate_id.to_le_bytes());

    let mut out = [0u8; S_SIZE];
    // finalize() via Digest returns a GenericArray; slice directly without heap allocs.
    let hash = hasher.finalize();
    out.copy_from_slice(&hash[..S_SIZE]);

    S::from_bytes(out)
}

impl HashWithGate<2> for Blake3Hasher {
    fn hash_with_gate(labels: &[S; 2], gate_id: usize) -> [S; 2] {
        let [selected_label, other_label] = labels;

        let h_selected = blake3_gate_prf(*selected_label, gate_id);
        let h_other = blake3_gate_prf(*other_label, gate_id);

        [h_selected, h_other]
    }
}

impl HashWithGate<1> for Blake3Hasher {
    fn hash_with_gate(label: &[S; 1], gate_id: usize) -> [S; 1] {
        [blake3_gate_prf(label[0], gate_id)]
    }
}

#[derive(Clone, Debug, Default)]
pub struct AesNiHasher;

#[inline(always)]
pub(crate) fn to_tweak(gate_id: usize) -> [u8; S_SIZE] {
    let gate_id_u64 = gate_id as u64;

    let t0 = gate_id_u64 ^ 0x1234_5678_9ABC_DEF0u64;
    let t1 = gate_id_u64.wrapping_mul(0xDEAD_BEEF_CAFE_BABEu64);

    u64_to_mask(t0, t1)
}

impl HashWithGate<2> for AesNiHasher {
    #[inline(always)]
    fn hash_with_gate(labels: &[S; 2], gate_id: usize) -> [S; 2] {
        let (c0, c1) = aes_ni::aes128_encrypt2_blocks_static_xor(
            labels[0].to_bytes(),
            labels[1].to_bytes(),
            to_tweak(gate_id),
        )
        .expect("AES backend should be available (HW or software)");

        [S::from_bytes(c0), S::from_bytes(c1)]
    }
}

impl HashWithGate<1> for AesNiHasher {
    #[inline(always)]
    fn hash_with_gate(label: &[S; 1], gate_id: usize) -> [S; 1] {
        let c = aes_ni::aes128_encrypt_block_static_xor(label[0].to_bytes(), to_tweak(gate_id))
            .expect("AES backend should be available (HW or software)");
        [S::from_bytes(c)]
    }
}

/// Double-AES hasher: AES(AES(label ^ tweak)) using the same static key.
#[derive(Clone, Debug, Default)]
pub struct DoubleAesNiHasher;

impl HashWithGate<2> for DoubleAesNiHasher {
    #[inline(always)]
    fn hash_with_gate(labels: &[S; 2], gate_id: usize) -> [S; 2] {
        let tweak = to_tweak(gate_id);
        // Inner: e_i = AES(x_i) via zero mask.
        let (e0, e1) = aes_ni::aes128_encrypt2_blocks_static_xor(
            labels[0].to_bytes(),
            labels[1].to_bytes(),
            [0u8; S_SIZE],
        )
        .expect("AES backend should be available (HW or software)");

        // Outer: o_i = AES(e_i ⊕ tweak).
        let (mut o0, mut o1) = aes_ni::aes128_encrypt2_blocks_static_xor(e0, e1, tweak)
            .expect("AES backend should be available (HW or software)");

        // H(x, tweak) = AES(AES(x) ⊕ tweak) ⊕ AES(x)
        for i in 0..S_SIZE {
            o0[i] ^= e0[i];
            o1[i] ^= e1[i];
        }

        [S::from_bytes(o0), S::from_bytes(o1)]
    }
}

/// SHA-256 based gate hasher derived from RustCrypto/hashes.
#[derive(Clone, Debug, Default)]
pub struct Sha256GateHasher;

#[inline(always)]
fn sha256_gate_prf(label: S, gate_id: usize, domain: u8) -> S {
    let mut hasher = Sha256::new();
    hasher.update(label.to_bytes());
    hasher.update(gate_id.to_le_bytes());
    hasher.update([domain]);

    let digest = hasher.finalize();
    let mut out = [0u8; S_SIZE];
    out.copy_from_slice(&digest[..S_SIZE]);

    S::from_bytes(out)
}

impl HashWithGate<2> for Sha256GateHasher {
    #[inline(always)]
    fn hash_with_gate(labels: &[S; 2], gate_id: usize) -> [S; 2] {
        [
            sha256_gate_prf(labels[0], gate_id, 0),
            sha256_gate_prf(labels[1], gate_id, 1),
        ]
    }
}

impl HashWithGate<1> for Sha256GateHasher {
    #[inline(always)]
    fn hash_with_gate(label: &[S; 1], gate_id: usize) -> [S; 1] {
        [sha256_gate_prf(label[0], gate_id, 0)]
    }
}

impl HashWithGate<1> for DoubleAesNiHasher {
    #[inline(always)]
    fn hash_with_gate(label: &[S; 1], gate_id: usize) -> [S; 1] {
        let tweak = to_tweak(gate_id);
        // Inner: e = AES(x) via zero mask.
        let e = aes_ni::aes128_encrypt_block_static_xor(label[0].to_bytes(), [0u8; S_SIZE])
            .expect("AES backend should be available (HW or software)");

        // Outer: o = AES(e ⊕ tweak).
        let mut o = aes_ni::aes128_encrypt_block_static_xor(e, tweak)
            .expect("AES backend should be available (HW or software)");

        // H(x, tweak) = AES(AES(x) ⊕ tweak) ⊕ AES(x)
        for i in 0..S_SIZE {
            o[i] ^= e[i];
        }

        [S::from_bytes(o)]
    }
}

#[inline(always)]
fn u64_to_mask(t0: u64, t1: u64) -> [u8; S_SIZE] {
    // Build mask in the same lane order as _mm_set_epi64x(t1, t0)
    let mut m = [0u8; S_SIZE];
    m[..8].copy_from_slice(&t0.to_le_bytes());
    m[8..].copy_from_slice(&t1.to_le_bytes());
    m
}
