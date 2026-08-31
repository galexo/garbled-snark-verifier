// Which 256-bit hash is fastest for 64-byte Merkle nodes?
// BLAKE3's advantage is tree-parallelism on large inputs; at 64 B the
// per-call cost dominates, and this CPU has SHA-NI.
use sha2::{Digest, Sha256};

const N: usize = 20_000_000;

fn main() {
    let a = [0x5au8; 32];
    let b = [0xa5u8; 32];

    let t = std::time::Instant::now();
    let mut acc = [0u8; 32];
    for i in 0..N {
        let mut buf = [0u8; 68];
        buf[..32].copy_from_slice(&a);
        buf[32..64].copy_from_slice(&b);
        buf[64..].copy_from_slice(&(i as u32).to_le_bytes());
        acc = *blake3::hash(&buf).as_bytes();
    }
    let blake = t.elapsed().as_secs_f64();
    std::hint::black_box(acc);

    let t = std::time::Instant::now();
    let mut acc2 = [0u8; 32];
    for i in 0..N {
        let mut h = Sha256::new();
        h.update(a); h.update(b); h.update((i as u32).to_le_bytes());
        let d = h.finalize(); acc2.copy_from_slice(&d[..]);
    }
    let sha = t.elapsed().as_secs_f64();
    std::hint::black_box(acc2);

    println!("{N} x 68-byte 2-to-1 compression, single thread:");
    println!("  blake3   {:>8.2} s   {:>8.1} ns/op   {:.2}M ops/s", blake, blake*1e9/N as f64, N as f64/blake/1e6);
    println!("  sha2     {:>8.2} s   {:>8.1} ns/op   {:.2}M ops/s", sha,   sha*1e9/N as f64,   N as f64/sha/1e6);
    println!("  ratio    sha2/blake3 = {:.2}x", sha/blake);
    println!();
    println!("2,714,835,821 leaves + ~2.7B internal = ~5.43B ops");
    println!("  blake3 1 thread: {:.0} s   16 threads: {:.0} s", 5.43e9*blake/N as f64, 5.43e9*blake/N as f64/16.0);
    println!("  sha2   1 thread: {:.0} s   16 threads: {:.0} s", 5.43e9*sha/N as f64,   5.43e9*sha/N as f64/16.0);
}
