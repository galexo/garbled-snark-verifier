// Anchored garbling of a real circuit under the scheme phi_mis_anchor_real.c
// checks, in Rust, so the pipeline is not capped by the Python generator.
//
// gen_anchor_real.py implements the same scheme but costs 33.6 s and 2.38 GB at
// 3M gates, which extrapolates to 32 hours and 8.2 TB for the whole verifier --
// a ceiling, not a slow path. This produces byte-identical output and is the
// prerequisite for any full-scale run.
//
// Scheme (all SHA-256, matching the predicate exactly):
//   delta    = PRF(seed, TAG_DELTA, 0) with LSB forced
//   label(w) = PRF(seed, TAG_LABEL0, w)               circuit input
//   non-free = anchor(g)  = PRF(seed, TAG_ANCHOR, g)
//   promoted = xanchor(g) = PRF(seed, TAG_XANCH,  g)  K-bounded free wire
//   Xor/Xnor/Not are free; Xnor and Not fold in delta
//   H(A,g)   = SHA256(A || g_le32)[0..16]
//   T = H(A0,g)^H(A1,g)^B0^ab*D    C0 = H(A0^aa*D,g)^ac*D    r = C0^anchor(g)
//   leaf = SHA256(T || r)[0..20],  node = SHA256(l || r)[0..20]
//
// Usage: anchor_witness <topo.bin> --skip N [--K 1024] [--gate G]
//                       [--corrupt none|table|offset|seed|decommit|path|freegate]
//                       [--rom PATH] [--witness PATH]

use std::{collections::HashMap, env, fs, io::Write};

use sha2::{Digest, Sha256};

const NODE: usize = 20;
const TAG_LABEL0: u8 = 0x01;
const TAG_DELTA: u8 = 0x02;
const TAG_ANCHOR: u8 = 0x03;
const TAG_XANCH: u8 = 0x05;
const TAG_SEEDCOM: u8 = 0x07;
const INPUT_FLAG: u32 = 0x8000_0000;
const PROMOTED: u32 = 0x100;
const DESC_OFF: usize = 80;
const T_XOR: u32 = 8;
const T_XNOR: u32 = 9;
const T_NOT: u32 = 10;

#[inline]
fn is_free(t: u32) -> bool { t >= T_XOR }

#[inline]
fn sha(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts { h.update(p); }
    h.finalize().into()
}

fn prf16(seed: &[u8; 32], tag: u8, idx: u32) -> [u8; 16] {
    // idx as le32 then four explicit zero bytes: the C side shifts a 32-bit idx
    // and RISC-V masks shifts to 5 bits, so the high half must not derive from it
    let d = sha(&[seed, &[tag], &idx.to_le_bytes(), &[0u8; 4]]);
    let mut o = [0u8; 16]; o.copy_from_slice(&d[..16]); o
}

fn hgate(a: &[u8; 16], g: u32) -> [u8; 16] {
    let d = sha(&[a, &g.to_le_bytes()]);
    let mut o = [0u8; 16]; o.copy_from_slice(&d[..16]); o
}

fn leaf_of(t: &[u8; 16], r: &[u8; 16]) -> [u8; NODE] {
    let d = sha(&[t, r]);
    let mut o = [0u8; NODE]; o.copy_from_slice(&d[..NODE]); o
}

fn node_of(l: &[u8; NODE], r: &[u8; NODE]) -> [u8; NODE] {
    let d = sha(&[l, r]);
    let mut o = [0u8; NODE]; o.copy_from_slice(&d[..NODE]); o
}

#[inline]
fn xor16(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut o = [0u8; 16];
    for i in 0..16 { o[i] = a[i] ^ b[i]; }
    o
}

fn arg<'a>(a: &'a [String], n: &str) -> Option<&'a String> {
    a.iter().position(|x| x == n).and_then(|i| a.get(i + 1))
}
fn argn(a: &[String], n: &str, d: usize) -> usize {
    arg(a, n).and_then(|v| v.parse().ok()).unwrap_or(d)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let topo = args.get(1).expect("usage: anchor_witness <topo.bin> --skip N");
    let skip = argn(&args, "--skip", 0) as u32;
    let k = argn(&args, "--K", 1024);
    let want_gate = arg(&args, "--gate").and_then(|v| v.parse::<i64>().ok()).unwrap_or(-1);
    let corrupt = arg(&args, "--corrupt").cloned().unwrap_or_else(|| "none".into());
    let rom_path = arg(&args, "--rom").cloned().unwrap_or_else(|| "anchor_rom_real.bin".into());
    let wit_path = arg(&args, "--witness").cloned().unwrap_or_else(|| "witness_real.hex".into());

    let raw = fs::read(topo).expect("read topo");
    let ng = raw.len() / 12;
    let rd = |i: usize, o: usize| -> u32 {
        u32::from_le_bytes([raw[12*i+o], raw[12*i+o+1], raw[12*i+o+2], raw[12*i+o+3]])
    };

    // ---- resolve sources into the predicate's wire convention.
    // A window references gates produced before it; those wires are free inputs
    // of the slice, so each gets its own input index and the slice is closed.
    let mut base_inputs = 0u32;
    for i in 0..ng {
        for o in [4, 8] {
            let s = rd(i, o);
            if s & INPUT_FLAG != 0 { base_inputs = base_inputs.max((s & !INPUT_FLAG) + 1); }
        }
    }
    let mut extern_map: HashMap<u32, u32> = HashMap::new();
    for i in 0..ng {
        for o in [4, 8] {
            let s = rd(i, o);
            if s & INPUT_FLAG == 0 && s < skip && !extern_map.contains_key(&s) {
                let n = base_inputs + extern_map.len() as u32;
                extern_map.insert(s, n);
            }
        }
    }
    let nin = base_inputs + extern_map.len() as u32;
    let w_of = |s: u32| -> u32 {
        if s & INPUT_FLAG != 0 { s & !INPUT_FLAG }
        else if s < skip { extern_map[&s] }
        else { nin + (s - skip) }
    };
    let desc: Vec<(u32, u32, u32)> =
        (0..ng).map(|i| (rd(i, 0), w_of(rd(i, 4)), w_of(rd(i, 8)))).collect();

    // ---- K-bounding, with supports dropped at each wire's last use so memory
    // tracks the live set rather than the whole circuit.
    let mut promoted = vec![false; ng];
    if k > 0 {
        let mut last_use: HashMap<u32, usize> = HashMap::new();
        for (g, &(ty, wa, wb)) in desc.iter().enumerate() {
            last_use.insert(wa, g);
            if ty != T_NOT { last_use.insert(wb, g); }
        }
        let mut supp: HashMap<u32, Vec<u32>> = HashMap::new();
        for w in 0..nin { supp.insert(w, vec![w]); }
        let empty: Vec<u32> = Vec::new();
        for (g, &(ty, wa, wb)) in desc.iter().enumerate() {
            let out = nin + g as u32;
            if is_free(ty) {
                let sa = supp.get(&wa).unwrap_or(&empty);
                let sb = if ty == T_NOT { &empty } else { supp.get(&wb).unwrap_or(&empty) };
                // sorted merge, aborting as soon as the union exceeds K
                let mut u: Vec<u32> = Vec::with_capacity(sa.len() + sb.len());
                let (mut i, mut j) = (0usize, 0usize);
                while i < sa.len() || j < sb.len() {
                    let v = if j >= sb.len() { let v = sa[i]; i += 1; v }
                            else if i >= sa.len() { let v = sb[j]; j += 1; v }
                            else if sa[i] < sb[j] { let v = sa[i]; i += 1; v }
                            else if sa[i] > sb[j] { let v = sb[j]; j += 1; v }
                            else { let v = sa[i]; i += 1; j += 1; v };
                    if u.last() != Some(&v) { u.push(v); }
                    if u.len() > k { break; }
                }
                if u.len() > k { promoted[g] = true; supp.insert(out, vec![out]); }
                else { supp.insert(out, u); }
            } else {
                supp.insert(out, vec![out]);
            }
            let ins: &[u32] = if ty == T_NOT { &[wa] } else { &[wa, wb] };
            for wv in ins {
                if last_use.get(wv) == Some(&g) { supp.remove(wv); }
            }
        }
        let n_free = desc.iter().filter(|d| is_free(d.0)).count();
        let n_prom = promoted.iter().filter(|p| **p).count();
        println!("K-bounding K={k}: promoted {n_prom} of {n_free} free gates ({:.1}%)",
                 100.0 * n_prom as f64 / n_free.max(1) as f64);
    }

    // ---- garble
    let seed: [u8; 32] = core::array::from_fn(|i| i as u8);
    let dec = [0x5au8; 32];
    let mut delta = prf16(&seed, TAG_DELTA, 0);
    delta[0] |= 1;

    let filler = { let d = sha(&[&[0xffu8; 32]]); let mut o = [0u8; NODE]; o.copy_from_slice(&d[..NODE]); o };
    let mut lbl: Vec<[u8; 16]> = Vec::with_capacity(nin as usize + ng);
    for w in 0..nin { lbl.push(prf16(&seed, TAG_LABEL0, w)); }
    let mut leaves: Vec<[u8; NODE]> = Vec::with_capacity(ng);
    let mut n_leaf = 0usize;

    let half_gate = |lbl: &Vec<[u8; 16]>, ty: u32, wa: u32, wb: u32, g: u32| {
        let (aa, ab, ac) = ((ty >> 2) & 1, (ty >> 1) & 1, ty & 1);
        let a0 = lbl[wa as usize];
        let b0 = lbl[wb as usize];
        let ha0 = hgate(&a0, g);
        let ha1 = hgate(&xor16(&a0, &delta), g);
        let mut t = xor16(&xor16(&ha0, &ha1), &b0);
        if ab == 1 { t = xor16(&t, &delta); }
        let mut c0 = if aa == 1 { ha1 } else { ha0 };
        if ac == 1 { c0 = xor16(&c0, &delta); }
        (t, xor16(&c0, &prf16(&seed, TAG_ANCHOR, g)))
    };

    for (gi, &(ty, wa, wb)) in desc.iter().enumerate() {
        let g = gi as u32;
        if promoted[gi] {
            lbl.push(prf16(&seed, TAG_XANCH, g)); leaves.push(filler);
        } else if ty == T_XOR {
            lbl.push(xor16(&lbl[wa as usize], &lbl[wb as usize])); leaves.push(filler);
        } else if ty == T_XNOR {
            lbl.push(xor16(&xor16(&lbl[wa as usize], &lbl[wb as usize]), &delta)); leaves.push(filler);
        } else if ty == T_NOT {
            lbl.push(xor16(&lbl[wa as usize], &delta)); leaves.push(filler);
        } else {
            let (t, r) = half_gate(&lbl, ty, wa, wb, g);
            lbl.push(prf16(&seed, TAG_ANCHOR, g));
            leaves.push(leaf_of(&t, &r));
            n_leaf += 1;
        }
    }

    // ---- contested gate
    let gsel: usize = if want_gate >= 0 { want_gate as usize }
        else if corrupt == "freegate" {
            desc.iter().enumerate().position(|(i, d)| is_free(d.0) && !promoted[i]).expect("no free gate")
        } else {
            (0..ng).rev().find(|&i| !is_free(desc[i].0) && !promoted[i]).expect("no contestable gate")
        };

    let mut depth = 1usize;
    while (1usize << depth) < ng { depth += 1; }

    let (ty, wa, wb) = desc[gsel];
    let (mut tg, mut rg) = if !is_free(ty) && !promoted[gsel] {
        half_gate(&lbl, ty, wa, wb, gsel as u32)
    } else { ([0u8; 16], [0u8; 16]) };

    // a cheating GARBLER commits the wrong table, so the corruption enters the
    // tree; corrupting only the witness makes the leaf fail to open, which is a
    // verdict against the accuser and a different test
    if corrupt == "table"  { tg[0] ^= 1; leaves[gsel] = leaf_of(&tg, &rg); }
    if corrupt == "offset" { rg[0] ^= 1; leaves[gsel] = leaf_of(&tg, &rg); }

    // ---- Merkle tree
    let mut levels: Vec<Vec<[u8; NODE]>> = Vec::with_capacity(depth + 1);
    let mut cur = leaves;
    cur.resize(1usize << depth, filler);
    levels.push(cur);
    for d in 0..depth {
        let prev = &levels[d];
        let mut nxt = Vec::with_capacity(prev.len() / 2);
        for i in (0..prev.len()).step_by(2) { nxt.push(node_of(&prev[i], &prev[i + 1])); }
        levels.push(nxt);
    }
    let root = levels[depth][0];

    let mut path = Vec::with_capacity(depth * NODE);
    { let mut idx = gsel;
      for d in 0..depth { path.extend_from_slice(&levels[d][idx ^ 1]); idx >>= 1; } }
    if corrupt == "path" { path[0] ^= 1; }

    let mut wseed = seed; let mut wdec = dec;
    if corrupt == "seed" { wseed[0] ^= 1; }
    if corrupt == "decommit" { wdec[31] ^= 0xff; }
    let com_seed = sha(&[&[TAG_SEEDCOM], &seed[..], &dec[..]]);

    // ---- ROM
    let mut rom = Vec::with_capacity(DESC_OFF + ng * 12);
    rom.extend_from_slice(&nin.to_be_bytes());
    rom.extend_from_slice(&(ng as u32).to_be_bytes());
    rom.extend_from_slice(&(depth as u32).to_be_bytes());
    rom.extend_from_slice(&(DESC_OFF as u32).to_be_bytes());
    rom.extend_from_slice(&root); rom.extend_from_slice(&[0u8; 32 - NODE]);
    rom.extend_from_slice(&com_seed);
    assert_eq!(rom.len(), DESC_OFF);
    for (i, &(ty, wa, wb)) in desc.iter().enumerate() {
        let t = ty | if promoted[i] { PROMOTED } else { 0 };
        rom.extend_from_slice(&t.to_be_bytes());
        rom.extend_from_slice(&wa.to_be_bytes());
        rom.extend_from_slice(&wb.to_be_bytes());
    }
    fs::File::create(&rom_path).unwrap().write_all(&rom).unwrap();

    let mut wit = Vec::new();
    wit.extend_from_slice(&wseed); wit.extend_from_slice(&wdec);
    wit.extend_from_slice(&(gsel as u64).to_be_bytes());
    wit.extend_from_slice(&tg); wit.extend_from_slice(&rg);
    wit.extend_from_slice(&path);
    fs::write(&wit_path, wit.iter().map(|b| format!("{b:02x}")).collect::<String>()).unwrap();

    let exp = match corrupt.as_str() {
        "none" => 0, "path" | "freegate" => 2, _ => 1,
    };
    println!("gates {ng} inputs {nin} leaves {n_leaf} depth {depth}");
    println!("{rom_path}: {} bytes   root {}", rom.len(),
             root.iter().map(|b| format!("{b:02x}")).collect::<String>());
    println!("{wit_path}: {} bytes   contested gate {gsel} (type {ty})", wit.len());
    println!("corrupt={corrupt}  EXPECT Halt({exp})");
}
