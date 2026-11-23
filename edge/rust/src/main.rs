//! GigaMesh Edge Data-Plane Agent (Rust Candidate)
//! Copyright (C) 2026 Adam Dryden and Quanumis Systems. Licensed AGPL-3.0-or-later OR Commercial.
//!
//! Zero-dependency, memory-safe, GC-free industrial OT edge security middleware:
//! - FIPS 180-4 SHA-256 + RFC 2104 HMAC-SHA256 (constant-time verification)
//! - Sparkplug B (spBv1.0) Birth-Certificate SHA-256 pinning (NBIRTH/DBIRTH)
//! - Digital Physics Safety Envelopes (min/max, slew-rate, immutable safety interlocks)
//! - Anti-replay nonce registry & IT-to-OT AI crossover blocker
//! - Offline signed policy bundle verifier (`--verify-bundle <path>`)
//! - High-throughput deterministic battle-test benchmark (`--bench <N>`)

use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::time::Instant;

// ---------------------------------------------------------------------------
// Clean FIPS 180-4 SHA-256 & RFC 2104 HMAC-SHA256 (zero external crates)
// ---------------------------------------------------------------------------
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let bit_len = (data.len() as u64) * 8;
    let mut padded = Vec::with_capacity(((data.len() + 9 + 63) / 64) * 64);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[4 * i], chunk[4 * i + 1], chunk[4 * i + 2], chunk[4 * i + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g; g = f; f = e; e = d.wrapping_add(t1);
            d = c; c = b; b = a; a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a); h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c); h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e); h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g); h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k_block = [0u8; 64];
    if key.len() > 64 {
        let hashed = sha256(key);
        k_block[..32].copy_from_slice(&hashed);
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }
    let mut i_pad = Vec::with_capacity(64 + msg.len());
    let mut o_pad = [0u8; 96];
    for i in 0..64 {
        i_pad.push(k_block[i] ^ 0x36);
        o_pad[i] = k_block[i] ^ 0x5c;
    }
    i_pad.extend_from_slice(msg);
    let inner = sha256(&i_pad);
    o_pad[64..96].copy_from_slice(&inner);
    sha256(&o_pad)
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}

// ---------------------------------------------------------------------------
// Sparkplug B + Digital Physics Safety Envelope Engine
// ---------------------------------------------------------------------------
struct Envelope {
    min_val: f64,
    max_val: f64,
    max_delta_per_sec: f64,
    interlock_lock: bool,
    last_val: f64,
    has_last: bool,
}

struct EdgeEngine {
    secret: Vec<u8>,
    birth_pins: HashMap<String, [u8; 32]>,
    envelopes: HashMap<String, Envelope>,
    seen_nonces: HashSet<String>,
}

impl EdgeEngine {
    fn new(secret: &[u8]) -> Self {
        let mut envelopes = HashMap::new();
        envelopes.insert(
            "Boiler/PressureSetpointPSI".to_string(),
            Envelope { min_val: 15.0, max_val: 145.0, max_delta_per_sec: 12.0, interlock_lock: false, last_val: 95.0, has_last: true },
        );
        envelopes.insert(
            "Boiler/EmergencyReliefInterlock".to_string(),
            Envelope { min_val: 0.0, max_val: 0.0, max_delta_per_sec: 0.0, interlock_lock: true, last_val: 0.0, has_last: false },
        );
        envelopes.insert(
            "Line3/ConveyorSpeedRPM".to_string(),
            Envelope { min_val: 0.0, max_val: 180.0, max_delta_per_sec: 35.0, interlock_lock: false, last_val: 110.0, has_last: true },
        );
        Self {
            secret: secret.to_vec(),
            birth_pins: HashMap::with_capacity(256),
            envelopes,
            seen_nonces: HashSet::with_capacity(131072),
        }
    }

    fn sign_command(&self, topic: &str, sender: &str, nonce: &str, metric: &str, val: f64) -> [u8; 32] {
        let msg = format!("{}|{}|{}|{}|{:.4}", topic, sender, nonce, metric, val);
        hmac_sha256(&self.secret, msg.as_bytes())
    }

    // 0 = allow, 1 = allow_with_alert, 2 = block
    fn inspect(&mut self, topic: &str, sender: &str, nonce: &str, metric: &str, val: f64, sig: &[u8; 32], ai_tainted: bool) -> u8 {
        let mut parts = topic.split('/');
        let ns = match parts.next() { Some(v) => v, None => return 2 };
        let group = match parts.next() { Some(v) => v, None => return 2 };
        let msg_type = match parts.next() { Some(v) => v, None => return 2 };
        let edge_node = match parts.next() { Some(v) => v, None => return 2 };
        if ns != "spBv1.0" {
            return 2;
        }
        let device = parts.next();

        if msg_type == "NBIRTH" || msg_type == "DBIRTH" || msg_type == "NDATA" || msg_type == "DDATA" {
            if msg_type == "NBIRTH" || msg_type == "DBIRTH" {
                let node_key = match device {
                    Some(d) => format!("{}/{}/{}", group, edge_node, d),
                    None => format!("{}/{}", group, edge_node),
                };
                let schema_hash = sha256(format!("{}:Double", metric).as_bytes());
                if let Some(prev) = self.birth_pins.get(&node_key) {
                    if prev != &schema_hash {
                        return 1;
                    }
                } else {
                    self.birth_pins.insert(node_key, schema_hash);
                }
            }
            if let Some(env) = self.envelopes.get_mut(metric) {
                env.last_val = val;
                env.has_last = true;
            }
            return 0;
        }

        if msg_type != "NCMD" && msg_type != "DCMD" {
            return 2;
        }
        if ai_tainted {
            return 2;
        }
        let expected = self.sign_command(topic, sender, nonce, metric, val);
        if !ct_eq(sig, &expected) {
            return 2;
        }
        if !self.seen_nonces.insert(nonce.to_string()) {
            return 2;
        }

        if let Some(env) = self.envelopes.get_mut(metric) {
            if env.interlock_lock {
                return 2;
            }
            if val < env.min_val || val > env.max_val {
                return 2;
            }
            if env.has_last && (val - env.last_val).abs() > env.max_delta_per_sec {
                return 2;
            }
            env.last_val = val;
            env.has_last = true;
        }
        0
    }
}

fn extract_json_str<'a>(raw: &'a str, key: &str) -> Option<&'a str> {
    let pat = format!("\"{}\"", key);
    let idx = raw.find(&pat)?;
    let rest = &raw[idx + pat.len()..];
    let colon = rest.find(':')?;
    let after = rest[colon + 1..].trim_start();
    let after_q = after.strip_prefix('"')?;
    let end_q = after_q.find('"')?;
    Some(&after_q[..end_q])
}

fn verify_bundle_file(path: &str, secret: &[u8]) -> Result<(), String> {
    let raw = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let ver = extract_json_str(&raw, "bundle_version").ok_or("missing bundle_version")?;
    let sha = extract_json_str(&raw, "bundle_sha256").ok_or("missing bundle_sha256")?;
    let sig = extract_json_str(&raw, "signature").ok_or("missing signature")?;
    let expected = to_hex(&hmac_sha256(secret, sha.as_bytes()));
    if !ct_eq(sig.as_bytes(), expected.as_bytes()) {
        return Err("invalid bundle signature".to_string());
    }
    println!("VERIFIED offline bundle {} (sha256={})", ver, &sha[..sha.len().min(12)]);
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let secret = b"gigamesh-edge-offline-bundle-v1";
    let mut bench_n: usize = 100_000;

    let mut i = 1;
    while i < args.len() {
        if args[i] == "--verify-bundle" && i + 1 < args.len() {
            if let Err(e) = verify_bundle_file(&args[i + 1], secret) {
                eprintln!("ERR: {}", e);
                std::process::exit(1);
            }
            return;
        } else if args[i] == "--bench" && i + 1 < args.len() {
            bench_n = args[i + 1].parse().unwrap_or(100_000);
            i += 1;
        }
        i += 1;
    }

    let mut eng = EdgeEngine::new(secret);
    let mut latencies: Vec<u128> = Vec::with_capacity(bench_n);
    let (mut allowed, mut alerts, mut blocked) = (0usize, 0usize, 0usize);
    let zero_sig = [0u8; 32];

    eng.inspect("spBv1.0/PlantAustin/DBIRTH/Edge01/Boiler01", "edge01", "", "Boiler/PressureSetpointPSI", 95.0, &zero_sig, false);

    let start_all = Instant::now();
    for idx in 0..bench_n {
        let t0 = Instant::now();
        let res = match idx % 5 {
            0 | 1 => eng.inspect("spBv1.0/PlantAustin/DDATA/Edge01/Boiler01", "edge01", "", "Boiler/PressureSetpointPSI", 95.0 + (idx % 5) as f64, &zero_sig, false),
            2 => {
                let nonce = format!("n-{}", idx);
                let val = 96.0 + (idx % 4) as f64;
                let sig = eng.sign_command("spBv1.0/PlantAustin/DCMD/Edge01/Boiler01", "eng-android", &nonce, "Boiler/PressureSetpointPSI", val);
                eng.inspect("spBv1.0/PlantAustin/DCMD/Edge01/Boiler01", "eng-android", &nonce, "Boiler/PressureSetpointPSI", val, &sig, false)
            }
            3 => {
                let nonce = format!("atk-{}", idx);
                let sig = eng.sign_command("spBv1.0/PlantAustin/DCMD/Edge01/Boiler01", "compromised-hmi", &nonce, "Boiler/PressureSetpointPSI", 260.0);
                eng.inspect("spBv1.0/PlantAustin/DCMD/Edge01/Boiler01", "compromised-hmi", &nonce, "Boiler/PressureSetpointPSI", 260.0, &sig, false)
            }
            _ => eng.inspect("spBv1.0/PlantAustin/DCMD/Edge01/Boiler01", "ai-copilot", "ai-n", "Boiler/PressureSetpointPSI", 100.0, &zero_sig, true),
        };
        latencies.push(t0.elapsed().as_nanos());
        match res {
            0 => allowed += 1,
            1 => alerts += 1,
            _ => blocked += 1,
        }
    }
    let elapsed = start_all.elapsed();
    latencies.sort_unstable();

    let p50 = latencies[bench_n * 50 / 100];
    let p95 = latencies[bench_n * 95 / 100];
    let p99 = latencies[bench_n * 99 / 100];
    let p999 = latencies[bench_n * 999 / 1000];
    let tps = (bench_n as f64 / elapsed.as_secs_f64()).round();
    let elapsed_ms = (elapsed.as_micros() as f64) / 1000.0;

    println!(
        "{{\"runtime\":\"rust\",\"messages\":{},\"elapsed_ms\":{:.3},\"throughput\":{:.0},\"p50_ns\":{},\"p95_ns\":{},\"p99_ns\":{},\"p999_ns\":{},\"allowed\":{},\"alerts\":{},\"blocked\":{}}}",
        bench_n, elapsed_ms, tps, p50, p95, p99, p999, allowed, alerts, blocked
    );
}
