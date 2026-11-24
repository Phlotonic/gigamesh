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
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
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
// Zero-Allocation MQTT 5.0 Wildcard Matcher (`+` single-level, `#` multi-level)
// ---------------------------------------------------------------------------
fn mqtt_topic_matches(pattern: &str, topic: &str) -> bool {
    let mut p_iter = pattern.split('/').filter(|s| !s.is_empty());
    let mut t_iter = topic.split('/').filter(|s| !s.is_empty());
    loop {
        match (p_iter.next(), t_iter.next()) {
            (Some("#"), _) => return p_iter.next().is_none(),
            (Some("+"), Some(_)) => continue,
            (Some(p), Some(t)) if p == t => continue,
            (None, None) => return true,
            _ => return false,
        }
    }
}

fn is_uns_command_topic(topic: &str) -> bool {
    for seg in topic.split('/') {
        if seg.eq_ignore_ascii_case("Commands")
            || seg.eq_ignore_ascii_case("Command")
            || seg.eq_ignore_ascii_case("CMD")
            || seg.eq_ignore_ascii_case("Setpoints")
            || seg.eq_ignore_ascii_case("Control")
        {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Dual-Mode Sparkplug B + ISA-95 Unified Namespace (S-UNS) Policy Engine
// ---------------------------------------------------------------------------
struct Envelope {
    min_val: f64,
    max_val: f64,
    max_delta_per_sec: f64,
    interlock_lock: bool,
    last_val: f64,
    has_last: bool,
}

struct UnsPolicy {
    pattern: String,
    enabled: bool,
    require_e2e_sig: bool,
    block_ai_tainted: bool,
    read_only_lockdown: bool,
    interlock_lock: bool,
    min_val: Option<f64>,
    max_val: Option<f64>,
    max_delta_per_sec: Option<f64>,
}

struct EdgeEngine {
    secret: Vec<u8>,
    birth_pins: HashMap<String, [u8; 32]>,
    envelopes: HashMap<String, Envelope>,
    uns_policies: Vec<UnsPolicy>,
    uns_last_vals: HashMap<String, f64>,
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

        let uns_policies = vec![
            UnsPolicy {
                pattern: "QuanumisCorp/+/+/+/+/+/Commands/#".to_string(),
                enabled: true,
                require_e2e_sig: true,
                block_ai_tainted: true,
                read_only_lockdown: false,
                interlock_lock: false,
                min_val: None,
                max_val: None,
                max_delta_per_sec: None,
            },
            UnsPolicy {
                pattern: "QuanumisCorp/+/+/+/+/+/Commands/EmergencyReliefInterlock".to_string(),
                enabled: true,
                require_e2e_sig: true,
                block_ai_tainted: true,
                read_only_lockdown: false,
                interlock_lock: true,
                min_val: None,
                max_val: None,
                max_delta_per_sec: None,
            },
            UnsPolicy {
                pattern: "QuanumisCorp/AustinPlant/ThermalArea/+/+/+/Commands/PressureSetpointPSI".to_string(),
                enabled: true,
                require_e2e_sig: false,
                block_ai_tainted: false,
                read_only_lockdown: false,
                interlock_lock: false,
                min_val: Some(15.0),
                max_val: Some(145.0),
                max_delta_per_sec: Some(12.0),
            },
            UnsPolicy {
                pattern: "QuanumisCorp/MunichPlant/AssemblyArea/+/+/+/Commands/ConveyorSpeedRPM".to_string(),
                enabled: true,
                require_e2e_sig: false,
                block_ai_tainted: false,
                read_only_lockdown: false,
                interlock_lock: false,
                min_val: Some(0.0),
                max_val: Some(160.0),
                max_delta_per_sec: Some(30.0),
            },
        ];

        let mut uns_last_vals = HashMap::with_capacity(256);
        uns_last_vals.insert(
            "QuanumisCorp/AustinPlant/ThermalArea/Line3/BoilerCell/BoilerPLC01/Telemetry/PressureSetpointPSI".to_string(),
            95.0,
        );
        uns_last_vals.insert(
            "QuanumisCorp/MunichPlant/AssemblyArea/Line1/RobotCell/RobotCell04/Telemetry/ConveyorSpeedRPM".to_string(),
            120.0,
        );

        Self {
            secret: secret.to_vec(),
            birth_pins: HashMap::with_capacity(256),
            envelopes,
            uns_policies,
            uns_last_vals,
            seen_nonces: HashSet::with_capacity(131072),
        }
    }

    fn set_site_lockdown(&mut self, enterprise: &str, site: &str, locked: bool) {
        let pat = format!("{}/{}/#", enterprise, site);
        for p in &mut self.uns_policies {
            if p.pattern == pat {
                p.enabled = locked;
                p.read_only_lockdown = locked;
                return;
            }
        }
        self.uns_policies.push(UnsPolicy {
            pattern: pat,
            enabled: locked,
            require_e2e_sig: false,
            block_ai_tainted: false,
            read_only_lockdown: locked,
            interlock_lock: false,
            min_val: None,
            max_val: None,
            max_delta_per_sec: None,
        });
    }

    fn sign_command(&self, topic: &str, sender: &str, nonce: &str, metric: &str, val: f64) -> [u8; 32] {
        let msg = format!("{}|{}|{}|{}|{:.4}", topic, sender, nonce, metric, val);
        hmac_sha256(&self.secret, msg.as_bytes())
    }

    // 0 = allow, 1 = allow_with_alert, 2 = block
    fn inspect(&mut self, topic: &str, sender: &str, nonce: &str, metric: &str, val: f64, sig: &[u8; 32], ai_tainted: bool) -> u8 {
        if topic.starts_with("spBv1.0/") {
            return self.inspect_sparkplug(topic, sender, nonce, metric, val, sig, ai_tainted);
        }
        self.inspect_uns(topic, sender, nonce, metric, val, sig, ai_tainted)
    }

    fn inspect_uns(&mut self, topic: &str, sender: &str, nonce: &str, metric: &str, val: f64, sig: &[u8; 32], ai_tainted: bool) -> u8 {
        if !is_uns_command_topic(topic) {
            // Fail-open passive telemetry/state update
            self.uns_last_vals.insert(topic.to_string(), val);
            return 0;
        }

        // Monotonic strictest-wins wildcard policy resolution (Enterprise -> Site -> Area -> Asset)
        let mut req_sig = false;
        let mut block_ai = false;
        let mut lockdown = false;
        let mut interlock = false;
        let mut min_v: Option<f64> = None;
        let mut max_v: Option<f64> = None;
        let mut max_d: Option<f64> = None;

        for p in &self.uns_policies {
            if !p.enabled || !mqtt_topic_matches(&p.pattern, topic) {
                continue;
            }
            req_sig |= p.require_e2e_sig;
            block_ai |= p.block_ai_tainted;
            lockdown |= p.read_only_lockdown;
            interlock |= p.interlock_lock;
            if let Some(mn) = p.min_val {
                min_v = Some(match min_v { Some(cur) => cur.max(mn), None => mn });
            }
            if let Some(mx) = p.max_val {
                max_v = Some(match max_v { Some(cur) => cur.min(mx), None => mx });
            }
            if let Some(md) = p.max_delta_per_sec {
                max_d = Some(match max_d { Some(cur) => cur.min(md), None => md });
            }
        }

        if lockdown || interlock {
            return 2;
        }
        if block_ai && ai_tainted {
            return 2;
        }
        if req_sig {
            let expected = self.sign_command(topic, sender, nonce, metric, val);
            if !ct_eq(sig, &expected) {
                return 2;
            }
            if !self.seen_nonces.insert(nonce.to_string()) {
                return 2;
            }
        }
        if let Some(mn) = min_v {
            if val < mn { return 2; }
        }
        if let Some(mx) = max_v {
            if val > mx { return 2; }
        }
        if let Some(md) = max_d {
            let sibling = topic.replace("/Commands/", "/Telemetry/");
            if let Some(&prev) = self.uns_last_vals.get(&sibling).or_else(|| self.uns_last_vals.get(topic)) {
                if (val - prev).abs() > md {
                    return 2;
                }
            }
        }
        self.uns_last_vals.insert(topic.to_string(), val);
        0
    }

    fn inspect_sparkplug(&mut self, topic: &str, sender: &str, nonce: &str, metric: &str, val: f64, sig: &[u8; 32], ai_tainted: bool) -> u8 {
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
        // Check mapped UNS site lockdown if PlantAustin -> AustinPlant
        let mapped_site = if group == "PlantAustin" { "AustinPlant" } else if group == "PlantMunich" { "MunichPlant" } else { group };
        let probe_uns = format!("QuanumisCorp/{}/EdgeArea/{}/Cell0/{}/Commands/{}", mapped_site, edge_node, device.unwrap_or(edge_node), metric);
        for p in &self.uns_policies {
            if p.enabled && p.read_only_lockdown && mqtt_topic_matches(&p.pattern, &probe_uns) {
                return 2;
            }
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
    let ent = extract_json_str(&raw, "uns_enterprise").unwrap_or("QuanumisCorp");
    let expected = to_hex(&hmac_sha256(secret, sha.as_bytes()));
    if !ct_eq(sig.as_bytes(), expected.as_bytes()) {
        return Err("invalid bundle signature".to_string());
    }
    println!(
        "VERIFIED offline bundle {} (enterprise={}, sha256={})",
        ver,
        ent,
        &sha[..sha.len().min(12)]
    );
    Ok(())
}

fn run_uns_selftest(secret: &[u8]) -> Result<(), String> {
    if !mqtt_topic_matches("QuanumisCorp/+/+/+/+/+/Commands/#", "QuanumisCorp/MunichPlant/AssemblyArea/Line1/RobotCell/RobotCell04/Commands/ConveyorSpeedRPM") {
        return Err("wildcard +/# match failed".to_string());
    }
    if mqtt_topic_matches("QuanumisCorp/AustinPlant/#", "QuanumisCorp/MunichPlant/AssemblyArea/Line1/RobotCell/RobotCell04/Commands/ConveyorSpeedRPM") {
        return Err("site wildcard leaked across sites".to_string());
    }
    let mut eng = EdgeEngine::new(secret);
    let zero = [0u8; 32];
    let t_munich = "QuanumisCorp/MunichPlant/AssemblyArea/Line1/RobotCell/RobotCell04/Commands/ConveyorSpeedRPM";
    let t_austin = "QuanumisCorp/AustinPlant/ThermalArea/Line3/BoilerCell/BoilerPLC01/Commands/PressureSetpointPSI";

    // AI tainted write to Munich -> blocked by Enterprise wildcard policy
    if eng.inspect(t_munich, "ai-copilot", "n-ai", "ConveyorSpeedRPM", 125.0, &zero, true) != 2 {
        return Err("AI tainted UNS command was not blocked".to_string());
    }
    // Safe signed write to Austin -> allowed
    let sig_ok = eng.sign_command(t_austin, "eng-android", "n-ok1", "PressureSetpointPSI", 102.0);
    if eng.inspect(t_austin, "eng-android", "n-ok1", "PressureSetpointPSI", 102.0, &sig_ok, false) != 0 {
        return Err("valid signed UNS command was rejected".to_string());
    }
    // Enable 1-click AustinPlant Read-Only Lockdown -> Austin blocked, Munich still allowed!
    eng.set_site_lockdown("QuanumisCorp", "AustinPlant", true);
    let sig_locked = eng.sign_command(t_austin, "eng-android", "n-ok2", "PressureSetpointPSI", 103.0);
    if eng.inspect(t_austin, "eng-android", "n-ok2", "PressureSetpointPSI", 103.0, &sig_locked, false) != 2 {
        return Err("Austin lockdown failed to block Austin command".to_string());
    }
    let sig_m = eng.sign_command(t_munich, "munich-eng", "n-m1", "ConveyorSpeedRPM", 130.0);
    if eng.inspect(t_munich, "munich-eng", "n-m1", "ConveyorSpeedRPM", 130.0, &sig_m, false) != 0 {
        return Err("Austin lockdown erroneously blocked Munich".to_string());
    }
    println!("UNS_SELFTEST_PASSED dual_mode=sparkplug_b+isa95_uns wildcards=+/# lockdown=isolated");
    Ok(())
}

fn read_mqtt_packet<R: Read>(reader: &mut R) -> io::Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 1];
    reader.read_exact(&mut hdr)?;
    let mut rem_len: usize = 0;
    let mut mult: usize = 1;
    let mut raw = Vec::with_capacity(64);
    raw.push(hdr[0]);
    for _ in 0..4 {
        let mut b = [0u8; 1];
        reader.read_exact(&mut b)?;
        raw.push(b[0]);
        rem_len += ((b[0] & 0x7F) as usize) * mult;
        if (b[0] & 0x80) == 0 {
            break;
        }
        mult *= 128;
    }
    if rem_len > 2 * 1024 * 1024 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "MQTT packet exceeds 2MB cap"));
    }
    let body_start = raw.len();
    raw.resize(body_start + rem_len, 0);
    reader.read_exact(&mut raw[body_start..])?;
    Ok((hdr[0], raw))
}

fn parse_mqtt_publish(hdr: u8, raw: &[u8]) -> Option<(String, String)> {
    // Skip fixed header + remaining-length varint
    let mut idx = 1usize;
    while idx < raw.len() && (raw[idx] & 0x80) != 0 {
        idx += 1;
    }
    idx += 1; // step past last remaining-length byte
    if idx + 2 > raw.len() {
        return None;
    }
    let topic_len = u16::from_be_bytes([raw[idx], raw[idx + 1]]) as usize;
    idx += 2;
    if idx + topic_len > raw.len() {
        return None;
    }
    let topic = String::from_utf8_lossy(&raw[idx..idx + topic_len]).to_string();
    idx += topic_len;
    let qos = (hdr >> 1) & 0x03;
    if qos > 0 {
        if idx + 2 > raw.len() {
            return None;
        }
        idx += 2; // skip packet identifier
    }
    let payload = String::from_utf8_lossy(&raw[idx..]).to_string();
    Some((topic, payload))
}

fn decode_hex32(hex_str: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = hex_str.as_bytes();
    for i in 0..32 {
        if 2 * i + 1 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(&hex_str[2 * i..2 * i + 2], 16) {
                out[i] = v;
            }
        }
    }
    out
}

fn extract_json_f64(raw: &str, key: &str) -> Option<f64> {
    let pat = format!("\"{}\"", key);
    let idx = raw.find(&pat)?;
    let rest = &raw[idx + pat.len()..];
    let colon = rest.find(':')?;
    let after = rest[colon + 1..].trim_start();
    let end = after.find(|c: char| !c.is_ascii_digit() && c != '.' && c != '-').unwrap_or(after.len());
    after[..end].parse::<f64>().ok()
}

fn run_mqtt_tcp_proxy(listen_addr: &str, upstream_addr: &str, secret: &[u8]) -> Result<(), String> {
    let listener = TcpListener::bind(listen_addr).map_err(|e| format!("bind {}: {}", listen_addr, e))?;
    let engine = Arc::new(Mutex::new(EdgeEngine::new(secret)));
    println!("GIGAMESH_EDGE_PROXY_READY listen={} upstream={}", listen_addr, upstream_addr);
    let _ = io::stdout().flush();

    for stream in listener.incoming() {
        let mut client_r = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let upstream_str = upstream_addr.to_string();
        let eng_ref = Arc::clone(&engine);

        thread::spawn(move || {
            let mut up_w = match TcpStream::connect(&upstream_str) {
                Ok(u) => u,
                Err(_) => return,
            };
            let mut up_r = match up_w.try_clone() {
                Ok(u) => u,
                Err(_) => return,
            };
            let mut client_w = match client_r.try_clone() {
                Ok(c) => c,
                Err(_) => return,
            };

            // Server -> Client transparent forwarder
            let rev = thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n) = up_r.read(&mut buf) {
                    if n == 0 || client_w.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });

            // Client -> Server inline MQTT wire inspection (Sparkplug B + ISA-95 UNS)
            while let Ok((hdr, raw)) = read_mqtt_packet(&mut client_r) {
                let pkt_type = hdr >> 4;
                let mut forward = true;
                if pkt_type == 3 {
                    if let Some((topic, payload)) = parse_mqtt_publish(hdr, &raw) {
                        let sender = extract_json_str(&payload, "sender_id").unwrap_or("mqtt-client");
                        let nonce = extract_json_str(&payload, "nonce").unwrap_or("");
                        let sig_hex = extract_json_str(&payload, "signature").unwrap_or("");
                        let sig_bytes = decode_hex32(sig_hex);
                        let metric = extract_json_str(&payload, "metric")
                            .unwrap_or_else(|| topic.rsplit('/').next().unwrap_or("value"));
                        let val = extract_json_f64(&payload, "value")
                            .or_else(|| payload.trim().parse::<f64>().ok())
                            .unwrap_or(0.0);
                        let ai_tainted = payload.contains("\"ai_tainted\":true") || payload.contains("\"it_tainted\":true");

                        let verdict = if let Ok(mut guard) = eng_ref.lock() {
                            guard.inspect(&topic, sender, nonce, metric, val, &sig_bytes, ai_tainted)
                        } else {
                            2 // Fail-closed on lock poison
                        };
                        if verdict == 2 {
                            forward = false;
                            eprintln!("[GIGAMESH-PROXY BLOCKED] topic={} sender={}", topic, sender);
                        }
                    }
                }
                if forward && up_w.write_all(&raw).is_err() {
                    break;
                }
            }
            let _ = up_w.shutdown(std::net::Shutdown::Both);
            let _ = rev.join();
        });
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let secret_env = env::var("GIGAMESH_EDGE_BUNDLE_SECRET").unwrap_or_else(|_| "gigamesh-edge-offline-bundle-v1".to_string());
    let secret = secret_env.as_bytes();
    let mut bench_n: usize = 100_000;
    let mut proxy_mode = false;
    let mut listen_addr = "0.0.0.0:1883".to_string();
    let mut upstream_addr = "127.0.0.1:1884".to_string();
    let mut bundle_path: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        if args[i] == "--verify-bundle" && i + 1 < args.len() {
            if let Err(e) = verify_bundle_file(&args[i + 1], secret) {
                eprintln!("ERR: {}", e);
                std::process::exit(1);
            }
            return;
        } else if args[i] == "--test-uns" {
            if let Err(e) = run_uns_selftest(secret) {
                eprintln!("ERR: {}", e);
                std::process::exit(1);
            }
            return;
        } else if args[i] == "--proxy" {
            proxy_mode = true;
        } else if args[i] == "--listen" && i + 1 < args.len() {
            listen_addr = args[i + 1].clone();
            i += 1;
        } else if args[i] == "--upstream" && i + 1 < args.len() {
            upstream_addr = args[i + 1].clone();
            i += 1;
        } else if args[i] == "--bundle" && i + 1 < args.len() {
            bundle_path = Some(args[i + 1].clone());
            i += 1;
        } else if args[i] == "--bench" && i + 1 < args.len() {
            bench_n = args[i + 1].parse().unwrap_or(100_000);
            i += 1;
        }
        i += 1;
    }

    if proxy_mode {
        if let Some(ref bp) = bundle_path {
            if let Err(e) = verify_bundle_file(bp, secret) {
                eprintln!("FATAL: refusing to start proxy with invalid bundle: {}", e);
                std::process::exit(1);
            }
        }
        if let Err(e) = run_mqtt_tcp_proxy(&listen_addr, &upstream_addr, secret) {
            eprintln!("ERR: {}", e);
            std::process::exit(1);
        }
        return;
    }

    let mut eng = EdgeEngine::new(secret);
    let mut latencies: Vec<u128> = Vec::with_capacity(bench_n);
    let (mut allowed, mut alerts, mut blocked) = (0usize, 0usize, 0usize);
    let zero_sig = [0u8; 32];

    eng.inspect("spBv1.0/PlantAustin/DBIRTH/Edge01/Boiler01", "edge01", "", "Boiler/PressureSetpointPSI", 95.0, &zero_sig, false);

    let uns_telem = "QuanumisCorp/MunichPlant/AssemblyArea/Line1/RobotCell/RobotCell04/Telemetry/ConveyorSpeedRPM";
    let uns_cmd = "QuanumisCorp/MunichPlant/AssemblyArea/Line1/RobotCell/RobotCell04/Commands/ConveyorSpeedRPM";

    let start_all = Instant::now();
    for idx in 0..bench_n {
        let t0 = Instant::now();
        let res = match idx % 6 {
            0 => eng.inspect("spBv1.0/PlantAustin/DDATA/Edge01/Boiler01", "edge01", "", "Boiler/PressureSetpointPSI", 95.0 + (idx % 5) as f64, &zero_sig, false),
            1 => eng.inspect(uns_telem, "munich-edge", "", "ConveyorSpeedRPM", 118.0 + (idx % 5) as f64, &zero_sig, false),
            2 => {
                let nonce = format!("sp-{}", idx);
                let val = 96.0 + (idx % 4) as f64;
                let sig = eng.sign_command("spBv1.0/PlantAustin/DCMD/Edge01/Boiler01", "eng-android", &nonce, "Boiler/PressureSetpointPSI", val);
                eng.inspect("spBv1.0/PlantAustin/DCMD/Edge01/Boiler01", "eng-android", &nonce, "Boiler/PressureSetpointPSI", val, &sig, false)
            }
            3 => {
                let nonce = format!("uns-{}", idx);
                let val = 122.0 + (idx % 4) as f64;
                let sig = eng.sign_command(uns_cmd, "munich-eng", &nonce, "ConveyorSpeedRPM", val);
                eng.inspect(uns_cmd, "munich-eng", &nonce, "ConveyorSpeedRPM", val, &sig, false)
            }
            4 => {
                let nonce = format!("atk-{}", idx);
                let sig = eng.sign_command(uns_cmd, "compromised-hmi", &nonce, "ConveyorSpeedRPM", 260.0);
                eng.inspect(uns_cmd, "compromised-hmi", &nonce, "ConveyorSpeedRPM", 260.0, &sig, false)
            }
            _ => eng.inspect(uns_cmd, "ai-copilot", "ai-n", "ConveyorSpeedRPM", 125.0, &zero_sig, true),
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
        "{{\"runtime\":\"rust-dual-uns\",\"messages\":{},\"elapsed_ms\":{:.3},\"throughput\":{:.0},\"p50_ns\":{},\"p95_ns\":{},\"p99_ns\":{},\"p999_ns\":{},\"allowed\":{},\"alerts\":{},\"blocked\":{}}}",
        bench_n, elapsed_ms, tps, p50, p95, p99, p999, allowed, alerts, blocked
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uns_and_wildcards() {
        assert!(run_uns_selftest(b"gigamesh-edge-offline-bundle-v1").is_ok());
    }

    #[test]
    fn test_mqtt_publish_wire_parser() {
        let topic = b"QuanumisCorp/AustinPlant/ThermalArea/Line3/BoilerCell/BoilerPLC01/Telemetry/PressureSetpointPSI";
        let payload = b"{\"value\":98.5}";
        let rem_len = 2 + topic.len() + payload.len();
        let mut pkt = vec![0x30u8, rem_len as u8];
        pkt.extend_from_slice(&(topic.len() as u16).to_be_bytes());
        pkt.extend_from_slice(topic);
        pkt.extend_from_slice(payload);
        let (t, p) = parse_mqtt_publish(0x30, &pkt).expect("parse publish");
        assert!(t.ends_with("PressureSetpointPSI"));
        assert_eq!(extract_json_f64(&p, "value"), Some(98.5));
    }
}
