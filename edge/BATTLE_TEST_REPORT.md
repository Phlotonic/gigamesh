# GigaMesh Edge Data-Plane Battle Test: Go vs. Rust

**Copyright © 2026 Adam Dryden and Quanumis Systems**

Both candidates implement the identical zero-dependency Sparkplug B (`spBv1.0`) industrial OT security engine:
- Birth-Certificate SHA-256 pinning (`NBIRTH` / `DBIRTH`)
- Constant-time HMAC-SHA256 end-to-end command signature verification + anti-replay nonce registry
- Digital Physics Safety Envelopes (`min_value`, `max_value`, `max_delta_per_sec`, immutable safety interlock locks)
- IT-to-OT AI crossover taint blocker
- Signed offline policy bundle verification (`--verify-bundle`)

## Empirical Results (200,000 Sparkplug B Frames on Linux x86_64)

Workload mix: 40% high-rate `DDATA` telemetry (fail-open passive), 20% valid signed admin `DCMD`, 20% unsafe Digital Physics `DCMD` (260 PSI sabotage), 20% IT-to-OT AI crossover attempts (`120,000` allowed, `80,000` blocked — identical verdicts on both runtimes).

| Metric | Go (`go 1.24.3`) | Rust (`rustc 1.100.0`, LTO + strip) | Winner |
| :--- | :---: | :---: | :--- |
| **Throughput** | 333,420 msg/sec | **344,345 msg/sec** | **Rust (+3.3%)** |
| **Median Latency (P50)** | 374 ns | **136 ns** | **Rust (2.75× faster)** |
| **P95 Latency** | **6.43 µs** | 7.63 µs | Go |
| **P99 Latency** | **11.90 µs** | 14.14 µs | Go |
| **Extreme Tail Latency (P99.9)** | 68.75 µs | **48.18 µs** | **Rust (30% lower tail)** |
| **Peak Memory (RSS)** | 23,068 KB (22.5 MB) | **12,980 KB (12.7 MB)** | **Rust (44% less RAM)** |
| **Stripped Binary Size** | 2,172.2 KB (2.12 MB) | **355.8 KB (0.35 MB)** | **Rust (6.1× smaller)** |
| **Clean Release Build Time** | 11.67 s | **6.65 s** | **Rust (1.75× faster)** |
| **Offline Bundle Verification** | Verified (`pol-c8fcead656a7`) | Verified (`pol-c8fcead656a7`) | Tie |
| **GC-Free Determinism (OT/PLC)** | No (runtime GC) | **Yes (zero GC pauses)** | **Rust** |
| **Android JNI / Embedded Shared Lib** | Complex (`gomobile`) | **Native (`cdylib` / `uniffi`)** | **Rust** |
| **Cross-Compile Simplicity** | **Single env var (`GOOS`/`GOARCH`)** | Requires target toolchain (`musl`/`cross`) | **Go** |

## Darwinian Verdict: **Rust (`gigamesh-edge-rust`) Wins as Primary Edge Runtime**

- **Why Rust wins for GigaMesh's edge-to-edge mission**:
  1. **6.1× smaller binary (`355.8 KB`)** and **44% lower RAM (`12.7 MB`)** fit comfortably on constrained ARM64 factory gateways, Ignition Edge devices, and embedded IoT nodes.
  2. **2.75× faster P50 (`136 ns`)** and **30% lower P99.9 tail latency (`48.2 µs`)** with **zero garbage-collection pauses** for real-time industrial control networks.
  3. **Native Android / iOS FFI**: The exact same Rust verification core can be compiled as a `.so`/`.a` library directly inside the Capacitor Android app (sharing one verified cryptographic/physics engine from Android phone to factory PLC!).
- **Why we retain `edge/go/` as a secondary reference**: Go's P95/P99 stayed very tight (`6.4–11.9 µs`) and Go excels for rapid IT/cloud cross-compilation where `GOOS`/`GOARCH` convenience is prized.
