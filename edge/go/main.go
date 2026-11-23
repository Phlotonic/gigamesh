// GigaMesh Edge Data-Plane Agent (Go Candidate)
// Copyright (C) 2026 Adam Dryden and Quanumis Systems. Licensed AGPL-3.0-or-later OR Commercial.
//
// Implements offline-resilient Sparkplug B (spBv1.0) security middleware:
// - Birth-Certificate SHA-256 pinning (NBIRTH/DBIRTH)
// - End-to-end HMAC-SHA256 command signature verification (constant-time) + anti-replay nonces
// - Digital Physics Safety Envelopes (min/max, slew-rate, immutable safety interlocks)
// - Signed Offline Policy Bundle verifier (`--verify-bundle`)
// - High-throughput deterministic battle-test benchmark (`--bench N`)
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"time"
)

type Envelope struct {
	MinVal         float64
	MaxVal         float64
	MaxDeltaPerSec float64
	InterlockLock  bool
	LastVal        float64
	HasLast        bool
}

type EdgeEngine struct {
	secret     []byte
	birthPins  map[string][32]byte
	envelopes  map[string]*Envelope
	seenNonces map[string]struct{}
}

func NewEdgeEngine(secret []byte) *EdgeEngine {
	return &EdgeEngine{
		secret:     secret,
		birthPins:  make(map[string][32]byte, 256),
		seenNonces: make(map[string]struct{}, 131072),
		envelopes: map[string]*Envelope{
			"Boiler/PressureSetpointPSI":     {MinVal: 15.0, MaxVal: 145.0, MaxDeltaPerSec: 12.0, LastVal: 95.0, HasLast: true},
			"Boiler/EmergencyReliefInterlock": {InterlockLock: true},
			"Line3/ConveyorSpeedRPM":         {MinVal: 0.0, MaxVal: 180.0, MaxDeltaPerSec: 35.0, LastVal: 110.0, HasLast: true},
		},
	}
}

func (e *EdgeEngine) SignCommand(topic, sender, nonce, metric string, val float64) [32]byte {
	mac := hmac.New(sha256.New, e.secret)
	fmt.Fprintf(mac, "%s|%s|%s|%s|%.4f", topic, sender, nonce, metric, val)
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

// Inspect returns: 0=allow, 1=allow_with_alert, 2=block
func (e *EdgeEngine) Inspect(topic, sender, nonce, metric string, val float64, sig [32]byte, aiTainted bool) int {
	parts := strings.Split(topic, "/")
	if len(parts) < 4 || parts[0] != "spBv1.0" {
		return 2
	}
	msgType := parts[2]
	nodeKey := parts[1] + "/" + parts[3]
	if len(parts) >= 5 {
		nodeKey += "/" + parts[4]
	}

	// Telemetry path: fail-open passive inspection + Birth-Certificate SHA-256 pinning
	if msgType == "NBIRTH" || msgType == "DBIRTH" || msgType == "NDATA" || msgType == "DDATA" {
		if msgType == "NBIRTH" || msgType == "DBIRTH" {
			h := sha256.Sum256([]byte(metric + ":Double"))
			if prev, ok := e.birthPins[nodeKey]; ok {
				if prev != h {
					return 1 // allow_with_alert (tampered birth schema)
				}
			} else {
				e.birthPins[nodeKey] = h
			}
		}
		if env, ok := e.envelopes[metric]; ok {
			env.LastVal = val
			env.HasLast = true
		}
		return 0
	}

	// Actuation path (NCMD / DCMD): fail-closed inline cryptographic & physical verification
	if msgType != "NCMD" && msgType != "DCMD" {
		return 2
	}
	if aiTainted {
		return 2 // IT-to-OT AI crossover blocked
	}
	expected := e.SignCommand(topic, sender, nonce, metric, val)
	if subtle.ConstantTimeCompare(sig[:], expected[:]) != 1 {
		return 2
	}
	if _, replayed := e.seenNonces[nonce]; replayed {
		return 2
	}
	e.seenNonces[nonce] = struct{}{}

	if env, ok := e.envelopes[metric]; ok {
		if env.InterlockLock {
			return 2
		}
		if val < env.MinVal || val > env.MaxVal {
			return 2
		}
		if env.HasLast && math.Abs(val-env.LastVal) > env.MaxDeltaPerSec {
			return 2
		}
		env.LastVal = val
		env.HasLast = true
	}
	return 0
}

type OfflineBundle struct {
	BundleVersion string `json:"bundle_version"`
	BundleSHA256  string `json:"bundle_sha256"`
	Signature     string `json:"signature"`
}

func verifyBundleFile(path string, secret []byte) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var b OfflineBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return err
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(b.BundleSHA256))
	exp := hex.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(b.Signature), []byte(exp)) != 1 {
		return fmt.Errorf("invalid bundle signature")
	}
	fmt.Printf("VERIFIED offline bundle %s (sha256=%s)\n", b.BundleVersion, b.BundleSHA256[:12])
	return nil
}

func main() {
	benchN := flag.Int("bench", 100000, "Number of Sparkplug B frames to battle-test")
	bundlePath := flag.String("verify-bundle", "", "Path to signed offline policy bundle JSON")
	flag.Parse()

	secret := []byte("gigamesh-edge-offline-bundle-v1")
	if *bundlePath != "" {
		if err := verifyBundleFile(*bundlePath, secret); err != nil {
			fmt.Fprintf(os.Stderr, "ERR: %v\n", err)
			os.Exit(1)
		}
		return
	}

	eng := NewEdgeEngine(secret)
	n := *benchN
	latencies := make([]int64, n)
	var allowed, alerts, blocked int

	// Seed initial DBIRTH
	var zeroSig [32]byte
	eng.Inspect("spBv1.0/PlantAustin/DBIRTH/Edge01/Boiler01", "edge01", "", "Boiler/PressureSetpointPSI", 95.0, zeroSig, false)

	startAll := time.Now()
	for i := 0; i < n; i++ {
		t0 := time.Now()
		var res int
		switch i % 5 {
		case 0, 1: // 40% high-rate telemetry NDATA (fail-open passive)
			res = eng.Inspect("spBv1.0/PlantAustin/DDATA/Edge01/Boiler01", "edge01", "", "Boiler/PressureSetpointPSI", 95.0+float64(i%5), zeroSig, false)
		case 2: // 20% valid signed admin DCMD within physical bounds
			nonce := fmt.Sprintf("n-%d", i)
			val := 96.0 + float64(i%4)
			sig := eng.SignCommand("spBv1.0/PlantAustin/DCMD/Edge01/Boiler01", "eng-android", nonce, "Boiler/PressureSetpointPSI", val)
			res = eng.Inspect("spBv1.0/PlantAustin/DCMD/Edge01/Boiler01", "eng-android", nonce, "Boiler/PressureSetpointPSI", val, sig, false)
		case 3: // 20% unsafe physics / interlock attack (260 PSI)
			nonce := fmt.Sprintf("atk-%d", i)
			sig := eng.SignCommand("spBv1.0/PlantAustin/DCMD/Edge01/Boiler01", "compromised-hmi", nonce, "Boiler/PressureSetpointPSI", 260.0)
			res = eng.Inspect("spBv1.0/PlantAustin/DCMD/Edge01/Boiler01", "compromised-hmi", nonce, "Boiler/PressureSetpointPSI", 260.0, sig, false)
		case 4: // 20% IT-to-OT AI crossover attempt
			res = eng.Inspect("spBv1.0/PlantAustin/DCMD/Edge01/Boiler01", "ai-copilot", "ai-n", "Boiler/PressureSetpointPSI", 100.0, zeroSig, true)
		}
		latencies[i] = time.Since(t0).Nanoseconds()
		switch res {
		case 0:
			allowed++
		case 1:
			alerts++
		default:
			blocked++
		}
	}
	elapsed := time.Since(startAll)
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })

	p50 := latencies[n*50/100]
	p95 := latencies[n*95/100]
	p99 := latencies[n*99/100]
	p999 := latencies[n*999/1000]
	tps := float64(n) / elapsed.Seconds()

	out := map[string]any{
		"runtime":     "go",
		"messages":    n,
		"elapsed_ms":  float64(elapsed.Microseconds()) / 1000.0,
		"throughput":  math.Round(tps),
		"p50_ns":      p50,
		"p95_ns":      p95,
		"p99_ns":      p99,
		"p999_ns":     p999,
		"allowed":     allowed,
		"alerts":      alerts,
		"blocked":     blocked,
	}
	enc, _ := json.Marshal(out)
	fmt.Println(string(enc))
}
