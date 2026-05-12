package csprng

import (
	crand "crypto/rand"
	"bytes"
	"sync"
	"testing"
)

func mustNew(t *testing.T) *DRBG {
	t.Helper()
	seed := make([]byte, SeedLen)
	if _, err := crand.Read(seed); err != nil {
		t.Fatal(err)
	}
	d, err := New(seed)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestNew_ShortEntropy(t *testing.T) {
	_, err := New(make([]byte, SeedLen-1))
	if err == nil {
		t.Fatal("expected error for short entropy, got nil")
	}
}

func TestGenerate_Basic(t *testing.T) {
	d := mustNew(t)
	got, err := d.Generate(64)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(got) != 64 {
		t.Fatalf("len = %d, want 64", len(got))
	}
	if allZero(got) {
		t.Fatal("Generate returned all-zero bytes")
	}
}

func TestGenerate_Zero(t *testing.T) {
	d := mustNew(t)
	got, err := d.Generate(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("Generate(0) returned %d bytes, want 0", len(got))
	}
}

func TestGenerate_Deterministic(t *testing.T) {
	seed := make([]byte, SeedLen)
	for i := range seed {
		seed[i] = byte(i + 1)
	}

	d1, err := New(seed)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := New(seed)
	if err != nil {
		t.Fatal(err)
	}

	out1, err := d1.Generate(128)
	if err != nil {
		t.Fatal(err)
	}
	out2, err := d2.Generate(128)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(out1, out2) {
		t.Fatal("same seed must produce identical outputs")
	}
}

func TestGenerate_DistinctOutputs(t *testing.T) {
	d := mustNew(t)
	a, err := d.Generate(32)
	if err != nil {
		t.Fatal(err)
	}
	b, err := d.Generate(32)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("consecutive Generate calls returned identical output")
	}
}

func TestReseed_ChangesOutput(t *testing.T) {
	seed := make([]byte, SeedLen)
	for i := range seed {
		seed[i] = byte(i + 1)
	}

	d1, _ := New(seed)
	d2, _ := New(seed)

	// Without reseed: same output.
	out1, _ := d1.Generate(32)
	out2, _ := d2.Generate(32)
	if !bytes.Equal(out1, out2) {
		t.Fatal("pre-reseed: same seed must produce same output")
	}

	// Reseed d2 with different entropy.
	newEntropy := make([]byte, SeedLen)
	for i := range newEntropy {
		newEntropy[i] = 0xFF
	}
	if err := d2.Reseed(newEntropy); err != nil {
		t.Fatalf("Reseed: %v", err)
	}

	out1After, _ := d1.Generate(32)
	out2After, _ := d2.Generate(32)
	if bytes.Equal(out1After, out2After) {
		t.Fatal("after reseed with different entropy, outputs must differ")
	}
}

func TestReseed_ShortEntropy(t *testing.T) {
	d := mustNew(t)
	if err := d.Reseed(make([]byte, SeedLen-1)); err == nil {
		t.Fatal("expected error for short reseed entropy")
	}
}

func TestHealthCheck_Valid(t *testing.T) {
	d := mustNew(t)
	if err := d.HealthCheck(); err != nil {
		t.Fatalf("HealthCheck on valid DRBG: %v", err)
	}
}

func TestHealthCheck_ZeroKey(t *testing.T) {
	// Craft a DRBG with an all-zero key (invalid state).
	d := &DRBG{}
	if err := d.HealthCheck(); err == nil {
		t.Fatal("HealthCheck must fail on all-zero key")
	}
}

func TestOutputBytes(t *testing.T) {
	d := mustNew(t)
	if d.OutputBytes() != 0 {
		t.Fatalf("initial OutputBytes = %d, want 0", d.OutputBytes())
	}
	if _, err := d.Generate(100); err != nil {
		t.Fatal(err)
	}
	if d.OutputBytes() != 100 {
		t.Fatalf("OutputBytes = %d, want 100", d.OutputBytes())
	}
	if _, err := d.Generate(56); err != nil {
		t.Fatal(err)
	}
	if d.OutputBytes() != 156 {
		t.Fatalf("OutputBytes = %d, want 156", d.OutputBytes())
	}
}

func TestConcurrent(t *testing.T) {
	d := mustNew(t)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if _, err := d.Generate(32); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// TestByteFrequency checks that 1 MB of output passes a chi-square frequency test.
// For 255 degrees of freedom, chi-square should be in [160, 340] with overwhelming
// probability for a good RNG (covers roughly ±5 standard deviations).
func TestByteFrequency(t *testing.T) {
	d := mustNew(t)

	const total = 1 << 20 // 1 MB
	data, err := d.Generate(total)
	if err != nil {
		t.Fatal(err)
	}

	var counts [256]int
	for _, b := range data {
		counts[b]++
	}

	expected := float64(total) / 256.0
	var chi2 float64
	for _, c := range counts {
		diff := float64(c) - expected
		chi2 += diff * diff / expected
	}

	// 255 df: E[χ²]=255, SD≈22.6. Range [160,340] ≈ ±4 SD.
	if chi2 < 160 || chi2 > 340 {
		t.Errorf("byte frequency chi-square = %.2f; expected ~255 in [160, 340] for 255 df", chi2)
	}
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
