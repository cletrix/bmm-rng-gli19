package health

import (
	"context"
	"fmt"
	"log"
	"math"
	"sync"
	"time"
)

// RNG is the interface required by the self-tester.
// csprng.DRBG satisfies this interface.
type RNG interface {
	Generate(n uint64) ([]byte, error)
}

// Status classifies a p-value per CONTEXT.md thresholds.
type Status string

const (
	StatusPass     Status = "pass"
	StatusWarnLow  Status = "warn_low"  // p < 0.01 (suspicious non-randomness)
	StatusWarnHigh Status = "warn_high" // p > 0.999 (suspiciously uniform)
	StatusFail     Status = "fail"      // p < 0.001 (CRITICAL — pause generation)
)

// TestResult holds the outcome of one NIST SP 800-22 test run.
type TestResult struct {
	Name   string
	PValue float64
	Status Status
}

// SelfTester runs a subset of NIST SP 800-22 tests continuously in background.
//
// Tests run on a goroutine spawned by Start(). Results are read-safe via Results().
// If any test returns Status == StatusFail, the caller must pause generation.
type SelfTester struct {
	rng        RNG
	sampleSize uint64 // bytes to generate per run
	blockBits  int    // M (block size in bits) for Block Frequency test

	mu      sync.RWMutex
	results []TestResult
	lastRun time.Time
}

// NewSelfTester creates a SelfTester.
// sampleBytes is the number of random bytes generated per test run (min 1250 = 10000 bits).
func NewSelfTester(rng RNG, sampleBytes uint64) *SelfTester {
	if sampleBytes < 1250 {
		sampleBytes = 1250
	}
	return &SelfTester{
		rng:        rng,
		sampleSize: sampleBytes,
		blockBits:  128, // 128-bit blocks; N = sampleBytes*8/128 blocks
	}
}

// Start launches the background self-test loop.
// The loop runs immediately and then every interval.
// Cancel ctx to stop it.
func (s *SelfTester) Start(ctx context.Context, interval time.Duration) {
	go func() {
		s.runAndLog()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.runAndLog()
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (s *SelfTester) runAndLog() {
	results, err := s.RunAll()
	if err != nil {
		log.Printf("health: NIST self-test error: %v", err)
		return
	}
	s.mu.Lock()
	s.results = results
	s.lastRun = time.Now()
	s.mu.Unlock()

	for _, r := range results {
		switch r.Status {
		case StatusFail:
			log.Printf("CRITICAL: NIST %s p-value=%.6f — CSPRNG may be compromised; PAUSE GENERATION", r.Name, r.PValue)
		case StatusWarnLow, StatusWarnHigh:
			log.Printf("WARNING: NIST %s p-value=%.6f", r.Name, r.PValue)
		}
	}
}

// RunAll generates sampleSize bytes from the CSPRNG and runs all three tests.
// Returns one TestResult per test; error only if generation fails.
func (s *SelfTester) RunAll() ([]TestResult, error) {
	data, err := s.rng.Generate(s.sampleSize)
	if err != nil {
		return nil, fmt.Errorf("health: selftest generate: %w", err)
	}
	bits := bytesToBits(data)

	tests := []struct {
		name string
		fn   func([]byte) (float64, error)
	}{
		{"Frequency", frequencyTest},
		{"Runs", runsTest},
		{"BlockFrequency", func(b []byte) (float64, error) {
			return blockFrequencyTest(b, s.blockBits)
		}},
	}

	results := make([]TestResult, 0, len(tests))
	for _, t := range tests {
		p, err := t.fn(bits)
		if err != nil {
			// Non-fatal: record as warn so the test continues.
			results = append(results, TestResult{Name: t.name, PValue: 0, Status: StatusWarnLow})
			log.Printf("health: NIST %s error: %v", t.name, err)
			continue
		}
		results = append(results, TestResult{Name: t.name, PValue: p, Status: classify(p)})
	}
	return results, nil
}

// Results returns the latest test results and when they were last run.
// Returns nil if no test has been run yet.
func (s *SelfTester) Results() ([]TestResult, time.Time) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.results, s.lastRun
}

// HasCriticalFailure reports whether any test has Status == StatusFail.
func (s *SelfTester) HasCriticalFailure() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.results {
		if r.Status == StatusFail {
			return true
		}
	}
	return false
}

// ─── NIST SP 800-22 Tests ────────────────────────────────────────────────────

// frequencyTest implements NIST SP 800-22 Section 2.1 (Frequency / Monobit Test).
//
// Checks that the number of 1s and 0s in a bit stream is approximately equal.
// p-value = erfc(|S_n| / sqrt(n) / sqrt(2))
func frequencyTest(bits []byte) (float64, error) {
	n := len(bits)
	if n < 100 {
		return 0, fmt.Errorf("frequency: need >= 100 bits, got %d", n)
	}

	var sn int
	for _, b := range bits {
		if b == 1 {
			sn++
		} else {
			sn--
		}
	}

	sObs := math.Abs(float64(sn)) / math.Sqrt(float64(n))
	pValue := math.Erfc(sObs / math.Sqrt2)
	return pValue, nil
}

// runsTest implements NIST SP 800-22 Section 2.3 (Runs Test).
//
// Checks whether the number of runs (uninterrupted sequences of identical bits)
// is consistent with a random sequence. Requires pi ≈ 0.5 (prerequisite check).
func runsTest(bits []byte) (float64, error) {
	n := len(bits)
	if n < 100 {
		return 0, fmt.Errorf("runs: need >= 100 bits, got %d", n)
	}

	// Proportion of 1s.
	ones := 0
	for _, b := range bits {
		if b == 1 {
			ones++
		}
	}
	pi := float64(ones) / float64(n)

	// Prerequisite: if |pi - 0.5| >= 2/sqrt(n), p-value is effectively 0.
	if math.Abs(pi-0.5) >= 2.0/math.Sqrt(float64(n)) {
		return 0, nil
	}

	// Count runs: V_obs = number of position changes + 1.
	vObs := 1
	for i := 1; i < n; i++ {
		if bits[i] != bits[i-1] {
			vObs++
		}
	}

	// p-value = erfc(|V_obs - 2*n*pi*(1-pi)| / (2*sqrt(2*n)*pi*(1-pi)))
	num := math.Abs(float64(vObs) - 2.0*float64(n)*pi*(1-pi))
	denom := 2.0 * math.Sqrt(2.0*float64(n)) * pi * (1 - pi)
	pValue := math.Erfc(num / denom)
	return pValue, nil
}

// blockFrequencyTest implements NIST SP 800-22 Section 2.2 (Block Frequency Test).
//
// Divides the bit stream into N non-overlapping blocks of M bits each and checks
// that the proportion of 1s in each block is ~0.5.
// blockBits is M (block size in bits; must be >= 20 per NIST).
func blockFrequencyTest(bits []byte, blockBits int) (float64, error) {
	n := len(bits)
	if blockBits < 20 {
		return 0, fmt.Errorf("blockfreq: blockBits must be >= 20, got %d", blockBits)
	}
	numBlocks := n / blockBits // N
	if numBlocks < 1 {
		return 0, fmt.Errorf("blockfreq: need >= %d bits, got %d", blockBits, n)
	}

	// chi2 = 4*M * sum((pi_j - 0.5)^2)
	var chi2 float64
	for i := 0; i < numBlocks; i++ {
		block := bits[i*blockBits : (i+1)*blockBits]
		ones := 0
		for _, b := range block {
			if b == 1 {
				ones++
			}
		}
		piJ := float64(ones) / float64(blockBits)
		diff := piJ - 0.5
		chi2 += diff * diff
	}
	chi2 *= 4.0 * float64(blockBits)

	// p-value = Q(N/2, chi2/2) — regularized upper incomplete gamma
	pValue := gammaQ(float64(numBlocks)/2.0, chi2/2.0)
	return pValue, nil
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// bytesToBits converts a byte slice into a slice of 0/1 values (MSB first).
func bytesToBits(data []byte) []byte {
	bits := make([]byte, len(data)*8)
	for i, b := range data {
		for j := 7; j >= 0; j-- {
			if b&(1<<uint(j)) != 0 {
				bits[i*8+(7-j)] = 1
			}
		}
	}
	return bits
}

// classify maps a p-value to a Status per CONTEXT.md thresholds.
func classify(p float64) Status {
	switch {
	case p < 0.001:
		return StatusFail
	case p < 0.01:
		return StatusWarnLow
	case p > 0.999:
		return StatusWarnHigh
	default:
		return StatusPass
	}
}

// ─── Regularized upper incomplete gamma function Q(a, x) ─────────────────────
// Required for the Block Frequency test p-value.
// Implemented via series (x < a+1) and continued fraction (x >= a+1).
// Reference: Press et al., Numerical Recipes (3rd ed.), §6.2.

func gammaQ(a, x float64) float64 {
	if x < 0 || a <= 0 {
		return 0
	}
	if x == 0 {
		return 1
	}
	if x < a+1 {
		return 1 - gammaPSeries(a, x)
	}
	return gammaQCF(a, x)
}

// gammaPSeries computes the regularized lower incomplete gamma P(a, x) via series.
func gammaPSeries(a, x float64) float64 {
	const (
		maxIter = 300
		eps     = 1e-12
	)
	lnA, _ := math.Lgamma(a)
	ap := a
	del := 1.0 / a
	sum := del
	for i := 0; i < maxIter; i++ {
		ap++
		del *= x / ap
		sum += del
		if math.Abs(del) < math.Abs(sum)*eps {
			break
		}
	}
	return math.Exp(-x+a*math.Log(x)-lnA) * sum
}

// gammaQCF computes Q(a, x) via the Lentz continued fraction algorithm.
func gammaQCF(a, x float64) float64 {
	const (
		maxIter = 300
		eps     = 1e-12
		fpmin   = 1e-300
	)
	lnA, _ := math.Lgamma(a)

	b := x + 1.0 - a
	c := 1.0 / fpmin
	d := 1.0 / b
	h := d
	for i := 1; i <= maxIter; i++ {
		an := -float64(i) * (float64(i) - a)
		b += 2
		d = an*d + b
		if math.Abs(d) < fpmin {
			d = fpmin
		}
		c = b + an/c
		if math.Abs(c) < fpmin {
			c = fpmin
		}
		d = 1.0 / d
		del := d * c
		h *= del
		if math.Abs(del-1.0) < eps {
			break
		}
	}
	return math.Exp(-x+a*math.Log(x)-lnA) * h
}
