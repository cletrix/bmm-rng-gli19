package health

import (
	crand "crypto/rand"
	"math"
	"testing"
)

// ─── gammaQ math tests ────────────────────────────────────────────────────────

func TestGammaQ_Boundary(t *testing.T) {
	// Q(a, 0) = 1 for any a > 0.
	if v := gammaQ(1, 0); v != 1.0 {
		t.Errorf("gammaQ(1,0) = %v, want 1.0", v)
	}
	// Q(a, large_x) → 0.
	if v := gammaQ(1, 100); v > 1e-30 {
		t.Errorf("gammaQ(1,100) = %v, expected ~0", v)
	}
}

func TestGammaQ_KnownValues(t *testing.T) {
	cases := []struct {
		a, x, want, tol float64
	}{
		// Q(1, x) = e^(-x) — exact.
		{1.0, 1.0, math.Exp(-1), 1e-10},
		{1.0, 2.0, math.Exp(-2), 1e-10},
		// Q(0.5, x) = erfc(sqrt(x)) — identity from special functions.
		{0.5, 0.5, math.Erfc(math.Sqrt(0.5)), 1e-8},
		{0.5, 1.0, math.Erfc(1.0), 1e-8},
		// Q(2, 1) = e^(-1)(1 + 1) = 2e^(-1) ... actually Q(2,1) = e^(-1)(1+1) = 2/e ≈ 0.7358.
		// Let's use Q(2, 2) = e^(-2)(1 + 2) = 3e^(-2) ≈ 0.4060.
		{2.0, 2.0, 3 * math.Exp(-2), 1e-8},
	}
	for _, c := range cases {
		got := gammaQ(c.a, c.x)
		if math.Abs(got-c.want) > c.tol {
			t.Errorf("gammaQ(%.1f, %.1f) = %.10f, want %.10f (tol %.0e)",
				c.a, c.x, got, c.want, c.tol)
		}
	}
}

// ─── bytesToBits ──────────────────────────────────────────────────────────────

func TestBytesToBits_AllOnes(t *testing.T) {
	bits := bytesToBits([]byte{0xFF})
	for i, b := range bits {
		if b != 1 {
			t.Errorf("bit[%d] = %d, want 1 for 0xFF", i, b)
		}
	}
}

func TestBytesToBits_AllZeros(t *testing.T) {
	bits := bytesToBits([]byte{0x00})
	for i, b := range bits {
		if b != 0 {
			t.Errorf("bit[%d] = %d, want 0 for 0x00", i, b)
		}
	}
}

func TestBytesToBits_MSBFirst(t *testing.T) {
	// 0xA0 = 1010_0000
	bits := bytesToBits([]byte{0xA0})
	expected := []byte{1, 0, 1, 0, 0, 0, 0, 0}
	for i, b := range bits {
		if b != expected[i] {
			t.Errorf("bit[%d] = %d, want %d for 0xA0", i, b, expected[i])
		}
	}
}

// ─── Frequency test ───────────────────────────────────────────────────────────

func TestFrequencyTest_AllZeros_Fails(t *testing.T) {
	// All-zero byte stream → all -1 in the sum → p-value very close to 0.
	data := make([]byte, 200)
	bits := bytesToBits(data)
	p, err := frequencyTest(bits)
	if err != nil {
		t.Fatal(err)
	}
	if p >= 0.001 {
		t.Errorf("all-zero data: p-value = %.6f, expected < 0.001 (FAIL)", p)
	}
}

func TestFrequencyTest_AllOnes_Fails(t *testing.T) {
	data := make([]byte, 200)
	for i := range data {
		data[i] = 0xFF
	}
	bits := bytesToBits(data)
	p, err := frequencyTest(bits)
	if err != nil {
		t.Fatal(err)
	}
	if p >= 0.001 {
		t.Errorf("all-ones data: p-value = %.6f, expected < 0.001 (FAIL)", p)
	}
}

func TestFrequencyTest_GoodCSPRNG_Passes(t *testing.T) {
	data := make([]byte, 1250) // 10000 bits
	if _, err := crand.Read(data); err != nil {
		t.Fatal(err)
	}
	bits := bytesToBits(data)
	p, err := frequencyTest(bits)
	if err != nil {
		t.Fatal(err)
	}
	if p < 0.001 {
		// With good random data this should essentially never happen.
		t.Errorf("crypto/rand data: frequency p-value = %.6f, expected >= 0.001", p)
	}
}

func TestFrequencyTest_TooShort(t *testing.T) {
	bits := make([]byte, 50) // < 100 bits
	if _, err := frequencyTest(bits); err == nil {
		t.Fatal("expected error for < 100 bits")
	}
}

// ─── Runs test ────────────────────────────────────────────────────────────────

func TestRunsTest_AllZeros_ZeroPValue(t *testing.T) {
	// All-zero stream: pi = 0, prerequisite fails → p-value = 0.
	data := make([]byte, 200)
	bits := bytesToBits(data)
	p, err := runsTest(bits)
	if err != nil {
		t.Fatal(err)
	}
	if p != 0 {
		t.Errorf("all-zeros runs p-value = %.6f, expected 0 (prerequisite fail)", p)
	}
}

func TestRunsTest_GoodCSPRNG_Passes(t *testing.T) {
	data := make([]byte, 1250)
	if _, err := crand.Read(data); err != nil {
		t.Fatal(err)
	}
	bits := bytesToBits(data)
	p, err := runsTest(bits)
	if err != nil {
		t.Fatal(err)
	}
	if p < 0.001 {
		t.Errorf("crypto/rand data: runs p-value = %.6f, expected >= 0.001", p)
	}
}

// ─── Block Frequency test ─────────────────────────────────────────────────────

func TestBlockFreqTest_AllZeros_Fails(t *testing.T) {
	data := make([]byte, 1250) // 10000 bits
	bits := bytesToBits(data)
	p, err := blockFrequencyTest(bits, 128)
	if err != nil {
		t.Fatal(err)
	}
	if p >= 0.001 {
		t.Errorf("all-zeros block freq p-value = %.6f, expected < 0.001", p)
	}
}

func TestBlockFreqTest_GoodCSPRNG_Passes(t *testing.T) {
	data := make([]byte, 1250)
	if _, err := crand.Read(data); err != nil {
		t.Fatal(err)
	}
	bits := bytesToBits(data)
	p, err := blockFrequencyTest(bits, 128)
	if err != nil {
		t.Fatal(err)
	}
	if p < 0.001 {
		t.Errorf("crypto/rand data: block freq p-value = %.6f, expected >= 0.001", p)
	}
}

func TestBlockFreqTest_TooSmallBlock(t *testing.T) {
	bits := make([]byte, 1000)
	if _, err := blockFrequencyTest(bits, 10); err == nil {
		t.Fatal("expected error for blockBits < 20")
	}
}

// ─── SelfTester integration ───────────────────────────────────────────────────

type cryptoRNG struct{}

func (cryptoRNG) Generate(n uint64) ([]byte, error) {
	b := make([]byte, n)
	_, err := crand.Read(b)
	return b, err
}

func TestSelfTester_RunAll_GoodRNG(t *testing.T) {
	st := NewSelfTester(cryptoRNG{}, 10000)
	results, err := st.RunAll()
	if err != nil {
		t.Fatalf("RunAll: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("len(results) = %d, want 3", len(results))
	}
	for _, r := range results {
		if r.Status == StatusFail {
			t.Errorf("test %q: p-value=%.6f → FAIL (unexpected for good RNG)", r.Name, r.PValue)
		}
	}
}

func TestSelfTester_HasCriticalFailure_False(t *testing.T) {
	st := NewSelfTester(cryptoRNG{}, 10000)
	st.results = []TestResult{
		{Name: "Frequency", PValue: 0.5, Status: StatusPass},
		{Name: "Runs", PValue: 0.3, Status: StatusPass},
	}
	if st.HasCriticalFailure() {
		t.Fatal("HasCriticalFailure should be false when no test is in Fail status")
	}
}

func TestSelfTester_HasCriticalFailure_True(t *testing.T) {
	st := NewSelfTester(cryptoRNG{}, 10000)
	st.results = []TestResult{
		{Name: "Frequency", PValue: 0.0001, Status: StatusFail},
	}
	if !st.HasCriticalFailure() {
		t.Fatal("HasCriticalFailure should be true when any test is in Fail status")
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		p      float64
		status Status
	}{
		{0.0, StatusFail},
		{0.0005, StatusFail},
		{0.001, StatusWarnLow}, // p == 0.001: not < 0.001, so warn_low
		{0.0009, StatusFail},  // p < 0.001 → CRITICAL
		{0.005, StatusWarnLow},
		{0.01, StatusPass},    // p >= 0.01 → pass
		{0.5, StatusPass},
		{0.999, StatusPass},   // p <= 0.999 → pass
		{0.9995, StatusWarnHigh},
		{1.0, StatusWarnHigh},
	}
	for _, c := range cases {
		got := classify(c.p)
		if got != c.status {
			t.Errorf("classify(%.4f) = %q, want %q", c.p, got, c.status)
		}
	}
}
