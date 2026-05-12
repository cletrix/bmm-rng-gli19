package scaling

import (
	crand "crypto/rand"
	"math"
	"sort"
	"testing"
)

// cryptoRNG is a test helper that wraps crypto/rand to satisfy the RNG interface.
type cryptoRNG struct{}

func (cryptoRNG) Generate(n uint64) ([]byte, error) {
	b := make([]byte, n)
	_, err := crand.Read(b)
	return b, err
}

var rng = cryptoRNG{}

// --- RandRange ---

func TestRandRange_InRange(t *testing.T) {
	for _, max := range []uint64{2, 3, 10, 75, 90, 256, 1000, 1<<32 - 1} {
		for i := 0; i < 200; i++ {
			v, err := RandRange(rng, max)
			if err != nil {
				t.Fatalf("max=%d: %v", max, err)
			}
			if v >= max {
				t.Fatalf("max=%d: got %d, want < max", max, v)
			}
		}
	}
}

func TestRandRange_MaxOne(t *testing.T) {
	for i := 0; i < 10; i++ {
		v, err := RandRange(rng, 1)
		if err != nil {
			t.Fatal(err)
		}
		if v != 0 {
			t.Fatalf("RandRange(1) = %d, want 0", v)
		}
	}
}

func TestRandRange_ZeroMax(t *testing.T) {
	if _, err := RandRange(rng, 0); err == nil {
		t.Fatal("expected error for max=0")
	}
}

func TestRandRange_PowerOfTwo(t *testing.T) {
	// For power-of-two max, threshold=0 so no rejections should occur.
	for i := 0; i < 1000; i++ {
		v, err := RandRange(rng, 256)
		if err != nil {
			t.Fatal(err)
		}
		if v >= 256 {
			t.Fatalf("got %d, want < 256", v)
		}
	}
}

// TestRandRange_Distribution uses chi-square to verify uniformity for max=6 (dice).
func TestRandRange_Distribution(t *testing.T) {
	const max = 6
	const trials = 60000
	counts := make([]int, max)

	for i := 0; i < trials; i++ {
		v, err := RandRange(rng, max)
		if err != nil {
			t.Fatal(err)
		}
		counts[v]++
	}

	expected := float64(trials) / float64(max)
	var chi2 float64
	for _, c := range counts {
		diff := float64(c) - expected
		chi2 += diff * diff / expected
	}

	// Chi-square with max-1=5 df. Critical value at p=0.001 is ~20.5.
	if chi2 > 25 {
		t.Errorf("RandRange distribution chi-square = %.2f > 25; distribution may be biased", chi2)
	}
}

// --- RandRangeInclusive ---

func TestRandRangeInclusive(t *testing.T) {
	for i := 0; i < 500; i++ {
		v, err := RandRangeInclusive(rng, 1, 90) // bingo ball
		if err != nil {
			t.Fatal(err)
		}
		if v < 1 || v > 90 {
			t.Fatalf("got %d, want [1, 90]", v)
		}
	}
}

func TestRandRangeInclusive_InvalidRange(t *testing.T) {
	if _, err := RandRangeInclusive(rng, 10, 5); err == nil {
		t.Fatal("expected error for min > max")
	}
}

func TestRandRangeInclusive_SingleValue(t *testing.T) {
	v, err := RandRangeInclusive(rng, 42, 42)
	if err != nil {
		t.Fatal(err)
	}
	if v != 42 {
		t.Fatalf("got %d, want 42", v)
	}
}

// --- RandFloat64 ---

func TestRandFloat64_Range(t *testing.T) {
	for i := 0; i < 10000; i++ {
		f, err := RandFloat64(rng)
		if err != nil {
			t.Fatal(err)
		}
		if f < 0 || f >= 1 {
			t.Fatalf("RandFloat64 = %v, want [0, 1)", f)
		}
	}
}

func TestRandFloat64_Distribution(t *testing.T) {
	const buckets = 10
	const trials = 100000
	counts := make([]int, buckets)

	for i := 0; i < trials; i++ {
		f, err := RandFloat64(rng)
		if err != nil {
			t.Fatal(err)
		}
		b := int(f * float64(buckets))
		if b >= buckets {
			b = buckets - 1
		}
		counts[b]++
	}

	expected := float64(trials) / float64(buckets)
	var chi2 float64
	for _, c := range counts {
		diff := float64(c) - expected
		chi2 += diff * diff / expected
	}

	// 9 df, critical value at p=0.001 ≈ 27.9.
	if chi2 > 30 {
		t.Errorf("RandFloat64 distribution chi-square = %.2f > 30", chi2)
	}
}

// --- Shuffle ---

func TestShuffle_PreservesElements(t *testing.T) {
	original := makeDeck(90)
	deck := makeDeck(90)
	if err := Shuffle(rng, deck); err != nil {
		t.Fatal(err)
	}

	sort.Ints(deck)
	for i, v := range deck {
		if v != original[i] {
			t.Fatalf("shuffle changed elements: got %v at index %d, want %d", v, i, original[i])
		}
	}
}

func TestShuffle_NoDuplicates(t *testing.T) {
	deck := makeDeck(75)
	if err := Shuffle(rng, deck); err != nil {
		t.Fatal(err)
	}

	seen := make(map[int]bool)
	for _, v := range deck {
		if seen[v] {
			t.Fatalf("duplicate value %d after shuffle", v)
		}
		seen[v] = true
	}
}

// TestShuffle_Distribution verifies that each position receives each value
// with roughly equal frequency (uniform permutation).
func TestShuffle_Distribution(t *testing.T) {
	const n = 5
	const trials = 5000
	// counts[pos][val] = how many times val appeared at pos
	counts := [n][n]int{}

	for i := 0; i < trials; i++ {
		deck := makeDeck(n)
		if err := Shuffle(rng, deck); err != nil {
			t.Fatal(err)
		}
		for pos, val := range deck {
			counts[pos][val-1]++ // val is 1-indexed
		}
	}

	expected := float64(trials) / float64(n)
	var chi2 float64
	for _, row := range counts {
		for _, c := range row {
			diff := float64(c) - expected
			chi2 += diff * diff / expected
		}
	}

	// n*n - 1 = 24 df. Critical value at p=0.001 ≈ 51.2.
	if chi2 > 60 {
		t.Errorf("Shuffle distribution chi-square = %.2f > 60; permutation may not be uniform", chi2)
	}
	_ = math.NaN() // ensure math import is used (for documentation value)
}

func TestShuffle_EmptyAndSingle(t *testing.T) {
	if err := Shuffle(rng, []int{}); err != nil {
		t.Fatal(err)
	}
	deck := []int{42}
	if err := Shuffle(rng, deck); err != nil {
		t.Fatal(err)
	}
	if deck[0] != 42 {
		t.Fatalf("single-element shuffle changed value")
	}
}

func makeDeck(n int) []int {
	deck := make([]int, n)
	for i := range deck {
		deck[i] = i + 1
	}
	return deck
}
