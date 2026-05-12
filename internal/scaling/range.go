// Package scaling converts raw CSPRNG bytes into numbers within a desired range
// without introducing statistical bias.
package scaling

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// RNG is the interface required by all scaling functions.
// internal/csprng.DRBG satisfies this interface.
type RNG interface {
	Generate(n uint64) ([]byte, error)
}

// RandRange returns a uniform random value in [0, max) using rejection sampling.
//
// Simple modulo ("n % max") introduces bias when max is not a power of two,
// because the uint64 range is not evenly divisible by max. Rejection sampling
// eliminates this bias by discarding values in the non-uniform residue class.
//
// Expected number of rejections < 1 on average; worst case ~1 for max near 2^63.
func RandRange(rng RNG, max uint64) (uint64, error) {
	if max == 0 {
		return 0, errors.New("scaling: RandRange: max must be > 0")
	}
	if max == 1 {
		return 0, nil
	}

	// threshold = 2^64 % max: values in [0, threshold) are rejected.
	// In unsigned arithmetic: -max % max == (2^64 - max) % max == 2^64 % max.
	threshold := (-max) % max

	for {
		b, err := rng.Generate(8)
		if err != nil {
			return 0, fmt.Errorf("scaling: RandRange: %w", err)
		}
		n := binary.BigEndian.Uint64(b)
		if n >= threshold {
			return n % max, nil
		}
	}
}

// RandRangeInclusive returns a uniform random value in [min, max] (both inclusive).
func RandRangeInclusive(rng RNG, min, max uint64) (uint64, error) {
	if min > max {
		return 0, fmt.Errorf("scaling: RandRangeInclusive: min (%d) > max (%d)", min, max)
	}
	n, err := RandRange(rng, max-min+1)
	if err != nil {
		return 0, err
	}
	return min + n, nil
}

// RandFloat64 returns a uniform random float64 in [0.0, 1.0).
// Uses 53 bits of entropy, matching the mantissa precision of a float64.
func RandFloat64(rng RNG) (float64, error) {
	b, err := rng.Generate(8)
	if err != nil {
		return 0, fmt.Errorf("scaling: RandFloat64: %w", err)
	}
	n := binary.BigEndian.Uint64(b) >> 11 // 53 significant bits
	return float64(n) * (1.0 / (1 << 53)), nil
}

// Shuffle randomly permutes deck in place using the Fisher-Yates algorithm.
// Produces a uniformly random permutation with no bias.
//
// Bingo usage: Shuffle(rng, deck) where deck = [1..90] or [1..75].
func Shuffle(rng RNG, deck []int) error {
	for i := len(deck) - 1; i > 0; i-- {
		j, err := RandRange(rng, uint64(i+1))
		if err != nil {
			return fmt.Errorf("scaling: Shuffle: %w", err)
		}
		deck[i], deck[j] = deck[j], deck[i]
	}
	return nil
}
