// Package csprng implements NIST SP 800-90A Rev.1 CTR_DRBG with AES-256.
// This is the algorithm accepted by BMM Testlabs for iGaming certification.
//
// Do NOT use math/rand, Mersenne Twister, or any non-CSPRNG in iGaming contexts.
package csprng

import (
	"crypto/aes"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
)

// SeedLen is the number of entropy bytes required for instantiation and re-seeding.
// NIST SP 800-90A: keylen (256 bits) + outlen (128 bits) = 384 bits = 48 bytes.
const SeedLen = 48

// DRBG implements NIST SP 800-90A Rev.1 CTR_DRBG with AES-256.
//
// Security strength: 256 bits.
// The internal state (key, v) is never exposed through any method or field.
// Safe for concurrent use.
type DRBG struct {
	key         [32]byte // AES-256 key — never exported
	v           [16]byte // 128-bit block counter — never exported
	mu          sync.Mutex
	outputBytes atomic.Uint64
}

// New instantiates a DRBG seeded with the provided entropy.
// entropy must be at least SeedLen (48) bytes from a cryptographically
// secure source (see internal/entropy). Never pass user-provided data here.
func New(entropy []byte) (*DRBG, error) {
	if len(entropy) < SeedLen {
		return nil, fmt.Errorf("csprng: entropy too short: need %d bytes, got %d", SeedLen, len(entropy))
	}
	d := &DRBG{}
	seed := make([]byte, SeedLen)
	copy(seed, entropy[:SeedLen])
	// Initial state: key=0^32, V=0^16. updateLocked seeds both via CTR_DRBG_Update.
	if err := d.updateLocked(seed); err != nil {
		return nil, err
	}
	return d, nil
}

// Generate produces n cryptographically secure random bytes.
//
// Implements NIST SP 800-90A §10.2.1.5.2 (Generate without DF).
// After generation, the internal state is updated for forward secrecy:
// knowledge of outputs does not allow reconstructing the current key.
func (d *DRBG) Generate(n uint64) ([]byte, error) {
	if n == 0 {
		return []byte{}, nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	cipher, err := aes.NewCipher(d.key[:])
	if err != nil {
		return nil, fmt.Errorf("csprng: aes: %w", err)
	}

	// Allocate slightly more than n to avoid partial-block slicing.
	buf := make([]byte, 0, n+16)
	var block [16]byte
	for uint64(len(buf)) < n {
		increment(&d.v)
		cipher.Encrypt(block[:], d.v[:])
		buf = append(buf, block[:]...)
	}
	result := make([]byte, n)
	copy(result, buf[:n])

	// Post-generation state update (NIST §10.2.1.5.2 step 6).
	// This replaces key and V, providing forward secrecy.
	if err := d.updateLocked(nil); err != nil {
		return nil, err
	}

	d.outputBytes.Add(n)
	return result, nil
}

// Reseed updates the DRBG state with fresh entropy from the entropy pool.
// entropy must be at least SeedLen (48) bytes.
//
// Re-seed policy (CONTEXT.md):
//   - Every 1,000,000 output bytes (configurable via RNG_RESEED_INTERVAL_OUTPUTS)
//   - Every 3600 seconds (configurable via RNG_RESEED_INTERVAL_SECONDS)
//   - On service restart or detected anomaly
func (d *DRBG) Reseed(entropy []byte) error {
	if len(entropy) < SeedLen {
		return fmt.Errorf("csprng: reseed entropy too short: need %d bytes, got %d", SeedLen, len(entropy))
	}
	seed := make([]byte, SeedLen)
	copy(seed, entropy[:SeedLen])

	d.mu.Lock()
	defer d.mu.Unlock()
	return d.updateLocked(seed)
}

// HealthCheck returns an error if the internal state appears corrupted.
// A zero key indicates the DRBG was never properly seeded.
func (d *DRBG) HealthCheck() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, b := range d.key {
		if b != 0 {
			return nil
		}
	}
	return errors.New("csprng: key is all-zero — DRBG state invalid or not seeded")
}

// OutputBytes returns the cumulative number of bytes generated since instantiation.
// Used by the re-seed scheduler to enforce the output-count re-seed policy.
func (d *DRBG) OutputBytes() uint64 {
	return d.outputBytes.Load()
}

// updateLocked implements NIST SP 800-90A §10.2.1.2 CTR_DRBG_Update.
// Caller must hold d.mu.
//
// provided may be nil; in that case the XOR step is a no-op (XOR with zeros).
// seedLen = 48 bytes: 3 AES-256 block encryptions of successive counter values.
func (d *DRBG) updateLocked(provided []byte) error {
	cipher, err := aes.NewCipher(d.key[:])
	if err != nil {
		return fmt.Errorf("csprng: aes: %w", err)
	}

	var temp [SeedLen]byte
	var block [16]byte
	for i := 0; i < SeedLen/16; i++ {
		increment(&d.v)
		cipher.Encrypt(block[:], d.v[:])
		copy(temp[i*16:], block[:])
	}

	// XOR with provided data (NIST step 7); skip if nil.
	for i := 0; i < len(provided) && i < SeedLen; i++ {
		temp[i] ^= provided[i]
	}

	copy(d.key[:], temp[:32])
	copy(d.v[:], temp[32:SeedLen])
	return nil
}

// increment adds 1 to v as a 128-bit big-endian counter.
func increment(v *[16]byte) {
	hi := binary.BigEndian.Uint64(v[0:8])
	lo := binary.BigEndian.Uint64(v[8:16])
	lo++
	if lo == 0 {
		hi++
	}
	binary.BigEndian.PutUint64(v[0:8], hi)
	binary.BigEndian.PutUint64(v[8:16], lo)
}
