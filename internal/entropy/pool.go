package entropy

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Pool collects high-quality entropy for seeding the CSPRNG.
// On Linux, uses getrandom(2). On other platforms, uses crypto/rand.
type Pool struct {
	hwrngPath string
	mu        sync.Mutex
}

// New creates an entropy pool.
// hwrngPath is the path to a hardware RNG device (e.g. /dev/hwrng).
// Pass an empty string if no HWRNG is available.
func New(hwrngPath string) *Pool {
	return &Pool{hwrngPath: hwrngPath}
}

// Read fills b with entropy. Thread-safe.
func (p *Pool) Read(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if err := readEntropy(b); err != nil {
		return 0, fmt.Errorf("entropy: getrandom: %w", err)
	}

	// HWRNG is secondary: XOR its bytes into the getrandom output.
	// Even if the HWRNG is compromised, getrandom output remains secure.
	if p.hwrngPath != "" {
		if hw, err := p.readHWRNG(len(b)); err == nil {
			for i := range b {
				b[i] ^= hw[i]
			}
		}
		// Silently continue if HWRNG is unavailable — getrandom is sufficient.
	}

	return len(b), nil
}

func (p *Pool) readHWRNG(n int) ([]byte, error) {
	f, err := os.Open(p.hwrngPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	buf := make([]byte, n)
	if _, err := io.ReadFull(f, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// ReseedEvent holds the metadata logged on every re-seed operation.
type ReseedEvent struct {
	TimestampUTC           time.Time
	TenantID               string
	EntropySource          string
	SeedHash               string // SHA256 of seed bytes — never the seed itself
	OutputsSinceLastReseed uint64
}

// CollectForReseed gathers fresh entropy for a CSPRNG re-seed.
// size must be >= csprng.SeedLen (48 bytes).
//
// Never pass previous CSPRNG output as entropy — this function must be the
// only source of bytes passed to csprng.DRBG.Reseed.
func (p *Pool) CollectForReseed(size int, tenantID string, outputsSince uint64) ([]byte, ReseedEvent, error) {
	buf := make([]byte, size)
	if _, err := p.Read(buf); err != nil {
		return nil, ReseedEvent{}, fmt.Errorf("entropy: collect for reseed: %w", err)
	}

	source := "getrandom"
	if p.hwrngPath != "" {
		source = "getrandom+hwrng"
	}

	h := sha256.Sum256(buf)
	event := ReseedEvent{
		TimestampUTC:           time.Now().UTC(),
		TenantID:               tenantID,
		EntropySource:          source,
		SeedHash:               fmt.Sprintf("%x", h),
		OutputsSinceLastReseed: outputsSince,
	}

	return buf, event, nil
}
