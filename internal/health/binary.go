// Package health implements BMM-required runtime integrity checks:
//   - Tamper detection: SHA256 of the running binary verified at startup and every 5 min.
//   - Continuous NIST SP 800-22 self-tests on CSPRNG output.
package health

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"runtime"
)

const devBuildHash = "dev-build"

// Checker verifies the running binary has not been modified since build time.
//
// Startup: compares embeddedHash (injected via -ldflags at build time) against
// the SHA256 of the actual executable on disk. Refuses to start if they differ.
//
// Runtime: re-hashes every 5 minutes and compares against the startup hash.
// If they differ, generation must be paused and ops alerted (Sprint 4 wires this).
type Checker struct {
	embeddedHash string // from main.BinaryHash, injected by -ldflags
	startupHash  string // computed when New() is called
}

// New creates a Checker and performs the startup tamper check.
// Returns an error if embeddedHash != actual binary hash (unless embeddedHash == "dev-build").
func New(embeddedHash string) (*Checker, error) {
	startupHash, err := ComputeBinaryHash()
	if err != nil {
		return nil, fmt.Errorf("health: compute startup hash: %w", err)
	}

	if embeddedHash != devBuildHash && embeddedHash != "" {
		if embeddedHash != startupHash {
			return nil, fmt.Errorf(
				"health: TAMPER DETECTED at startup — embedded hash %q != binary hash %q",
				embeddedHash, startupHash,
			)
		}
	}

	return &Checker{
		embeddedHash: embeddedHash,
		startupHash:  startupHash,
	}, nil
}

// Verify re-hashes the running executable and compares against the startup hash.
// Call this every 5 minutes. Returns a non-nil error if tampering is detected.
func (c *Checker) Verify() error {
	current, err := ComputeBinaryHash()
	if err != nil {
		return fmt.Errorf("health: verify binary: %w", err)
	}
	if current != c.startupHash {
		return fmt.Errorf(
			"health: TAMPER DETECTED at runtime — current hash %q != startup hash %q",
			current, c.startupHash,
		)
	}
	return nil
}

// StartupHash returns the SHA256 of the binary as computed at process startup.
func (c *Checker) StartupHash() string { return c.startupHash }

// IsDev reports whether this is a dev build (embedded hash not set).
func (c *Checker) IsDev() bool { return c.embeddedHash == devBuildHash || c.embeddedHash == "" }

// ComputeBinaryHash returns the hex-encoded SHA256 of the running executable.
//
// On Linux, reads from /proc/self/exe (the canonical path used by the BMM audit).
// On other platforms (macOS for dev), uses os.Executable().
func ComputeBinaryHash() (string, error) {
	var exePath string

	if runtime.GOOS == "linux" {
		// /proc/self/exe is the definitive path to the running binary on Linux.
		// os.Readlink resolves the symlink to the actual file path.
		resolved, err := os.Readlink("/proc/self/exe")
		if err == nil {
			exePath = resolved
		}
	}
	if exePath == "" {
		var err error
		exePath, err = os.Executable()
		if err != nil {
			return "", fmt.Errorf("health: get executable path: %w", err)
		}
	}

	f, err := os.Open(exePath)
	if err != nil {
		return "", fmt.Errorf("health: open executable %q: %w", exePath, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("health: hash executable: %w", err)
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
