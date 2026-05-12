package health

import (
	"strings"
	"testing"
)

func TestComputeBinaryHash_Format(t *testing.T) {
	h, err := ComputeBinaryHash()
	if err != nil {
		t.Fatalf("ComputeBinaryHash: %v", err)
	}
	if len(h) != 64 {
		t.Fatalf("hash length = %d, want 64 hex chars", len(h))
	}
	for _, c := range h {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Fatalf("non-hex character %q in hash", c)
		}
	}
}

func TestComputeBinaryHash_Stable(t *testing.T) {
	h1, err := ComputeBinaryHash()
	if err != nil {
		t.Fatal(err)
	}
	h2, err := ComputeBinaryHash()
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("two calls returned different hashes: %q vs %q", h1, h2)
	}
}

func TestChecker_DevBuild_StartsOK(t *testing.T) {
	c, err := New(devBuildHash)
	if err != nil {
		t.Fatalf("New(devBuildHash): %v", err)
	}
	if c.StartupHash() == "" {
		t.Fatal("StartupHash is empty")
	}
	if !c.IsDev() {
		t.Fatal("IsDev() should be true for dev-build")
	}
}

func TestChecker_EmptyHash_StartsOK(t *testing.T) {
	if _, err := New(""); err != nil {
		t.Fatalf("New(''): %v", err)
	}
}

func TestChecker_MatchingHash_StartsOK(t *testing.T) {
	// Compute the actual hash and pass it as the embedded hash.
	realHash, err := ComputeBinaryHash()
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(realHash)
	if err != nil {
		t.Fatalf("New(realHash): %v", err)
	}
	if c.IsDev() {
		t.Fatal("IsDev() should be false when a real hash is provided")
	}
}

func TestChecker_WrongHash_Fails(t *testing.T) {
	_, err := New(strings.Repeat("00", 32)) // 64 zeros — won't match actual binary
	if err == nil {
		t.Fatal("expected tamper detection error for wrong embedded hash")
	}
	if !strings.Contains(err.Error(), "TAMPER DETECTED") {
		t.Fatalf("error message = %q; expected TAMPER DETECTED", err.Error())
	}
}

func TestChecker_Verify_PassesImmediately(t *testing.T) {
	c, err := New(devBuildHash)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}
