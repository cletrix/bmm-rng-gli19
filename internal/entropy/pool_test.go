package entropy

import (
	"testing"
)

func TestRead(t *testing.T) {
	p := New("")
	b := make([]byte, 64)
	n, err := p.Read(b)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if n != 64 {
		t.Fatalf("Read returned %d bytes, want 64", n)
	}
	if allZero(b) {
		t.Fatal("Read returned all-zero bytes")
	}
}

func TestReadLarge(t *testing.T) {
	p := New("")
	b := make([]byte, 4096)
	if _, err := p.Read(b); err != nil {
		t.Fatalf("Read(4096): %v", err)
	}
}

func TestReadProducesDistinctOutputs(t *testing.T) {
	p := New("")
	a := make([]byte, 32)
	b := make([]byte, 32)
	if _, err := p.Read(a); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Read(b); err != nil {
		t.Fatal(err)
	}
	// Two independent reads should not be identical.
	equal := true
	for i := range a {
		if a[i] != b[i] {
			equal = false
			break
		}
	}
	if equal {
		t.Fatal("two independent reads returned identical bytes")
	}
}

func TestCollectForReseed(t *testing.T) {
	p := New("")
	entropy, event, err := p.CollectForReseed(48, "test-tenant", 1000)
	if err != nil {
		t.Fatalf("CollectForReseed: %v", err)
	}
	if len(entropy) != 48 {
		t.Fatalf("expected 48 bytes, got %d", len(entropy))
	}
	if len(event.SeedHash) != 64 { // hex-encoded SHA256 = 64 chars
		t.Fatalf("SeedHash length = %d, want 64", len(event.SeedHash))
	}
	if event.TenantID != "test-tenant" {
		t.Fatalf("TenantID = %q, want %q", event.TenantID, "test-tenant")
	}
	if event.OutputsSinceLastReseed != 1000 {
		t.Fatalf("OutputsSinceLastReseed = %d, want 1000", event.OutputsSinceLastReseed)
	}
	if event.TimestampUTC.IsZero() {
		t.Fatal("TimestampUTC is zero")
	}
	if event.EntropySource == "" {
		t.Fatal("EntropySource is empty")
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
