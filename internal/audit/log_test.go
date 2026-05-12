package audit

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// testKey is a 32-byte key used across unit tests.
var testKey = bytes.Repeat([]byte{0xAB}, 32)

func makeEntry(tenant, round string, values []int64) *Entry {
	return &Entry{
		TenantID:   tenant,
		GameID:     "bingo-90",
		RoundID:    round,
		RequestID:  "00000000-0000-0000-0000-000000000001",
		Values:     values,
		ValueCount: len(values),
		MinValue:   1,
		MaxValue:   90,
		CreatedAt:  time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC),
	}
}

// --- Signing ---

func TestSign_SetsSig(t *testing.T) {
	e := makeEntry("tenant-a", "round-1", []int64{1, 2, 3})
	e.Sign(testKey)
	if e.Signature == "" {
		t.Fatal("Sign did not set Signature")
	}
	if len(e.Signature) != 64 {
		t.Fatalf("Signature length = %d, want 64 hex chars", len(e.Signature))
	}
}

func TestSign_Deterministic(t *testing.T) {
	e1 := makeEntry("tenant-a", "round-1", []int64{10, 20, 30})
	e2 := makeEntry("tenant-a", "round-1", []int64{10, 20, 30})
	e1.Sign(testKey)
	e2.Sign(testKey)
	if e1.Signature != e2.Signature {
		t.Fatal("Sign is not deterministic for identical inputs")
	}
}

func TestVerify_Valid(t *testing.T) {
	e := makeEntry("tenant-a", "round-1", []int64{42, 17, 83})
	e.Sign(testKey)
	if !e.Verify(testKey) {
		t.Fatal("Verify rejected a valid signature")
	}
}

func TestVerify_WrongKey(t *testing.T) {
	e := makeEntry("tenant-a", "round-1", []int64{42})
	e.Sign(testKey)
	otherKey := bytes.Repeat([]byte{0xFF}, 32)
	if e.Verify(otherKey) {
		t.Fatal("Verify accepted signature with wrong key")
	}
}

func TestVerify_TamperedValues(t *testing.T) {
	e := makeEntry("tenant-a", "round-1", []int64{1, 2, 3})
	e.Sign(testKey)
	e.Values[0] = 99 // tamper
	if e.Verify(testKey) {
		t.Fatal("Verify accepted signature after value tampering")
	}
}

func TestVerify_TamperedTenant(t *testing.T) {
	e := makeEntry("tenant-a", "round-1", []int64{1, 2, 3})
	e.Sign(testKey)
	e.TenantID = "tenant-b"
	if e.Verify(testKey) {
		t.Fatal("Verify accepted signature after tenant tampering")
	}
}

func TestVerify_TamperedTimestamp(t *testing.T) {
	e := makeEntry("tenant-a", "round-1", []int64{1, 2, 3})
	e.Sign(testKey)
	e.CreatedAt = e.CreatedAt.Add(1)
	if e.Verify(testKey) {
		t.Fatal("Verify accepted signature after timestamp tampering")
	}
}

func TestVerify_EmptySignature(t *testing.T) {
	e := makeEntry("tenant-a", "round-1", []int64{1})
	if e.Verify(testKey) {
		t.Fatal("Verify accepted empty signature")
	}
}

// Different tenants, same values → different signatures (tenant is in sign data).
func TestSign_TenantIsolation(t *testing.T) {
	e1 := makeEntry("tenant-a", "round-1", []int64{5, 10})
	e2 := makeEntry("tenant-b", "round-1", []int64{5, 10})
	e1.Sign(testKey)
	e2.Sign(testKey)
	if e1.Signature == e2.Signature {
		t.Fatal("different tenants produced identical signatures")
	}
}

// --- Hash chain ---

func TestChain_Seal_SetsHashes(t *testing.T) {
	c := NewChain()
	e := makeEntry("tenant-a", "round-1", []int64{7})
	e.Sign(testKey)

	if err := c.Seal(e); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if e.PrevHash != ZeroHash {
		t.Fatalf("first entry PrevHash = %q, want ZeroHash", e.PrevHash)
	}
	if len(e.EntryHash) != 64 {
		t.Fatalf("EntryHash length = %d, want 64", len(e.EntryHash))
	}
}

func TestChain_Seal_Links(t *testing.T) {
	c := NewChain()

	e1 := makeEntry("tenant-a", "round-1", []int64{1})
	e1.Sign(testKey)
	if err := c.Seal(e1); err != nil {
		t.Fatal(err)
	}

	e2 := makeEntry("tenant-a", "round-2", []int64{2})
	e2.Sign(testKey)
	if err := c.Seal(e2); err != nil {
		t.Fatal(err)
	}

	if e2.PrevHash != e1.EntryHash {
		t.Fatalf("e2.PrevHash = %q, want e1.EntryHash = %q", e2.PrevHash, e1.EntryHash)
	}
}

func TestChain_Seal_RequiresSignature(t *testing.T) {
	c := NewChain()
	e := makeEntry("tenant-a", "round-1", []int64{1})
	// Do NOT call e.Sign
	if err := c.Seal(e); err == nil {
		t.Fatal("Seal must fail on unsigned entry")
	}
}

func TestChain_PrevHash(t *testing.T) {
	c := NewChain()
	if c.PrevHash() != ZeroHash {
		t.Fatalf("initial PrevHash = %q, want ZeroHash", c.PrevHash())
	}

	e := makeEntry("tenant-a", "round-1", []int64{1})
	e.Sign(testKey)
	_ = c.Seal(e)

	if c.PrevHash() != e.EntryHash {
		t.Fatalf("PrevHash after Seal = %q, want %q", c.PrevHash(), e.EntryHash)
	}
}

func TestLoadChain_ResumeFromHash(t *testing.T) {
	// Simulate restart: pre-seed the chain from a known hash.
	fakeHash := strings.Repeat("ab", 32) // 64 hex chars
	c, err := LoadChain(fakeHash)
	if err != nil {
		t.Fatal(err)
	}
	if c.PrevHash() != fakeHash {
		t.Fatalf("PrevHash = %q, want %q", c.PrevHash(), fakeHash)
	}
}

func TestLoadChain_InvalidHash(t *testing.T) {
	if _, err := LoadChain("tooshort"); err == nil {
		t.Fatal("LoadChain must reject a non-64-char hash")
	}
}

// --- VerifyEntries ---

func buildChain(t *testing.T, n int) []Entry {
	t.Helper()
	c := NewChain()
	entries := make([]Entry, n)
	for i := range entries {
		e := makeEntry("tenant-a", "round-"+string(rune('A'+i)), []int64{int64(i + 1)})
		e.CreatedAt = e.CreatedAt.Add(time.Duration(i) * time.Second)
		e.Sign(testKey)
		if err := c.Seal(e); err != nil {
			t.Fatal(err)
		}
		entries[i] = *e
	}
	return entries
}

func TestVerifyEntries_Valid(t *testing.T) {
	entries := buildChain(t, 5)
	idx, err := VerifyEntries(entries, ZeroHash)
	if err != nil {
		t.Fatalf("VerifyEntries: %v", err)
	}
	if idx != -1 {
		t.Fatalf("VerifyEntries: invalid at index %d, expected -1 (all valid)", idx)
	}
}

func TestVerifyEntries_TamperedHash(t *testing.T) {
	entries := buildChain(t, 4)
	entries[2].EntryHash = strings.Repeat("00", 32) // corrupt the hash
	idx, _ := VerifyEntries(entries, ZeroHash)
	if idx != 2 {
		t.Fatalf("expected tamper detected at index 2, got %d", idx)
	}
}

func TestVerifyEntries_TamperedPrevHash(t *testing.T) {
	entries := buildChain(t, 4)
	entries[1].PrevHash = strings.Repeat("ff", 32) // break the chain link
	idx, _ := VerifyEntries(entries, ZeroHash)
	if idx != 1 {
		t.Fatalf("expected tamper detected at index 1, got %d", idx)
	}
}

func TestVerifyEntries_TamperedValues(t *testing.T) {
	entries := buildChain(t, 3)
	entries[0].Values[0] = 999 // tamper a value → hash will differ
	idx, _ := VerifyEntries(entries, ZeroHash)
	if idx != 0 {
		t.Fatalf("expected tamper detected at index 0, got %d", idx)
	}
}

// --- KeyStore ---

func TestStaticKeyStore_Found(t *testing.T) {
	ks, err := NewStaticKeyStore(map[string][]byte{
		"tenant-a": bytes.Repeat([]byte{1}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	k, err := ks.SigningKey("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(k) != 32 {
		t.Fatalf("key length = %d, want 32", len(k))
	}
}

func TestStaticKeyStore_Wildcard(t *testing.T) {
	ks, _ := NewStaticKeyStore(map[string][]byte{
		"*": bytes.Repeat([]byte{2}, 32),
	})
	if _, err := ks.SigningKey("any-tenant"); err != nil {
		t.Fatalf("wildcard key lookup failed: %v", err)
	}
}

func TestStaticKeyStore_Missing(t *testing.T) {
	ks, _ := NewStaticKeyStore(map[string][]byte{
		"tenant-a": bytes.Repeat([]byte{1}, 32),
	})
	if _, err := ks.SigningKey("tenant-b"); err == nil {
		t.Fatal("expected error for missing tenant key")
	}
}

func TestStaticKeyStore_ShortKey(t *testing.T) {
	_, err := NewStaticKeyStore(map[string][]byte{
		"tenant-a": []byte("tooshort"),
	})
	if err == nil {
		t.Fatal("expected error for key < 32 bytes")
	}
}

// --- InMemoryStore ---

func TestInMemoryStore_AppendAndLatestHash(t *testing.T) {
	store := NewInMemoryStore()
	ctx := context.Background()

	h, err := store.LatestHash(ctx)
	if err != nil || h != ZeroHash {
		t.Fatalf("empty store LatestHash = %q, %v; want ZeroHash", h, err)
	}

	c := NewChain()
	e := makeEntry("tenant-a", "round-1", []int64{1, 2})
	e.Sign(testKey)
	_ = c.Seal(e)

	if err := store.Append(ctx, e); err != nil {
		t.Fatal(err)
	}

	h, err = store.LatestHash(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if h != e.EntryHash {
		t.Fatalf("LatestHash = %q, want %q", h, e.EntryHash)
	}
}

func TestInMemoryStore_VerifyChain(t *testing.T) {
	store := NewInMemoryStore()
	ctx := context.Background()
	c := NewChain()

	for i := 0; i < 5; i++ {
		e := makeEntry("tenant-a", "round-"+string(rune('A'+i)), []int64{int64(i)})
		e.CreatedAt = e.CreatedAt.Add(time.Duration(i) * time.Second)
		e.Sign(testKey)
		_ = c.Seal(e)
		_ = store.Append(ctx, e)
	}

	ok, err := store.VerifyChain(ctx, "tenant-a")
	if err != nil || !ok {
		t.Fatalf("VerifyChain = %v, %v; want true, nil", ok, err)
	}
}

func TestInMemoryStore_VerifyChain_Tampered(t *testing.T) {
	store := NewInMemoryStore()
	ctx := context.Background()
	c := NewChain()

	for i := 0; i < 3; i++ {
		e := makeEntry("tenant-a", "round-"+string(rune('A'+i)), []int64{int64(i)})
		e.CreatedAt = e.CreatedAt.Add(time.Duration(i) * time.Second)
		e.Sign(testKey)
		_ = c.Seal(e)
		_ = store.Append(ctx, e)
	}

	// Tamper with an entry directly.
	store.mu.Lock()
	store.entries[1].Values[0] = 9999
	store.mu.Unlock()

	ok, err := store.VerifyChain(ctx, "tenant-a")
	if ok || err == nil {
		t.Fatal("VerifyChain must detect tampering")
	}
}

func TestInMemoryStore_GetByRound(t *testing.T) {
	store := NewInMemoryStore()
	ctx := context.Background()
	c := NewChain()

	for _, round := range []string{"R1", "R2", "R1"} {
		e := makeEntry("tenant-a", round, []int64{1})
		e.Sign(testKey)
		_ = c.Seal(e)
		_ = store.Append(ctx, e)
	}

	entries, err := store.GetByRound(ctx, "R1")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("GetByRound(R1) = %d entries, want 2", len(entries))
	}
}

func TestNewRequestID_UniqueAndFormat(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		id, err := NewRequestID()
		if err != nil {
			t.Fatal(err)
		}
		if len(id) != 36 {
			t.Fatalf("RequestID length = %d, want 36", len(id))
		}
		if seen[id] {
			t.Fatalf("duplicate RequestID: %s", id)
		}
		seen[id] = true
	}
}
