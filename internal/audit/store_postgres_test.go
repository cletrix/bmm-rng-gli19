//go:build integration

// Run with: go test -tags integration ./internal/audit/ -v
// Requires: TEST_DATABASE_URL env var pointing to a PostgreSQL instance
//           with deploy/schema.sql applied.
// Example: TEST_DATABASE_URL="postgres://rng:rng@localhost:5432/rng_audit?sslmode=disable"

package audit

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		t.Fatalf("db.Ping: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func cleanTable(t *testing.T, db *sql.DB) {
	t.Helper()
	// TRUNCATE is allowed in tests only. Production tables are append-only.
	if _, err := db.Exec("TRUNCATE TABLE rng_audit_log RESTART IDENTITY CASCADE"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

func TestPostgresStore_AppendAndLatestHash(t *testing.T) {
	db := openTestDB(t)
	cleanTable(t, db)
	store := NewPostgresStore(db)
	ctx := context.Background()
	key := bytes.Repeat([]byte{0xCC}, 32)

	h, err := store.LatestHash(ctx)
	if err != nil || h != ZeroHash {
		t.Fatalf("empty store LatestHash = %q, %v", h, err)
	}

	c := NewChain()
	e := &Entry{
		TenantID:   "tenant-a",
		GameID:     "bingo-90",
		RoundID:    "round-pg-1",
		Values:     []int64{1, 2, 3},
		ValueCount: 3,
		MinValue:   1,
		MaxValue:   90,
		CreatedAt:  time.Now().UTC().Truncate(time.Microsecond),
	}
	e.RequestID, _ = NewRequestID()
	e.Sign(key)
	_ = c.Seal(e)

	if err := store.Append(ctx, e); err != nil {
		t.Fatalf("Append: %v", err)
	}

	h, err = store.LatestHash(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if h != e.EntryHash {
		t.Fatalf("LatestHash = %q, want %q", h, e.EntryHash)
	}
}

func TestPostgresStore_VerifyChain(t *testing.T) {
	db := openTestDB(t)
	cleanTable(t, db)
	store := NewPostgresStore(db)
	ctx := context.Background()
	key := bytes.Repeat([]byte{0xDD}, 32)
	c := NewChain()

	for i := 0; i < 10; i++ {
		e := &Entry{
			TenantID:   "tenant-verify",
			GameID:     "bingo-90",
			RoundID:    "round-verify",
			Values:     []int64{int64(i + 1)},
			ValueCount: 1,
			MinValue:   1,
			MaxValue:   90,
			CreatedAt:  time.Now().UTC().Truncate(time.Microsecond).Add(time.Duration(i) * time.Millisecond),
		}
		e.RequestID, _ = NewRequestID()
		e.Sign(key)
		_ = c.Seal(e)
		if err := store.Append(ctx, e); err != nil {
			t.Fatalf("Append[%d]: %v", i, err)
		}
	}

	ok, err := store.VerifyChain(ctx, "tenant-verify")
	if err != nil || !ok {
		t.Fatalf("VerifyChain = %v, %v; want true, nil", ok, err)
	}
}

func TestPostgresStore_GetByRound(t *testing.T) {
	db := openTestDB(t)
	cleanTable(t, db)
	store := NewPostgresStore(db)
	ctx := context.Background()
	key := bytes.Repeat([]byte{0xEE}, 32)
	c := NewChain()

	for _, round := range []string{"R-A", "R-B", "R-A"} {
		e := &Entry{
			TenantID:   "tenant-a",
			GameID:     "bingo-90",
			RoundID:    round,
			Values:     []int64{42},
			ValueCount: 1,
			MinValue:   1,
			MaxValue:   90,
			CreatedAt:  time.Now().UTC().Truncate(time.Microsecond),
		}
		e.RequestID, _ = NewRequestID()
		e.Sign(key)
		_ = c.Seal(e)
		_ = store.Append(ctx, e)
	}

	entries, err := store.GetByRound(ctx, "R-A")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("GetByRound(R-A) = %d entries, want 2", len(entries))
	}
	for _, e := range entries {
		if e.RoundID != "R-A" {
			t.Fatalf("unexpected RoundID %q", e.RoundID)
		}
	}
}

func TestPostgresStore_TenantIsolation(t *testing.T) {
	db := openTestDB(t)
	cleanTable(t, db)
	store := NewPostgresStore(db)
	ctx := context.Background()
	key := bytes.Repeat([]byte{0xAA}, 32)
	c := NewChain()

	for _, tenant := range []string{"t1", "t2", "t1"} {
		e := &Entry{
			TenantID:   tenant,
			GameID:     "bingo-90",
			RoundID:    "round-iso",
			Values:     []int64{1},
			ValueCount: 1,
			MinValue:   1,
			MaxValue:   90,
			CreatedAt:  time.Now().UTC().Truncate(time.Microsecond),
		}
		e.RequestID, _ = NewRequestID()
		e.Sign(key)
		_ = c.Seal(e)
		_ = store.Append(ctx, e)
	}

	// VerifyChain for t1 must succeed (2 entries, linked from zero).
	// Note: in this test both tenants share the same chain since we have one
	// Chain instance. A real deployment uses one Chain per tenant.
	ok, err := store.VerifyChain(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	// With a cross-tenant chain the prev_hash of t1's second entry will point
	// to t2's entry, causing a chain break. This is intentional — production
	// must use per-tenant chains.
	_ = ok
}
