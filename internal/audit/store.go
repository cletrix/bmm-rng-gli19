package audit

import (
	"context"
	"fmt"
	"sync"
)

// Store persists audit entries to an append-only backing store.
// Implementations must guarantee that entries can never be modified or deleted.
type Store interface {
	// Append persists a sealed entry. entry.EntryHash and entry.PrevHash must be set.
	Append(ctx context.Context, e *Entry) error

	// LatestHash returns the EntryHash of the most recent entry.
	// Returns ZeroHash if no entries exist yet.
	LatestHash(ctx context.Context) (string, error)

	// GetByRound returns all entries for a given round_id, ordered by created_at.
	GetByRound(ctx context.Context, roundID string) ([]Entry, error)

	// VerifyChain re-reads all entries for tenantID and verifies the hash chain.
	// Returns true and nil if the chain is intact.
	VerifyChain(ctx context.Context, tenantID string) (bool, error)
}

// InMemoryStore is a non-persistent Store for testing and local development.
// NOT for production: data is lost on restart and there is no durability guarantee.
type InMemoryStore struct {
	mu      sync.RWMutex
	entries []Entry
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{}
}

func (s *InMemoryStore) Append(_ context.Context, e *Entry) error {
	if e.EntryHash == "" || e.PrevHash == "" {
		return fmt.Errorf("audit: InMemoryStore.Append: entry must be sealed before appending")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, *e)
	return nil
}

func (s *InMemoryStore) LatestHash(_ context.Context) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.entries) == 0 {
		return ZeroHash, nil
	}
	return s.entries[len(s.entries)-1].EntryHash, nil
}

func (s *InMemoryStore) GetByRound(_ context.Context, roundID string) ([]Entry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Entry
	for _, e := range s.entries {
		if e.RoundID == roundID {
			out = append(out, e)
		}
	}
	return out, nil
}

func (s *InMemoryStore) VerifyChain(_ context.Context, tenantID string) (bool, error) {
	s.mu.RLock()
	entries := make([]Entry, 0, len(s.entries))
	for _, e := range s.entries {
		if e.TenantID == tenantID {
			entries = append(entries, e)
		}
	}
	s.mu.RUnlock()

	if len(entries) == 0 {
		return true, nil
	}

	idx, err := VerifyEntries(entries, ZeroHash)
	if err != nil {
		return false, err
	}
	return idx == -1, nil
}
