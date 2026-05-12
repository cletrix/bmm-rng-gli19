// Package audit implements the Audit & Evidence Layer required for BMM certification.
//
// Every RNG output is signed with HMAC-SHA256 and linked into an append-only
// hash chain, producing a tamper-evident audit trail verifiable by the BMM.
package audit

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ZeroHash is the chain predecessor for the very first entry (genesis).
const ZeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Entry is one immutable audit log record.
// After Seal is called by the Chain, EntryHash and PrevHash are set permanently.
type Entry struct {
	EntryHash   string    // SHA256 of this entry, hex-encoded
	PrevHash    string    // SHA256 of the previous entry, hex-encoded
	TenantID    string    // identifies the B2B operator
	GameID      string    // identifies the game type
	RoundID     string    // identifies the specific game round
	RequestID   string    // UUID, unique per API call
	Values      []int64   // the generated random numbers
	ValueCount  int       // len(Values)
	MinValue    int64     // requested minimum (inclusive)
	MaxValue    int64     // requested maximum (inclusive)
	Signature   string    // HMAC-SHA256, hex-encoded
	CreatedAt   time.Time // UTC
	ReseedEvent bool      // true if this entry marks a CSPRNG re-seed
}

// NewRequestID generates a random UUID v4 for the RequestID field.
func NewRequestID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant bits
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// signData returns the canonical binary payload signed by HMAC-SHA256.
//
// Layout (all integers big-endian):
//
//	uint32 len(TenantID) | TenantID bytes
//	uint32 len(RoundID)  | RoundID bytes
//	int64  CreatedAt.UnixNano()
//	uint32 len(Values)
//	int64  Values[0] … int64 Values[n-1]
//
// Length-prefixed strings prevent ambiguous concatenation.
// This format is documented in docs/bmm-submission-package/algorithm-description.md.
func (e *Entry) signData() []byte {
	size := 4 + len(e.TenantID) +
		4 + len(e.RoundID) +
		8 +
		4 + len(e.Values)*8

	buf := make([]byte, 0, size)

	buf = appendLenPrefixed(buf, []byte(e.TenantID))
	buf = appendLenPrefixed(buf, []byte(e.RoundID))

	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(e.CreatedAt.UnixNano()))
	buf = append(buf, ts[:]...)

	var cnt [4]byte
	binary.BigEndian.PutUint32(cnt[:], uint32(len(e.Values)))
	buf = append(buf, cnt[:]...)

	var vb [8]byte
	for _, v := range e.Values {
		binary.BigEndian.PutUint64(vb[:], uint64(v))
		buf = append(buf, vb[:]...)
	}
	return buf
}

// Sign computes HMAC-SHA256 over the canonical sign data and sets e.Signature.
// Call this before Chain.Seal.
func (e *Entry) Sign(key []byte) {
	mac := hmac.New(sha256.New, key)
	mac.Write(e.signData())
	e.Signature = hex.EncodeToString(mac.Sum(nil))
}

// Verify returns true if the HMAC signature is valid for the given key.
func (e *Entry) Verify(key []byte) bool {
	if e.Signature == "" {
		return false
	}
	got, err := hex.DecodeString(e.Signature)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(e.signData())
	return hmac.Equal(mac.Sum(nil), got)
}

// computeHash computes this entry's position in the hash chain.
//
// Layout (all integers big-endian):
//
//	32 bytes  PrevHash (decoded from hex)
//	int64     CreatedAt.UnixNano()
//	uint32    len(TenantID) | TenantID bytes
//	uint32    len(RoundID)  | RoundID bytes
//	uint32    len(Values)
//	int64     Values[0] … int64 Values[n-1]
//	32 bytes  Signature (decoded from hex)
func (e *Entry) computeHash() (string, error) {
	prevBytes, err := hex.DecodeString(e.PrevHash)
	if err != nil {
		return "", fmt.Errorf("audit: invalid prev_hash %q: %w", e.PrevHash, err)
	}
	sigBytes, err := hex.DecodeString(e.Signature)
	if err != nil {
		return "", fmt.Errorf("audit: invalid signature %q: %w", e.Signature, err)
	}

	h := sha256.New()
	h.Write(prevBytes)

	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(e.CreatedAt.UnixNano()))
	h.Write(ts[:])

	h.Write(appendLenPrefixed(nil, []byte(e.TenantID)))
	h.Write(appendLenPrefixed(nil, []byte(e.RoundID)))

	var cnt [4]byte
	binary.BigEndian.PutUint32(cnt[:], uint32(len(e.Values)))
	h.Write(cnt[:])

	var vb [8]byte
	for _, v := range e.Values {
		binary.BigEndian.PutUint64(vb[:], uint64(v))
		h.Write(vb[:])
	}

	h.Write(sigBytes)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Chain maintains the hash chain tip for the audit log.
// Concurrent Seal calls are serialized by the internal mutex.
type Chain struct {
	prevHash string
	mu       sync.Mutex
}

// NewChain creates a chain starting from genesis (all-zero predecessor).
func NewChain() *Chain {
	return &Chain{prevHash: ZeroHash}
}

// LoadChain resumes a chain from a known previous hash (e.g. after restart).
// lastHash is the EntryHash of the most recent entry from the store.
func LoadChain(lastHash string) (*Chain, error) {
	if len(lastHash) != 64 {
		return nil, fmt.Errorf("audit: LoadChain: hash must be 64 hex chars, got %d", len(lastHash))
	}
	return &Chain{prevHash: lastHash}, nil
}

// Seal finalizes an entry by linking it to the chain and computing its hash.
// The entry must have Signature set (call e.Sign first).
// After Seal, e.PrevHash and e.EntryHash are permanently set.
func (c *Chain) Seal(e *Entry) error {
	if e.Signature == "" {
		return errors.New("audit: entry must be signed before sealing")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	e.PrevHash = c.prevHash
	hash, err := e.computeHash()
	if err != nil {
		return err
	}
	e.EntryHash = hash
	c.prevHash = hash
	return nil
}

// PrevHash returns the hash of the last sealed entry (the current chain tip).
func (c *Chain) PrevHash() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.prevHash
}

// VerifyEntries checks the integrity of a sequence of entries.
// firstPrevHash is the expected PrevHash of entries[0] (use ZeroHash for a full chain).
// Returns the index of the first invalid entry, or -1 if all are valid.
func VerifyEntries(entries []Entry, firstPrevHash string) (int, error) {
	prevHash := firstPrevHash
	for i := range entries {
		e := &entries[i]
		if e.PrevHash != prevHash {
			return i, fmt.Errorf("audit: entry[%d]: prev_hash mismatch: got %s, want %s",
				i, e.PrevHash, prevHash)
		}
		computed, err := e.computeHash()
		if err != nil {
			return i, fmt.Errorf("audit: entry[%d]: %w", i, err)
		}
		if computed != e.EntryHash {
			return i, fmt.Errorf("audit: entry[%d]: entry_hash mismatch: got %s, want %s",
				i, e.EntryHash, computed)
		}
		prevHash = e.EntryHash
	}
	return -1, nil
}

// KeyStore provides per-tenant HMAC signing keys.
type KeyStore interface {
	// SigningKey returns the current signing key for the given tenant.
	// Keys are rotated monthly; the store must handle key versioning.
	SigningKey(tenantID string) ([]byte, error)
}

// StaticKeyStore is a KeyStore backed by an in-memory map.
// For development and testing only; production must use a KMS or Vault backend.
type StaticKeyStore struct {
	keys map[string][]byte // tenantID → key
}

// NewStaticKeyStore creates a key store from a tenantID→key map.
// Keys must be at least 32 bytes (256 bits) for HMAC-SHA256 security.
func NewStaticKeyStore(keys map[string][]byte) (*StaticKeyStore, error) {
	for id, k := range keys {
		if len(k) < 32 {
			return nil, fmt.Errorf("audit: key for tenant %q is only %d bytes; need >= 32", id, len(k))
		}
	}
	cp := make(map[string][]byte, len(keys))
	for k, v := range keys {
		cp[k] = v
	}
	return &StaticKeyStore{keys: cp}, nil
}

// SigningKey returns the key for the given tenant.
func (s *StaticKeyStore) SigningKey(tenantID string) ([]byte, error) {
	k, ok := s.keys[tenantID]
	if !ok {
		// Fallback: look for a wildcard key (tenantID="*")
		k, ok = s.keys["*"]
		if !ok {
			return nil, fmt.Errorf("audit: no signing key for tenant %q", tenantID)
		}
	}
	return k, nil
}

func appendLenPrefixed(buf, data []byte) []byte {
	var ln [4]byte
	binary.BigEndian.PutUint32(ln[:], uint32(len(data)))
	buf = append(buf, ln[:]...)
	buf = append(buf, data...)
	return buf
}
