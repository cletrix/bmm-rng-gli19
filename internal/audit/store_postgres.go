package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// PostgresStore is an append-only audit log backed by PostgreSQL.
// The schema (deploy/schema.sql) enforces immutability via triggers and RLS.
//
// Register the PostgreSQL driver in your main package:
//
//	import _ "github.com/lib/pq"
type PostgresStore struct {
	db *sql.DB
}

// NewPostgresStore creates a store using an existing *sql.DB connection.
// The connection must point to a database with deploy/schema.sql applied.
func NewPostgresStore(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

// Append inserts one sealed entry into rng_audit_log.
// The entry must have EntryHash, PrevHash, and Signature already set.
func (s *PostgresStore) Append(ctx context.Context, e *Entry) error {
	if e.EntryHash == "" || e.PrevHash == "" || e.Signature == "" {
		return fmt.Errorf("audit: PostgresStore.Append: entry must be sealed and signed")
	}

	valJSON, err := json.Marshal(e.Values)
	if err != nil {
		return fmt.Errorf("audit: marshal values: %w", err)
	}

	const q = `
		INSERT INTO rng_audit_log (
			entry_hash, prev_hash,
			tenant_id, game_id, round_id, request_id,
			values_json, value_count, min_value, max_value,
			signature, created_at, reseed_event
		) VALUES (
			$1, $2,
			$3, $4, $5, $6,
			$7, $8, $9, $10,
			$11, $12, $13
		)`

	_, err = s.db.ExecContext(ctx, q,
		e.EntryHash, e.PrevHash,
		e.TenantID, e.GameID, e.RoundID, e.RequestID,
		valJSON, e.ValueCount, e.MinValue, e.MaxValue,
		e.Signature, e.CreatedAt.UTC(), e.ReseedEvent,
	)
	if err != nil {
		return fmt.Errorf("audit: insert entry: %w", err)
	}
	return nil
}

// LatestHash returns the EntryHash of the most recent row in the table.
// Returns ZeroHash if the table is empty.
func (s *PostgresStore) LatestHash(ctx context.Context) (string, error) {
	const q = `SELECT entry_hash FROM rng_audit_log ORDER BY id DESC LIMIT 1`
	var hash string
	err := s.db.QueryRowContext(ctx, q).Scan(&hash)
	if err == sql.ErrNoRows {
		return ZeroHash, nil
	}
	if err != nil {
		return "", fmt.Errorf("audit: latest hash: %w", err)
	}
	return hash, nil
}

// GetByRound returns all entries for the given round_id, ordered by created_at.
func (s *PostgresStore) GetByRound(ctx context.Context, roundID string) ([]Entry, error) {
	const q = `
		SELECT entry_hash, prev_hash,
		       tenant_id, game_id, round_id, request_id,
		       values_json, value_count, min_value, max_value,
		       signature, created_at, reseed_event
		FROM rng_audit_log
		WHERE round_id = $1
		ORDER BY id ASC`

	rows, err := s.db.QueryContext(ctx, q, roundID)
	if err != nil {
		return nil, fmt.Errorf("audit: get by round: %w", err)
	}
	defer rows.Close()

	return scanEntries(rows)
}

// VerifyChain re-reads all entries for tenantID ordered by insertion (id ASC)
// and verifies the hash chain end-to-end.
// Returns true and nil if the chain is intact.
func (s *PostgresStore) VerifyChain(ctx context.Context, tenantID string) (bool, error) {
	const q = `
		SELECT entry_hash, prev_hash,
		       tenant_id, game_id, round_id, request_id,
		       values_json, value_count, min_value, max_value,
		       signature, created_at, reseed_event
		FROM rng_audit_log
		WHERE tenant_id = $1
		ORDER BY id ASC`

	rows, err := s.db.QueryContext(ctx, q, tenantID)
	if err != nil {
		return false, fmt.Errorf("audit: verify chain query: %w", err)
	}
	defer rows.Close()

	entries, err := scanEntries(rows)
	if err != nil {
		return false, err
	}
	if len(entries) == 0 {
		return true, nil
	}

	idx, err := VerifyEntries(entries, ZeroHash)
	if err != nil {
		return false, err
	}
	return idx == -1, nil
}

func scanEntries(rows *sql.Rows) ([]Entry, error) {
	var out []Entry
	for rows.Next() {
		var e Entry
		var valJSON []byte
		var createdAt time.Time

		err := rows.Scan(
			&e.EntryHash, &e.PrevHash,
			&e.TenantID, &e.GameID, &e.RoundID, &e.RequestID,
			&valJSON, &e.ValueCount, &e.MinValue, &e.MaxValue,
			&e.Signature, &createdAt, &e.ReseedEvent,
		)
		if err != nil {
			return nil, fmt.Errorf("audit: scan entry: %w", err)
		}
		e.CreatedAt = createdAt.UTC()
		if err := json.Unmarshal(valJSON, &e.Values); err != nil {
			return nil, fmt.Errorf("audit: unmarshal values: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: rows error: %w", err)
	}
	return out, nil
}
