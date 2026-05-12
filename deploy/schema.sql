-- rng-service audit log schema
-- Apply with: psql $DATABASE_URL -f deploy/schema.sql
--
-- Immutability guarantees:
--   1. Trigger rejects UPDATE and DELETE on rng_audit_log.
--   2. RLS restricts each tenant to their own rows.
--   3. Application user must NOT have DROP/TRUNCATE privileges in production.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";  -- for gen_random_uuid() if needed

-- ---------------------------------------------------------------------------
-- Audit log — append-only, one row per RNG generation call
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS rng_audit_log (
    id           BIGSERIAL    PRIMARY KEY,

    -- Hash chain fields (BMM requirement: tamper-evident audit trail)
    entry_hash   CHAR(64)     NOT NULL UNIQUE,  -- SHA256 of this entry, hex
    prev_hash    CHAR(64)     NOT NULL,          -- SHA256 of previous entry, hex

    -- Request identification (all fields mandatory per multi-tenancy rule)
    tenant_id    VARCHAR(64)  NOT NULL,
    game_id      VARCHAR(128) NOT NULL,
    round_id     VARCHAR(128) NOT NULL,
    request_id   UUID         NOT NULL,

    -- Generated values
    values_json  JSONB        NOT NULL,   -- the random numbers produced
    value_count  INTEGER      NOT NULL CHECK (value_count >= 0),
    min_value    BIGINT       NOT NULL,
    max_value    BIGINT       NOT NULL CHECK (max_value >= min_value),

    -- HMAC-SHA256 of (tenant_id || round_id || timestamp || values)
    signature    CHAR(64)     NOT NULL,

    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    reseed_event BOOLEAN      NOT NULL DEFAULT FALSE
);

-- Indexes for audit queries and chain verification
CREATE INDEX IF NOT EXISTS idx_audit_tenant_created
    ON rng_audit_log (tenant_id, created_at ASC);

CREATE INDEX IF NOT EXISTS idx_audit_round
    ON rng_audit_log (round_id);

CREATE INDEX IF NOT EXISTS idx_audit_request
    ON rng_audit_log (request_id);

-- ---------------------------------------------------------------------------
-- Immutability trigger — reject all UPDATE and DELETE
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION rng_audit_log_immutable()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'rng_audit_log is append-only: UPDATE and DELETE are not permitted';
END;
$$;

DROP TRIGGER IF EXISTS trg_audit_immutable ON rng_audit_log;
CREATE TRIGGER trg_audit_immutable
    BEFORE UPDATE OR DELETE ON rng_audit_log
    FOR EACH ROW EXECUTE FUNCTION rng_audit_log_immutable();

-- ---------------------------------------------------------------------------
-- Row Level Security — each tenant sees only their own rows
-- ---------------------------------------------------------------------------
ALTER TABLE rng_audit_log ENABLE ROW LEVEL SECURITY;

-- Policy for the application role (set current_setting('rng.tenant_id') per connection)
DROP POLICY IF EXISTS rng_audit_tenant_isolation ON rng_audit_log;
CREATE POLICY rng_audit_tenant_isolation ON rng_audit_log
    USING (tenant_id = current_setting('rng.tenant_id', true));

-- Superuser / audit role bypasses RLS for BMM verification and chain checks.
-- Grant to: GRANT SELECT ON rng_audit_log TO rng_auditor;
-- Auditor role does NOT bypass RLS — must SET LOCAL rng.tenant_id to query.

-- ---------------------------------------------------------------------------
-- Re-seed event log (referenced by ReseedEvent.SeedHash in pool.go)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS rng_reseed_log (
    id              BIGSERIAL   PRIMARY KEY,
    timestamp_utc   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tenant_id       VARCHAR(64) NOT NULL,
    entropy_source  VARCHAR(64) NOT NULL,
    seed_hash       CHAR(64)    NOT NULL,  -- SHA256 of seed bytes, NEVER the seed
    outputs_since   BIGINT      NOT NULL DEFAULT 0,
    reason          VARCHAR(64) NOT NULL DEFAULT 'scheduled'
);

CREATE OR REPLACE FUNCTION rng_reseed_log_immutable()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'rng_reseed_log is append-only';
END;
$$;

DROP TRIGGER IF EXISTS trg_reseed_immutable ON rng_reseed_log;
CREATE TRIGGER trg_reseed_immutable
    BEFORE UPDATE OR DELETE ON rng_reseed_log
    FOR EACH ROW EXECUTE FUNCTION rng_reseed_log_immutable();
