package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/lucky-and-fun/rng-service/internal/audit"
	"github.com/lucky-and-fun/rng-service/internal/config"
	"github.com/lucky-and-fun/rng-service/internal/csprng"
	"github.com/lucky-and-fun/rng-service/internal/entropy"
	"github.com/lucky-and-fun/rng-service/internal/health"
	"github.com/lucky-and-fun/rng-service/internal/scaling"
)

// Server is the REST API gateway.
// It coordinates the RNG engine, audit chain, re-seed policy, and health checks.
type Server struct {
	drbg       *csprng.DRBG
	pool       *entropy.Pool
	chain      *audit.Chain
	store      audit.Store
	keys       audit.KeyStore
	limiter    *rateLimiter
	cfg        *config.Config
	checker    *health.Checker    // tamper detection; may be nil in tests
	selfTester *health.SelfTester // NIST self-test; may be nil in tests
	metrics    *health.Metrics    // Prometheus; may be nil in tests

	reseedMu   sync.Mutex
	lastReseed time.Time
}

// NewServer constructs a Server. checker, selfTester, and metrics may be nil (tests).
func NewServer(
	drbg *csprng.DRBG,
	pool *entropy.Pool,
	chain *audit.Chain,
	store audit.Store,
	keys audit.KeyStore,
	cfg *config.Config,
	checker *health.Checker,
	selfTester *health.SelfTester,
	metrics *health.Metrics,
) *Server {
	return &Server{
		drbg:       drbg,
		pool:       pool,
		chain:      chain,
		store:      store,
		keys:       keys,
		limiter:    newRateLimiter(cfg.RateLimitRPS),
		cfg:        cfg,
		checker:    checker,
		selfTester: selfTester,
		metrics:    metrics,
		lastReseed: time.Now(),
	}
}

// Handler returns an http.Handler with all routes and middleware applied.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /v1/generate", s.handleGenerate)
	mux.HandleFunc("POST /v1/generate/batch", s.handleGenerateBatch)
	mux.HandleFunc("POST /v1/generate/shuffle", s.handleShuffle)
	mux.HandleFunc("GET /v1/health", s.handleHealth)
	mux.HandleFunc("GET /v1/stats", s.handleStats)
	mux.HandleFunc("GET /v1/audit/{round_id}", s.handleAuditRound)

	// Middleware order (outermost = called first):
	//   authMiddleware → rateLimitMiddleware → mux handler
	limited := rateLimitMiddleware(s.limiter, mux)
	return authMiddleware(s.cfg.JWTSecret, s.cfg.APIKeys, limited)
}

// ─── Request / Response types ────────────────────────────────────────────────

type generateRequest struct {
	TenantID string `json:"tenant_id"`
	GameID   string `json:"game_id"`
	RoundID  string `json:"round_id"`
	Count    int    `json:"count"`
	Min      int64  `json:"min"`
	Max      int64  `json:"max"`
}

type generateResponse struct {
	RequestID    string  `json:"request_id"`
	TenantID     string  `json:"tenant_id"`
	GameID       string  `json:"game_id"`
	RoundID      string  `json:"round_id"`
	Values       []int64 `json:"values"`
	TimestampUTC string  `json:"timestamp_utc"`
	Signature    string  `json:"signature"`
	AuditHash    string  `json:"audit_hash"`
}

type batchItem struct {
	Count int   `json:"count"`
	Min   int64 `json:"min"`
	Max   int64 `json:"max"`
}

type batchRequest struct {
	TenantID string      `json:"tenant_id"`
	GameID   string      `json:"game_id"`
	RoundID  string      `json:"round_id"`
	Requests []batchItem `json:"requests"`
}

type batchResponse struct {
	Results []generateResponse `json:"results"`
}

type shuffleRequest struct {
	TenantID string  `json:"tenant_id"`
	GameID   string  `json:"game_id"`
	RoundID  string  `json:"round_id"`
	Items    []int64 `json:"items"`
}

type shuffleResponse struct {
	RequestID    string  `json:"request_id"`
	TenantID     string  `json:"tenant_id"`
	GameID       string  `json:"game_id"`
	RoundID      string  `json:"round_id"`
	Shuffled     []int64 `json:"shuffled"`
	TimestampUTC string  `json:"timestamp_utc"`
	Signature    string  `json:"signature"`
	AuditHash    string  `json:"audit_hash"`
}

// ─── Handlers ────────────────────────────────────────────────────────────────

func (s *Server) handleGenerate(w http.ResponseWriter, r *http.Request) {
	var req generateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if err := validateGenerateRequest(req.TenantID, req.GameID, req.RoundID, req.Count, req.Min, req.Max); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// tenant_id in body must match the authenticated tenant
	if ctxTenant := tenantFromContext(r.Context()); ctxTenant != req.TenantID {
		writeError(w, http.StatusForbidden, "tenant_id mismatch")
		return
	}

	resp, err := s.generate(r.Context(), req.TenantID, req.GameID, req.RoundID, req.Count, req.Min, req.Max)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleGenerateBatch(w http.ResponseWriter, r *http.Request) {
	var req batchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.TenantID == "" || req.GameID == "" || req.RoundID == "" {
		writeError(w, http.StatusBadRequest, "tenant_id, game_id, round_id are required")
		return
	}
	if ctxTenant := tenantFromContext(r.Context()); ctxTenant != req.TenantID {
		writeError(w, http.StatusForbidden, "tenant_id mismatch")
		return
	}
	if len(req.Requests) == 0 {
		writeError(w, http.StatusBadRequest, "requests must not be empty")
		return
	}
	if len(req.Requests) > 100 {
		writeError(w, http.StatusBadRequest, "requests exceeds max batch size of 100")
		return
	}

	results := make([]generateResponse, 0, len(req.Requests))
	for _, item := range req.Requests {
		if err := validateGenerateRequest(req.TenantID, req.GameID, req.RoundID, item.Count, item.Min, item.Max); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		resp, err := s.generate(r.Context(), req.TenantID, req.GameID, req.RoundID, item.Count, item.Min, item.Max)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		results = append(results, *resp)
	}
	writeJSON(w, http.StatusOK, batchResponse{Results: results})
}

func (s *Server) handleShuffle(w http.ResponseWriter, r *http.Request) {
	var req shuffleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.TenantID == "" || req.GameID == "" || req.RoundID == "" {
		writeError(w, http.StatusBadRequest, "tenant_id, game_id, round_id are required")
		return
	}
	if ctxTenant := tenantFromContext(r.Context()); ctxTenant != req.TenantID {
		writeError(w, http.StatusForbidden, "tenant_id mismatch")
		return
	}
	if len(req.Items) == 0 {
		writeError(w, http.StatusBadRequest, "items must not be empty")
		return
	}
	if len(req.Items) > 10000 {
		writeError(w, http.StatusBadRequest, "items exceeds max size of 10000")
		return
	}

	if err := s.reseedIfNeeded(r.Context(), req.TenantID); err != nil {
		writeError(w, http.StatusInternalServerError, "reseed failed: "+err.Error())
		return
	}

	// Convert to []int for scaling.Shuffle.
	deck := make([]int, len(req.Items))
	for i, v := range req.Items {
		deck[i] = int(v)
	}
	if err := scaling.Shuffle(s.drbg, deck); err != nil {
		writeError(w, http.StatusInternalServerError, "shuffle failed: "+err.Error())
		return
	}
	shuffled := make([]int64, len(deck))
	for i, v := range deck {
		shuffled[i] = int64(v)
	}

	reqID, err := audit.NewRequestID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "request ID: "+err.Error())
		return
	}
	now := time.Now().UTC()

	// Convert to int64 values for audit entry.
	values := shuffled

	sigKey, err := s.keys.SigningKey(req.TenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "signing key: "+err.Error())
		return
	}

	entry := &audit.Entry{
		TenantID:   req.TenantID,
		GameID:     req.GameID,
		RoundID:    req.RoundID,
		RequestID:  reqID,
		Values:     values,
		ValueCount: len(values),
		MinValue:   minInt64(shuffled),
		MaxValue:   maxInt64(shuffled),
		CreatedAt:  now,
	}
	entry.Sign(sigKey)
	if err := s.chain.Seal(entry); err != nil {
		writeError(w, http.StatusInternalServerError, "audit seal: "+err.Error())
		return
	}
	if err := s.store.Append(r.Context(), entry); err != nil {
		writeError(w, http.StatusInternalServerError, "audit store: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, shuffleResponse{
		RequestID:    reqID,
		TenantID:     req.TenantID,
		GameID:       req.GameID,
		RoundID:      req.RoundID,
		Shuffled:     shuffled,
		TimestampUTC: now.Format(time.RFC3339Nano),
		Signature:    entry.Signature,
		AuditHash:    entry.EntryHash,
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	csprngStatus := "ok"
	if err := s.drbg.HealthCheck(); err != nil {
		csprngStatus = "error"
	}

	tamperStatus := "ok"
	binaryHash := s.cfg.BinaryHash
	if s.checker != nil {
		if err := s.checker.Verify(); err != nil {
			tamperStatus = "TAMPER_DETECTED"
		}
		binaryHash = s.checker.StartupHash()
	}

	resp := map[string]any{
		"status":               overall(csprngStatus, tamperStatus),
		"entropy_pool":         "ok",
		"csprng":               csprngStatus,
		"tamper_detection":     tamperStatus,
		"audit_store":          "ok",
		"last_reseed_utc":      s.lastReseed.Format(time.RFC3339Nano),
		"outputs_since_reseed": s.drbg.OutputBytes(),
		"binary_hash":          binaryHash,
	}

	if s.selfTester != nil {
		results, lastRun := s.selfTester.Results()
		nistStatus := map[string]any{}
		for _, r := range results {
			nistStatus[r.Name] = map[string]any{
				"p_value": r.PValue,
				"status":  string(r.Status),
			}
		}
		resp["nist_selftest"] = nistStatus
		if !lastRun.IsZero() {
			resp["last_selftest_utc"] = lastRun.Format(time.RFC3339Nano)
		}
		if s.selfTester.HasCriticalFailure() {
			resp["status"] = "error"
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

func overall(statuses ...string) string {
	for _, s := range statuses {
		if s != "ok" {
			return "error"
		}
	}
	return "ok"
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	tenant := tenantFromContext(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant_id":       tenant,
		"total_outputs":   s.drbg.OutputBytes(),
		"binary_hash":     s.cfg.BinaryHash,
		"last_reseed_utc": s.lastReseed.Format(time.RFC3339Nano),
	})
}

func (s *Server) handleAuditRound(w http.ResponseWriter, r *http.Request) {
	roundID := r.PathValue("round_id")
	if roundID == "" {
		writeError(w, http.StatusBadRequest, "round_id is required")
		return
	}

	entries, err := s.store.GetByRound(r.Context(), roundID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	chainValid := false
	var chainErr string
	if len(entries) > 0 {
		idx, err := audit.VerifyEntries(entries, entries[0].PrevHash)
		chainValid = idx == -1 && err == nil
		if err != nil {
			chainErr = err.Error()
		}
	}

	resp := map[string]any{
		"round_id":         roundID,
		"entries":          entries,
		"hash_chain_valid": chainValid,
	}
	if chainErr != "" {
		resp["chain_error"] = chainErr
	}
	writeJSON(w, http.StatusOK, resp)
}

// ─── Core generation logic (shared by handleGenerate and handleGenerateBatch) ─

func (s *Server) generate(ctx context.Context, tenantID, gameID, roundID string, count int, min, max int64) (*generateResponse, error) {
	if err := s.reseedIfNeeded(ctx, tenantID); err != nil {
		return nil, fmt.Errorf("reseed: %w", err)
	}

	values := make([]int64, count)
	span := uint64(max-min) + 1
	for i := range values {
		n, err := scaling.RandRange(s.drbg, span)
		if err != nil {
			return nil, fmt.Errorf("generate value: %w", err)
		}
		values[i] = min + int64(n)
	}

	reqID, err := audit.NewRequestID()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()

	sigKey, err := s.keys.SigningKey(tenantID)
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}

	entry := &audit.Entry{
		TenantID:   tenantID,
		GameID:     gameID,
		RoundID:    roundID,
		RequestID:  reqID,
		Values:     values,
		ValueCount: len(values),
		MinValue:   min,
		MaxValue:   max,
		CreatedAt:  now,
	}
	entry.Sign(sigKey)
	if err := s.chain.Seal(entry); err != nil {
		return nil, fmt.Errorf("audit seal: %w", err)
	}
	if err := s.store.Append(ctx, entry); err != nil {
		return nil, fmt.Errorf("audit store: %w", err)
	}

	return &generateResponse{
		RequestID:    reqID,
		TenantID:     tenantID,
		GameID:       gameID,
		RoundID:      roundID,
		Values:       values,
		TimestampUTC: now.Format(time.RFC3339Nano),
		Signature:    entry.Signature,
		AuditHash:    entry.EntryHash,
	}, nil
}

// reseedIfNeeded re-seeds the DRBG if the output-count or time threshold is reached.
func (s *Server) reseedIfNeeded(ctx context.Context, tenantID string) error {
	if s.drbg.OutputBytes() < s.cfg.Reseed.IntervalOutputs &&
		time.Since(s.lastReseed) < s.cfg.Reseed.IntervalSeconds {
		return nil
	}

	s.reseedMu.Lock()
	defer s.reseedMu.Unlock()

	// Double-check after acquiring the lock.
	if s.drbg.OutputBytes() < s.cfg.Reseed.IntervalOutputs &&
		time.Since(s.lastReseed) < s.cfg.Reseed.IntervalSeconds {
		return nil
	}

	entropy, _, err := s.pool.CollectForReseed(csprng.SeedLen, tenantID, s.drbg.OutputBytes())
	if err != nil {
		return err
	}
	if err := s.drbg.Reseed(entropy); err != nil {
		return err
	}
	s.lastReseed = time.Now()
	return nil
}

func validateGenerateRequest(tenantID, gameID, roundID string, count int, min, max int64) error {
	if tenantID == "" {
		return fmt.Errorf("tenant_id is required")
	}
	if gameID == "" {
		return fmt.Errorf("game_id is required")
	}
	if roundID == "" {
		return fmt.Errorf("round_id is required")
	}
	if count <= 0 || count > 10000 {
		return fmt.Errorf("count must be between 1 and 10000, got %d", count)
	}
	if min > max {
		return fmt.Errorf("min (%d) must be <= max (%d)", min, max)
	}
	return nil
}

func minInt64(s []int64) int64 {
	if len(s) == 0 {
		return 0
	}
	m := s[0]
	for _, v := range s[1:] {
		if v < m {
			m = v
		}
	}
	return m
}

func maxInt64(s []int64) int64 {
	if len(s) == 0 {
		return 0
	}
	m := s[0]
	for _, v := range s[1:] {
		if v > m {
			m = v
		}
	}
	return m
}
