package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lucky-and-fun/rng-service/internal/audit"
	"github.com/lucky-and-fun/rng-service/internal/config"
	"github.com/lucky-and-fun/rng-service/internal/csprng"
	"github.com/lucky-and-fun/rng-service/internal/entropy"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()

	pool := entropy.New("")
	seed, _, err := pool.CollectForReseed(csprng.SeedLen, "test", 0)
	if err != nil {
		t.Fatal(err)
	}
	drbg, err := csprng.New(seed)
	if err != nil {
		t.Fatal(err)
	}

	chain := audit.NewChain()
	store := audit.NewInMemoryStore()
	keys, _ := audit.NewStaticKeyStore(map[string][]byte{
		"*": bytes.Repeat([]byte{0xAB}, 32),
	})

	cfg := &config.Config{}
	cfg.BinaryHash = "test-hash"
	cfg.RateLimitRPS = 1000
	cfg.JWTSecret = testSecret
	cfg.APIKeys = testAPIKeys
	cfg.Reseed.IntervalOutputs = 1_000_000
	cfg.Reseed.IntervalSeconds = time.Hour

	return NewServer(drbg, pool, chain, store, keys, cfg, nil, nil, nil)
}

// doRequest runs a request through the full middleware + handler stack.
func doRequest(t *testing.T, s *Server, method, path string, body any, apiKey string) *httptest.ResponseRecorder {
	t.Helper()
	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", apiKey)

	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	return rr
}

// --- POST /v1/generate ---

func TestHandleGenerate_Valid(t *testing.T) {
	s := newTestServer(t)
	rr := doRequest(t, s, "POST", "/v1/generate", map[string]any{
		"tenant_id": "tenant-a",
		"game_id":   "bingo-90",
		"round_id":  "round-001",
		"count":     5,
		"min":       1,
		"max":       90,
	}, "key-tenant-a")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}

	var resp generateResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Values) != 5 {
		t.Fatalf("len(Values) = %d, want 5", len(resp.Values))
	}
	for _, v := range resp.Values {
		if v < 1 || v > 90 {
			t.Errorf("value %d out of range [1, 90]", v)
		}
	}
	if resp.Signature == "" {
		t.Error("Signature is empty")
	}
	if resp.AuditHash == "" {
		t.Error("AuditHash is empty")
	}
	if resp.RequestID == "" {
		t.Error("RequestID is empty")
	}
}

func TestHandleGenerate_Unauthenticated(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest("POST", "/v1/generate", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
}

func TestHandleGenerate_TenantMismatch(t *testing.T) {
	s := newTestServer(t)
	// Authenticated as tenant-a but body says tenant-b.
	rr := doRequest(t, s, "POST", "/v1/generate", map[string]any{
		"tenant_id": "tenant-b",
		"game_id":   "bingo-90",
		"round_id":  "round-001",
		"count":     1,
		"min":       1,
		"max":       90,
	}, "key-tenant-a")

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
}

func TestHandleGenerate_MissingFields(t *testing.T) {
	s := newTestServer(t)
	rr := doRequest(t, s, "POST", "/v1/generate", map[string]any{
		"tenant_id": "tenant-a",
		// missing game_id, round_id, count, min, max
	}, "key-tenant-a")

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestHandleGenerate_InvalidRange(t *testing.T) {
	s := newTestServer(t)
	rr := doRequest(t, s, "POST", "/v1/generate", map[string]any{
		"tenant_id": "tenant-a",
		"game_id":   "bingo-90",
		"round_id":  "round-001",
		"count":     1,
		"min":       90,
		"max":       1, // min > max
	}, "key-tenant-a")

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

// --- POST /v1/generate/batch ---

func TestHandleGenerateBatch_Valid(t *testing.T) {
	s := newTestServer(t)
	rr := doRequest(t, s, "POST", "/v1/generate/batch", map[string]any{
		"tenant_id": "tenant-a",
		"game_id":   "bingo-90",
		"round_id":  "round-batch",
		"requests": []map[string]any{
			{"count": 5, "min": 1, "max": 90},
			{"count": 3, "min": 1, "max": 75},
		},
	}, "key-tenant-a")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}

	var resp batchResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Results) != 2 {
		t.Fatalf("len(Results) = %d, want 2", len(resp.Results))
	}
	if len(resp.Results[0].Values) != 5 {
		t.Errorf("first batch: len(Values) = %d, want 5", len(resp.Results[0].Values))
	}
	if len(resp.Results[1].Values) != 3 {
		t.Errorf("second batch: len(Values) = %d, want 3", len(resp.Results[1].Values))
	}
}

// --- POST /v1/generate/shuffle ---

func TestHandleShuffle_Valid(t *testing.T) {
	s := newTestServer(t)
	items := make([]int64, 90)
	for i := range items {
		items[i] = int64(i + 1)
	}

	rr := doRequest(t, s, "POST", "/v1/generate/shuffle", map[string]any{
		"tenant_id": "tenant-a",
		"game_id":   "bingo-90",
		"round_id":  "round-shuf",
		"items":     items,
	}, "key-tenant-a")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}

	var resp shuffleResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Shuffled) != 90 {
		t.Fatalf("len(Shuffled) = %d, want 90", len(resp.Shuffled))
	}
	// Check all elements preserved.
	seen := make(map[int64]bool)
	for _, v := range resp.Shuffled {
		seen[v] = true
	}
	if len(seen) != 90 {
		t.Errorf("shuffle lost elements: %d unique values, want 90", len(seen))
	}
}

// --- GET /v1/health ---

func TestHandleHealth(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest("GET", "/v1/health", nil)
	req.Header.Set("X-Api-Key", "key-tenant-a")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["status"] != "ok" {
		t.Errorf("status = %v, want ok", resp["status"])
	}
	if resp["binary_hash"] != "test-hash" {
		t.Errorf("binary_hash = %v, want test-hash", resp["binary_hash"])
	}
}

// --- GET /v1/audit/{round_id} ---

func TestHandleAuditRound(t *testing.T) {
	s := newTestServer(t)

	// Generate first so there are audit entries.
	doRequest(t, s, "POST", "/v1/generate", map[string]any{
		"tenant_id": "tenant-a",
		"game_id":   "bingo-90",
		"round_id":  "round-audit-test",
		"count":     3,
		"min":       1,
		"max":       90,
	}, "key-tenant-a")

	req := httptest.NewRequest("GET", "/v1/audit/round-audit-test", nil)
	req.Header.Set("X-Api-Key", "key-tenant-a")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)
	entries, _ := resp["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
}

// --- Audit chain integrity after multiple requests ---

func TestGenerateAuditChainIntegrity(t *testing.T) {
	s := newTestServer(t)

	for i := 0; i < 5; i++ {
		rr := doRequest(t, s, "POST", "/v1/generate", map[string]any{
			"tenant_id": "tenant-a",
			"game_id":   "bingo-90",
			"round_id":  "round-chain",
			"count":     1,
			"min":       1,
			"max":       90,
		}, "key-tenant-a")
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d", i, rr.Code)
		}
	}

	// Verify chain integrity via in-memory store.
	memStore, ok := s.store.(*audit.InMemoryStore)
	if !ok {
		t.Skip("store is not InMemoryStore")
	}
	ok2, err := memStore.VerifyChain(nil, "tenant-a")
	if err != nil || !ok2 {
		t.Fatalf("chain integrity check failed: %v, ok=%v", err, ok2)
	}
}
