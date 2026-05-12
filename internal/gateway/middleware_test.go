package gateway

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// makeJWT creates a minimal HS256 JWT with the given sub and expiry offset.
func makeJWT(secret, sub string, expiresIn time.Duration) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

	expiry := time.Now().Add(expiresIn).Unix()
	payloadJSON, _ := json.Marshal(map[string]any{"sub": sub, "exp": expiry})
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(header + "." + payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return header + "." + payload + "." + sig
}

const testSecret = "super-secret-key-for-testing-only"

var testAPIKeys = map[string]string{
	"key-tenant-a": "tenant-a",
	"key-tenant-b": "tenant-b",
}

func echoTenantHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(tenantFromContext(r.Context())))
	})
}

func withAuth(h http.Handler) http.Handler {
	return authMiddleware(testSecret, testAPIKeys, h)
}

func TestAuthMiddleware_ValidJWT(t *testing.T) {
	token := makeJWT(testSecret, "tenant-x", time.Hour)
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	rr := httptest.NewRecorder()
	withAuth(echoTenantHandler()).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if rr.Body.String() != "tenant-x" {
		t.Fatalf("tenant = %q, want %q", rr.Body.String(), "tenant-x")
	}
}

func TestAuthMiddleware_ExpiredJWT(t *testing.T) {
	token := makeJWT(testSecret, "tenant-x", -time.Hour)
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	rr := httptest.NewRecorder()
	withAuth(echoTenantHandler()).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
}

func TestAuthMiddleware_InvalidSignature(t *testing.T) {
	token := makeJWT("wrong-secret", "tenant-x", time.Hour)
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	rr := httptest.NewRecorder()
	withAuth(echoTenantHandler()).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
}

func TestAuthMiddleware_ValidAPIKey(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Api-Key", "key-tenant-a")

	rr := httptest.NewRecorder()
	withAuth(echoTenantHandler()).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if rr.Body.String() != "tenant-a" {
		t.Fatalf("tenant = %q, want %q", rr.Body.String(), "tenant-a")
	}
}

func TestAuthMiddleware_InvalidAPIKey(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Api-Key", "not-a-real-key")

	rr := httptest.NewRecorder()
	withAuth(echoTenantHandler()).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
}

func TestAuthMiddleware_NoCredentials(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	withAuth(echoTenantHandler()).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
}

func TestAuthMiddleware_JWTPreferredOverAPIKey(t *testing.T) {
	token := makeJWT(testSecret, "jwt-tenant", time.Hour)
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Api-Key", "key-tenant-a") // would give "tenant-a"

	rr := httptest.NewRecorder()
	withAuth(echoTenantHandler()).ServeHTTP(rr, req)

	if rr.Body.String() != "jwt-tenant" {
		t.Fatalf("tenant = %q, want %q", rr.Body.String(), "jwt-tenant")
	}
}

// --- Rate limiter ---

func TestRateLimiter_Allow(t *testing.T) {
	rl := newRateLimiter(10) // 10 RPS, burst 20
	for i := 0; i < 20; i++ {
		if !rl.allow("tenant-a") {
			t.Fatalf("request %d should be allowed within burst capacity", i)
		}
	}
}

func TestRateLimiter_BlocksWhenExhausted(t *testing.T) {
	rl := newRateLimiter(1) // 1 RPS, burst 2
	rl.allow("t")
	rl.allow("t")
	if rl.allow("t") {
		t.Fatal("rate limiter should block after burst exhausted")
	}
}

func TestRateLimiter_IsolatedPerTenant(t *testing.T) {
	rl := newRateLimiter(1) // burst 2
	rl.allow("tenant-a")
	rl.allow("tenant-a")
	if !rl.allow("tenant-b") {
		t.Fatal("tenant-b should not be rate limited by tenant-a exhaustion")
	}
}

func TestRateLimitMiddleware_Blocks(t *testing.T) {
	rl := newRateLimiter(1) // burst 2
	rl.allow("tenant-a")
	rl.allow("tenant-a")

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := rateLimitMiddleware(rl, inner)

	req := httptest.NewRequest("GET", "/", nil)
	ctx := context.WithValue(req.Context(), tenantIDKey, "tenant-a")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rr.Code)
	}
}

// --- validateJWT ---

func TestValidateJWT_MissingSubClaim(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payloadJSON, _ := json.Marshal(map[string]any{"exp": time.Now().Add(time.Hour).Unix()})
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	mac := hmac.New(sha256.New, []byte(testSecret))
	mac.Write([]byte(header + "." + payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if _, err := validateJWT(header+"."+payload+"."+sig, testSecret); err == nil {
		t.Fatal("expected error for missing sub claim")
	}
}

func TestValidateJWT_MalformedToken(t *testing.T) {
	if _, err := validateJWT("only.two", testSecret); err == nil {
		t.Fatal("expected error for malformed JWT")
	}
}

func TestValidateJWT_EmptySecret(t *testing.T) {
	token := makeJWT(testSecret, "tenant-x", time.Hour)
	if _, err := validateJWT(token, ""); err == nil {
		t.Fatal("expected error for empty JWT secret")
	}
}
