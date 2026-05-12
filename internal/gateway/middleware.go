package gateway

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

type contextKey string

const tenantIDKey contextKey = "tenant_id"

// tenantFromContext extracts the tenant_id injected by authMiddleware.
func tenantFromContext(ctx context.Context) string {
	id, _ := ctx.Value(tenantIDKey).(string)
	return id
}

// authMiddleware authenticates requests via JWT Bearer token or X-API-Key header.
// On success, it injects the tenant_id into the request context.
func authMiddleware(jwtSecret string, apiKeys map[string]string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenantID, err := extractTenant(r, jwtSecret, apiKeys)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized: "+err.Error())
			return
		}
		ctx := context.WithValue(r.Context(), tenantIDKey, tenantID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// extractTenant tries JWT Bearer first, then X-API-Key.
func extractTenant(r *http.Request, jwtSecret string, apiKeys map[string]string) (string, error) {
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		token := strings.TrimPrefix(auth, "Bearer ")
		return validateJWT(token, jwtSecret)
	}
	if key := r.Header.Get("X-Api-Key"); key != "" {
		tenant, ok := apiKeys[key]
		if !ok {
			return "", errors.New("invalid API key")
		}
		return tenant, nil
	}
	return "", errors.New("missing Authorization header or X-Api-Key")
}

// validateJWT validates an HS256 JWT and returns the sub (tenant_id) claim.
// Uses only the standard library — no external JWT dependency.
func validateJWT(tokenStr, secret string) (string, error) {
	if secret == "" {
		return "", errors.New("JWT secret not configured")
	}
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return "", errors.New("malformed JWT")
	}

	// Verify HS256 signature.
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	expected := mac.Sum(nil)

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", fmt.Errorf("invalid JWT signature encoding: %w", err)
	}
	if !hmac.Equal(expected, sig) {
		return "", errors.New("invalid JWT signature")
	}

	// Decode payload.
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("invalid JWT payload encoding: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("invalid JWT payload: %w", err)
	}

	// Check expiry.
	if exp, ok := claims["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			return "", errors.New("JWT expired")
		}
	}

	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		return "", errors.New("JWT missing sub claim")
	}
	return sub, nil
}

// rateLimiter implements a per-tenant token bucket.
type rateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*tokenBucket
	rate     float64 // tokens added per second
	capacity float64
}

type tokenBucket struct {
	tokens   float64
	lastFill time.Time
}

func newRateLimiter(rps float64) *rateLimiter {
	return &rateLimiter{
		buckets:  make(map[string]*tokenBucket),
		rate:     rps,
		capacity: rps * 2, // burst = 2 seconds of requests
	}
}

func (rl *rateLimiter) allow(tenantID string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	b, ok := rl.buckets[tenantID]
	if !ok {
		b = &tokenBucket{tokens: rl.capacity, lastFill: time.Now()}
		rl.buckets[tenantID] = b
	}

	now := time.Now()
	elapsed := now.Sub(b.lastFill).Seconds()
	b.tokens = min(rl.capacity, b.tokens+elapsed*rl.rate)
	b.lastFill = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func rateLimitMiddleware(rl *rateLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenant := tenantFromContext(r.Context())
		if tenant == "" {
			// auth middleware should have already rejected this
			writeError(w, http.StatusUnauthorized, "missing tenant")
			return
		}
		if !rl.allow(tenant) {
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
