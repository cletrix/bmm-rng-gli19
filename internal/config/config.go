package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all runtime configuration loaded from environment variables.
type Config struct {
	Env  string // production | staging | development
	Port struct {
		REST    string
		GRPC    string
		Metrics string
	}
	BinaryHash string

	Reseed struct {
		IntervalOutputs uint64
		IntervalSeconds time.Duration
	}

	Algorithm string // aes-256-ctr-drbg | chacha20

	DB struct {
		URL            string
		RetentionYears int
	}

	SigningKeyPath string
	HWRNGPath     string

	TLS struct {
		CertPath string
		KeyPath  string
		CAPath   string
	}

	SelfTest struct {
		IntervalSeconds time.Duration
		SampleSize      uint64
	}

	// Auth: JWT secret and API keys loaded from env (dev only; use Vault in prod)
	JWTSecret string
	// APIKeys maps api_key → tenant_id
	APIKeys map[string]string
	// RateLimit requests per second per tenant
	RateLimitRPS float64
}

// Load reads configuration from environment variables.
// Missing required values are reported as errors.
func Load() (*Config, error) {
	c := &Config{}

	c.Env = getEnv("RNG_ENV", "development")
	c.Port.REST = getEnv("RNG_PORT_REST", "2080")
	c.Port.GRPC = getEnv("RNG_PORT_GRPC", "2081")
	c.Port.Metrics = getEnv("RNG_METRICS_PORT", "9090")
	c.BinaryHash = getEnv("RNG_BINARY_HASH", "dev-build")
	c.HWRNGPath = getEnv("RNG_HWRNG_PATH", "")
	c.Algorithm = getEnv("RNG_ALGORITHM", "aes-256-ctr-drbg")
	c.SigningKeyPath = getEnv("RNG_SIGNING_KEY_PATH", "")
	c.TLS.CertPath = getEnv("RNG_TLS_CERT_PATH", "")
	c.TLS.KeyPath = getEnv("RNG_TLS_KEY_PATH", "")
	c.TLS.CAPath = getEnv("RNG_TLS_CA_PATH", "")
	c.DB.URL = getEnv("DATABASE_URL", "")

	var err error

	n, err := strconv.ParseUint(getEnv("RNG_RESEED_INTERVAL_OUTPUTS", "1000000"), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("config: RNG_RESEED_INTERVAL_OUTPUTS: %w", err)
	}
	c.Reseed.IntervalOutputs = n

	secs, err := strconv.ParseInt(getEnv("RNG_RESEED_INTERVAL_SECONDS", "3600"), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("config: RNG_RESEED_INTERVAL_SECONDS: %w", err)
	}
	c.Reseed.IntervalSeconds = time.Duration(secs) * time.Second

	ret, err := strconv.Atoi(getEnv("RNG_AUDIT_RETENTION_YEARS", "5"))
	if err != nil {
		return nil, fmt.Errorf("config: RNG_AUDIT_RETENTION_YEARS: %w", err)
	}
	c.DB.RetentionYears = ret

	stSecs, err := strconv.ParseInt(getEnv("RNG_SELFTEST_INTERVAL_SECONDS", "3600"), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("config: RNG_SELFTEST_INTERVAL_SECONDS: %w", err)
	}
	c.SelfTest.IntervalSeconds = time.Duration(stSecs) * time.Second

	stSample, err := strconv.ParseUint(getEnv("RNG_SELFTEST_SAMPLE_SIZE", "10000"), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("config: RNG_SELFTEST_SAMPLE_SIZE: %w", err)
	}
	c.SelfTest.SampleSize = stSample

	rps, err := strconv.ParseFloat(getEnv("RNG_RATE_LIMIT_RPS", "100"), 64)
	if err != nil {
		return nil, fmt.Errorf("config: RNG_RATE_LIMIT_RPS: %w", err)
	}
	c.RateLimitRPS = rps

	c.JWTSecret = getEnv("RNG_JWT_SECRET", "")

	// API keys: RNG_API_KEYS="key1:tenant-a,key2:tenant-b"
	c.APIKeys = parseAPIKeys(getEnv("RNG_API_KEYS", ""))

	return c, nil
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func parseAPIKeys(raw string) map[string]string {
	m := make(map[string]string)
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, ":", 2)
		if len(parts) == 2 {
			m[parts[0]] = parts[1]
		}
	}
	return m
}
