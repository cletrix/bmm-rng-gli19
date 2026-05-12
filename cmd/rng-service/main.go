package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/lib/pq"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/lucky-and-fun/rng-service/internal/audit"
	"github.com/lucky-and-fun/rng-service/internal/config"
	"github.com/lucky-and-fun/rng-service/internal/csprng"
	"github.com/lucky-and-fun/rng-service/internal/entropy"
	"github.com/lucky-and-fun/rng-service/internal/gateway"
	"github.com/lucky-and-fun/rng-service/internal/health"
)

// BinaryHash is injected at build time:
//
//	go build -ldflags="-X main.BinaryHash=$(sha256sum ./bin/rng-service | cut -d' ' -f1)"
var BinaryHash = "dev-build"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <command> [flags]\n\nCommands:\n  serve\n  dump\n", os.Args[0])
		os.Exit(1)
	}
	switch os.Args[1] {
	case "serve":
		runServe()
	case "dump":
		runDump(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}

func runServe() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	cfg.BinaryHash = BinaryHash

	// ── Tamper detection ──────────────────────────────────────────────────────
	checker, err := health.New(BinaryHash)
	if err != nil {
		// Tamper detected at startup — refuse to start.
		log.Fatalf("CRITICAL: %v", err)
	}
	log.Printf("startup binary hash: %s", checker.StartupHash())

	// ── Prometheus metrics (isolated registry — no default /metrics pollution) ─
	reg := prometheus.NewRegistry()
	metrics := health.NewMetrics(reg)
	metrics.RecordReseed("startup")

	// ── Entropy pool + CSPRNG ─────────────────────────────────────────────────
	pool := entropy.New(cfg.HWRNGPath)
	seed, _, err := pool.CollectForReseed(csprng.SeedLen, "system", 0)
	if err != nil {
		log.Fatalf("entropy: %v", err)
	}
	drbg, err := csprng.New(seed)
	if err != nil {
		log.Fatalf("csprng: %v", err)
	}

	// ── Audit chain + store ───────────────────────────────────────────────────
	chain := audit.NewChain()
	var store audit.Store
	if cfg.DB.URL != "" {
		log.Printf("DATABASE_URL set — PostgreSQL store ready (Sprint 4 TODO: load last hash)")
	}
	if store == nil {
		store = audit.NewInMemoryStore()
		log.Printf("WARN: using in-memory audit store — data will be lost on restart")
	}

	keys, err := audit.NewStaticKeyStore(map[string][]byte{"*": signingKeyFromEnv()})
	if err != nil {
		log.Fatalf("keystore: %v", err)
	}

	// ── NIST self-tester ──────────────────────────────────────────────────────
	selfTester := health.NewSelfTester(drbg, cfg.SelfTest.SampleSize)

	// ── REST gateway ──────────────────────────────────────────────────────────
	srv := gateway.NewServer(drbg, pool, chain, store, keys, cfg, checker, selfTester, metrics)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// ── Background: NIST self-tests ───────────────────────────────────────────
	selfTester.Start(ctx, cfg.SelfTest.IntervalSeconds)

	// ── Background: tamper detection every 5 minutes ──────────────────────────
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := checker.Verify(); err != nil {
					log.Printf("CRITICAL: %v", err)
					metrics.SetTamperDetected(true)
					// Sprint 4+: pause generation, alert ops
				} else {
					metrics.SetTamperDetected(false)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// ── Background: update NIST metrics ──────────────────────────────────────
	go func() {
		ticker := time.NewTicker(cfg.SelfTest.IntervalSeconds)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				results, lastRun := selfTester.Results()
				if results != nil {
					metrics.UpdateNIST(results)
					metrics.SelfTestLastRunTimestamp.Set(float64(lastRun.Unix()))
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// ── REST server ───────────────────────────────────────────────────────────
	restSrv := &http.Server{
		Addr:         ":" + cfg.Port.REST,
		Handler:      srv.Handler(),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	go func() {
		log.Printf("REST listening on :%s", cfg.Port.REST)
		if err := restSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("REST server: %v", err)
		}
	}()

	// ── Metrics server (internal — not exposed to B2B clients) ────────────────
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	metricsSrv := &http.Server{
		Addr:        ":" + cfg.Port.Metrics,
		Handler:     metricsMux,
		ReadTimeout: 5 * time.Second,
	}
	go func() {
		log.Printf("metrics listening on :%s/metrics", cfg.Port.Metrics)
		if err := metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("metrics server: %v", err)
		}
	}()

	// ── Graceful shutdown ─────────────────────────────────────────────────────
	<-ctx.Done()
	log.Println("shutting down...")
	shutCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = restSrv.Shutdown(shutCtx)
	_ = metricsSrv.Shutdown(shutCtx)
}

func signingKeyFromEnv() []byte {
	raw := os.Getenv("RNG_SIGNING_KEY")
	if len(raw) >= 32 {
		return []byte(raw)
	}
	log.Printf("WARN: RNG_SIGNING_KEY not set — using insecure dev key")
	key := make([]byte, 32)
	copy(key, []byte("dev-signing-key-not-for-prod!!!"))
	return key
}

func runDump(args []string) {
	fs := flag.NewFlagSet("dump", flag.ExitOnError)
	nBytes := fs.Uint64("bytes", 10*1024*1024, "bytes to write; 0 = unlimited")
	_ = fs.Parse(args)

	pool := entropy.New(os.Getenv("RNG_HWRNG_PATH"))
	seed, _, err := pool.CollectForReseed(csprng.SeedLen, "dump", 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "entropy: %v\n", err)
		os.Exit(1)
	}
	d, err := csprng.New(seed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "csprng: %v\n", err)
		os.Exit(1)
	}

	const chunk = 64 * 1024
	unlimited := *nBytes == 0
	written := uint64(0)
	for unlimited || written < *nBytes {
		n := uint64(chunk)
		if !unlimited && written+n > *nBytes {
			n = *nBytes - written
		}
		b, err := d.Generate(n)
		if err != nil {
			fmt.Fprintf(os.Stderr, "generate: %v\n", err)
			os.Exit(1)
		}
		if _, err := os.Stdout.Write(b); err != nil {
			return
		}
		written += n
	}
}
