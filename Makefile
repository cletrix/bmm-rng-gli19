BINARY := ./bin/rng-service

.PHONY: build build-release test test-race test-integration clean \
        dump-nist dump-diehard \
        test-nist-quick test-nist-billion \
        bmm-package \
        db-up db-down db-migrate

build:
	go build -o $(BINARY) ./cmd/rng-service

# Embeds the binary's own SHA256 hash for tamper detection (Sprint 4).
build-release: build
	@HASH=$$(sha256sum $(BINARY) | cut -d' ' -f1); \
	go build -ldflags="-X main.BinaryHash=$$HASH" -o $(BINARY) ./cmd/rng-service
	@echo "Built $(BINARY) with embedded hash"

test:
	go test ./...

test-race:
	go test -race ./...

clean:
	rm -f $(BINARY)

# Generate 1M bits (125 KB) for a quick NIST STS run.
dump-nist: build
	$(BINARY) dump --bytes 125000 > /tmp/rng_nist_input.bin
	@echo "Wrote 125000 bytes to /tmp/rng_nist_input.bin"
	@echo "Run: ./tests/nist/run_nist.sh"

# Stream to dieharder. Requires: apt install dieharder
dump-diehard: build
	$(BINARY) dump --bytes 0 | dieharder -a -g 200

# Integration tests (require PostgreSQL). Set TEST_DATABASE_URL before running.
test-integration:
	TEST_DATABASE_URL="postgres://rng:rng@localhost:5432/rng_audit?sslmode=disable" \
	go test -tags integration ./internal/audit/ -v

# Local PostgreSQL via Docker Compose
db-up:
	docker compose -f deploy/docker-compose.yml up -d --wait

db-down:
	docker compose -f deploy/docker-compose.yml down

db-migrate:
	psql "$$DATABASE_URL" -f deploy/schema.sql

# ── Sprint 5: testes estatísticos completos ───────────────────────────────────

# Teste rápido NIST (1 milhão de bits) — desenvolvimento / CI
test-nist-quick: build
	BITS=1000000 ./tests/nist/run_nist.sh

# Suíte completa: 1 bilhão de bits, NIST STS + Dieharder
# Requer: sts-2.1.2 compilado em ./tests/nist/sts-2.1.2/assess + dieharder
test-nist-billion: build-release
	./tests/nist/run_billion.sh

# Monta o pacote de submissão BMM: copia resultados + documentação
# Executar APÓS test-nist-billion
bmm-package:
	@echo "==> Montando pacote de submissão BMM..."
	@mkdir -p docs/bmm-submission-package/test-results
	@if ls tests/nist/results/billion_* 2>/dev/null; then \
		cp -r tests/nist/results/billion_* docs/bmm-submission-package/test-results/; \
		echo "    Resultados copiados para docs/bmm-submission-package/test-results/"; \
	else \
		echo "    AVISO: nenhum resultado encontrado em tests/nist/results/billion_*"; \
		echo "           Execute: make test-nist-billion"; \
	fi
	@sha256sum $(BINARY) > docs/bmm-submission-package/test-results/binary_hash.txt 2>/dev/null || true
	@echo "==> Pacote pronto em: docs/bmm-submission-package/"
	@echo "    Arquivos:"
	@ls -lh docs/bmm-submission-package/
