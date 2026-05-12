# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Projeto

Serviço RNG (Random Number Generator) para iGaming da **Lucky & Fun**, projetado para certificação pela **BMM Testlabs Brasil**. O certificado BMM é um ativo regulatório — qualquer mudança de algoritmo, fonte de entropia ou ambiente de execução exige re-certificação.

Uso duplo: alimentar os jogos próprios (`landf_game_bingo`, VLT) via gRPC e licenciar como SaaS B2B via REST.

## Comandos

> O projeto ainda não tem código. Ao criar os arquivos iniciais, use os comandos abaixo.

```bash
# Rodar todos os testes
go test ./...

# Rodar testes com race detector (obrigatório para o CSPRNG)
go test -race ./...

# Rodar um único pacote
go test ./internal/csprng/...

# Build com hash do binário embutido (necessário para tamper detection)
HASH=$(sha256sum ./bin/rng-service | cut -d' ' -f1)
go build -ldflags="-X main.BinaryHash=${HASH}" -o ./bin/rng-service ./cmd/rng-service

# Testes estatísticos NIST SP 800-22 (requer sts-2.1.2 compilado)
./tests/nist/run_nist.sh

# Testes Diehard (requer dieharder instalado)
./bin/rng-service dump | dieharder -a -g 200

# Dev local com PostgreSQL
docker compose -f deploy/docker-compose.yml up

# Verificar entropia disponível no sistema (deve ser > 1000 em produção)
cat /proc/sys/kernel/random/entropy_avail
```

## Arquitetura

### Fluxo de dados

```
Cliente (Bingo/VLT via gRPC | Operador B2B via REST)
  └─→ API Gateway (mTLS · JWT · API Key · rate limit por tenant)
        └─→ Core RNG Engine
              ├─ Entropy Pool: getrandom() [primária] + /dev/hwrng [secundária]
              ├─ CSPRNG: AES-256-CTR DRBG (NIST SP 800-90A Rev.1)
              └─ Scaling: rejection sampling (sem viés) / Fisher-Yates shuffle
        └─→ Audit & Evidence Layer
              ├─ Hash chain por output (SHA256 encadeado com tenant_id)
              ├─ Output signing (HMAC-SHA256 por batch, chave por tenant)
              └─ Audit store PostgreSQL append-only (retenção 5 anos)
```

### Regras críticas de certificação BMM

**NÃO usar:**
- `math/rand` — não é CSPRNG
- Mersenne Twister / GLib GRand — explicitamente rejeitado pela BMM (previsível após ~624 outputs)
- `time.Now().UnixNano()` como seed — previsível
- `% max` para mapear range — introduz viés estatístico

**Usar:**
- `getrandom()` syscall (nunca `GRND_NONBLOCK` em produção)
- AES-256-CTR DRBG como algoritmo principal; ChaCha20 como alternativa
- Rejection sampling para mapear outputs a um range
- Re-seed obrigatório a cada 1.000.000 outputs ou 3600 segundos

### Multi-tenancy

Todo request carrega `tenant_id` obrigatório. Esse ID aparece em cada entrada do audit log, no hash chain, no HMAC e nas métricas Prometheus. É o que permite a BMM certificar o serviço sem re-certificar cada cliente B2B.

### Módulos (estrutura planejada em `internal/`)

| Pacote | Responsabilidade |
|---|---|
| `entropy/` | Coleta de entropia via `getrandom()` e HWRNG; política de re-seed |
| `csprng/` | AES-256-CTR DRBG core; estado interno nunca exposto via API |
| `scaling/` | Rejection sampling (`RandRange`), shuffle Fisher-Yates, `RandFloat64` |
| `audit/` | Hash chain, HMAC signing, persistência PostgreSQL append-only |
| `gateway/` | Handlers REST e gRPC, middleware de auth/rate-limit/tenant |
| `health/` | Tamper detection (SHA256 do binário em runtime), self-test NIST em background |
| `config/` | Configuração via env vars |

### Tamper detection

No startup, o serviço calcula `SHA256(/proc/self/exe)` e compara com a constante `BinaryHash` embutida em build time via `-ldflags`. A cada 5 minutos repete a verificação. Se divergir: pausar geração e alertar ops.

### Self-test NIST contínuo

A cada hora (configurável), o serviço roda Frequency + Runs + Block Frequency em amostra de 10.000 outputs. Alertas:
- `p-value < 0.001` → CRITICAL, pausar geração
- `p-value < 0.01` → WARNING
- `p-value > 0.999` → WARNING (outputs "bons demais" = suspeito)

### API REST — endpoints principais

- `POST /v1/generate` — gerar N números em [min, max]
- `POST /v1/generate/batch` — múltiplos sorteios em um request
- `POST /v1/generate/shuffle` — embaralhar conjunto (bingo: 1–90)
- `GET  /v1/health` — status + hash do binário em execução
- `GET  /v1/stats` — distribuição + p-values recentes por tenant
- `GET  /v1/audit/{round_id}` — trilha auditável de uma rodada

### Portas e variáveis de ambiente relevantes

```
RNG_PORT_REST=8080
RNG_PORT_GRPC=8081
RNG_METRICS_PORT=9090
RNG_RESEED_INTERVAL_OUTPUTS=1000000
RNG_RESEED_INTERVAL_SECONDS=3600
RNG_ALGORITHM=aes-256-ctr-drbg   # ou chacha20
DATABASE_URL=postgres://...
RNG_SIGNING_KEY_PATH=/run/secrets/signing_key   # nunca env var direta em produção
```

## Ordem de implementação (Sprints)

1. **Sprint 1** — `entropy/`, `csprng/`, `scaling/` + testes unitários + NIST SP 800-22 local. **Critério de aceite: todos os 15 testes NIST com p-value > 0.01.**
2. **Sprint 2** — `audit/` (hash chain + PostgreSQL)
3. **Sprint 3** — `gateway/` REST + gRPC + middleware
4. **Sprint 4** — `health/` tamper detection + self-test + Prometheus + Grafana
5. **Sprint 5** — Gerar 1 bilhão de samples, rodar NIST + Diehard completos, montar pacote de submissão à BMM Brasil (`docs/bmm-submission-package/`)
