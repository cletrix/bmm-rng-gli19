# rng-service

Serviço de geração de números aleatórios criptograficamente seguros (CSPRNG) para iGaming, desenvolvido pela **Lucky & Fun** para certificação pela **BMM Testlabs Brasil**.

O serviço alimenta jogos próprios (Bingo, VLT) via gRPC e pode ser licenciado como SaaS B2B via REST. Todo output é auditável, rastreável por rodada e verificável offline por reguladores.

---

## Algoritmo

**AES-256-CTR DRBG** — NIST SP 800-90A Rev.1, Seção 10.2.1 (sem derivation function).

| Parâmetro | Valor |
|---|---|
| Função de bloco | AES-256 |
| Tamanho do seed | 384 bits (48 bytes = chave 256 bits + contador 128 bits) |
| Resistência à segurança | 256 bits |
| Limite de reseed | 1.000.000 outputs ou 3.600 segundos |
| Forward secrecy | `CTR_DRBG_Update(nil)` após cada `Generate` |

A escolha do AES-256-CTR DRBG é deliberada: é o algoritmo com maior histórico de aprovação em corpos de certificação de iGaming. ChaCha20-DRBG seria uma alternativa aceitável tecnicamente, porém com menor precedente regulatório no Brasil.

**O que não usar em iGaming:**
- `math/rand` — não é CSPRNG
- Mersenne Twister — previsível após 624 outputs [3]
- `% max` para mapear range — introduz viés estatístico [4]
- `time.Now().UnixNano()` como seed — previsível por timing

---

## Arquitetura

```
Cliente (Bingo/VLT via gRPC | Operador B2B via REST)
  └─→ API Gateway          mTLS · JWT HS256 · API Key · rate limit por tenant
        └─→ Core RNG
              ├── Entropy Pool    getrandom(2) [primária] + /dev/hwrng [XOR]
              ├── CSPRNG          AES-256-CTR DRBG (NIST SP 800-90A Rev.1)
              └── Scaling         rejection sampling · Fisher-Yates shuffle
        └─→ Auditoria
              ├── Hash chain      SHA-256 encadeado por output
              ├── Assinatura      HMAC-SHA-256 por batch, chave por tenant
              └── Persistência    PostgreSQL append-only, retenção 5 anos
        └─→ Health
              ├── Tamper detect   SHA-256 do executável a cada 5 minutos
              ├── Self-test NIST  Frequency + Runs + BlockFreq em loop (1 h)
              └── Métricas        Prometheus — porta 9090
```

### Pacotes

| Pacote | Responsabilidade |
|---|---|
| `internal/entropy` | `getrandom(2)` + HWRNG opcional; política de reseed |
| `internal/csprng` | AES-256-CTR DRBG; estado interno nunca exposto |
| `internal/scaling` | Rejection sampling, Fisher-Yates, `RandFloat64` |
| `internal/audit` | Hash chain SHA-256, HMAC-SHA-256, store PostgreSQL |
| `internal/gateway` | Handlers REST, middleware auth/rate-limit/tenant |
| `internal/health` | Tamper detection, self-test NIST, métricas Prometheus |
| `internal/config` | Configuração via variáveis de ambiente |

---

## Endpoints REST

| Método | Path | Descrição |
|---|---|---|
| `POST` | `/v1/generate` | Gerar N números em `[min, max]` |
| `POST` | `/v1/generate/batch` | Múltiplos sorteios em um request |
| `POST` | `/v1/generate/shuffle` | Embaralhar conjunto (bingo: 1–90) |
| `GET` | `/v1/health` | Status + hash do binário + p-values NIST |
| `GET` | `/v1/stats` | Distribuição + p-values recentes por tenant |
| `GET` | `/v1/audit/{round_id}` | Trilha auditável de uma rodada |

Autenticação obrigatória em todos os endpoints: `Authorization: Bearer <JWT>` ou `X-Api-Key: <key>`.

---

## Comandos

```bash
# Testes com race detector (obrigatório)
go test -race ./...

# Build com hash embutido para tamper detection
make build-release

# Teste estatístico rápido — 1 milhão de bits (desenvolvimento)
make test-nist-quick

# Suíte completa — 1 bilhão de bits (servidor Linux + STS 2.1.2 + dieharder)
make test-nist-billion

# Montar pacote de submissão BMM (após test-nist-billion)
make bmm-package

# Rodar testes de integração (requer PostgreSQL)
make db-up
make test-integration

# Stream contínuo para análise externa
make dump-diehard        # ./bin/rng-service dump | dieharder -a -g 200

# Verificar entropia disponível no sistema (produção: deve ser > 1000)
cat /proc/sys/kernel/random/entropy_avail
```

---

## Variáveis de Ambiente

| Variável | Padrão | Descrição |
|---|---|---|
| `RNG_PORT_REST` | `8080` | Porta da API REST |
| `RNG_PORT_GRPC` | `8081` | Porta gRPC |
| `RNG_METRICS_PORT` | `9090` | Porta Prometheus |
| `RNG_JWT_SECRET` | — | Secret HMAC para tokens JWT |
| `RNG_API_KEYS` | — | `"key1:tenant-a,key2:tenant-b"` |
| `RNG_RATE_LIMIT_RPS` | `100` | Rate limit por tenant (req/s) |
| `RNG_RESEED_INTERVAL_OUTPUTS` | `1000000` | Re-seed a cada N outputs |
| `RNG_RESEED_INTERVAL_SECONDS` | `3600` | Re-seed a cada N segundos |
| `RNG_HWRNG_PATH` | — | Path para `/dev/hwrng` (opcional) |
| `RNG_SIGNING_KEY` | — | Chave HMAC de assinatura (mín. 32 bytes) |
| `DATABASE_URL` | — | PostgreSQL connection string |
| `RNG_SELFTEST_INTERVAL_SECONDS` | `3600` | Frequência do self-test NIST |
| `RNG_SELFTEST_SAMPLE_SIZE` | `10000` | Bits por rodada de self-test |
| `RNG_ALGORITHM` | `aes-256-ctr-drbg` | Algoritmo (futuro: `chacha20`) |

Em produção, `RNG_JWT_SECRET` e `RNG_SIGNING_KEY` devem ser montados como volumes de segredo (Docker secrets / Kubernetes secrets), não como variáveis de ambiente.

---

## Auditoria e Rastreabilidade

Cada output produz um registro imutável com:

- **`request_id`** — UUID v4 aleatório (identificador único do request)
- **`entry_hash`** — `SHA-256(prev_hash || timestamp || tenant || round || values || signature)`
- **`prev_hash`** — hash da entrada anterior (encadeamento)
- **`signature`** — `HMAC-SHA-256(key_tenant, tenant || round || timestamp || values)`

O hash chain permite que qualquer auditor verifique offline que nenhum registro foi inserido, removido ou modificado retroativamente. A assinatura HMAC prova que os valores vieram do sistema certificado e não foram alterados.

A tabela PostgreSQL `rng_audit_log` tem trigger de imutabilidade que bloqueia `UPDATE` e `DELETE`.

---

## Testes Estatísticos

O serviço implementa dois níveis de verificação estatística:

**1. Self-test contínuo em produção** (`internal/health/nist_selftest.go`):
- Executado a cada hora (configurável)
- 3 testes NIST SP 800-22: Frequency, Block Frequency, Runs
- Alertas: `p-value < 0.001` → CRITICAL (parar geração); `< 0.01` → WARNING; `> 0.999` → WARNING

**2. Suíte completa para certificação** (`tests/nist/run_billion.sh`):
- 15 testes NIST SP 800-22 Rev.1a sobre 1 bilhão de bits
- Dieharder (~100 testes adicionais)
- Critério de aceite BMM: `p-value ≥ 0.01` em todos os 15 testes NIST

---

## Dependências Externas

| Dependência | Uso | Versão |
|---|---|---|
| `github.com/lib/pq` | Driver PostgreSQL | v1.10.9 |
| `github.com/prometheus/client_golang` | Métricas Prometheus | v1.23.2 |

O núcleo criptográfico usa **exclusivamente a biblioteca padrão do Go** (`crypto/aes`, `crypto/hmac`, `crypto/sha256`, `crypto/rand`). Nenhuma biblioteca criptográfica de terceiros é usada para o DRBG.

---

## Pacote de Submissão BMM

A documentação técnica para certificação está em `docs/bmm-submission-package/`:

| Documento | Conteúdo |
|---|---|
| `01-design-document.md` | Arquitetura, decisões de design, gatilhos de re-certificação |
| `02-algorithm-specification.md` | Pseudocódigo completo do CTR_DRBG_Update, Generate, Reseed |
| `03-entropy-sources.md` | `getrandom(2)`, HWRNG, política de reseed |
| `04-statistical-testing.md` | Metodologia NIST + Diehard, tabela de resultados |
| `05-security-controls.md` | Auth, rate limit, tamper detection, gerenciamento de segredos |
| `06-audit-trail.md` | Hash chain, HMAC, schema PostgreSQL, fluxo por request |
| `07-compliance-checklist.md` | Autoavaliação com itens pendentes para submissão |

---

## Referências

### Padrões e Normas

**[1]** NIST SP 800-90A Rev.1 — *Recommendation for Random Number Generation Using Deterministic Random Bit Generators* (junho de 2015).  
Especifica o CTR_DRBG implementado neste serviço.  
https://doi.org/10.6028/NIST.SP.800-90Ar1

**[2]** NIST SP 800-22 Rev.1a — *A Statistical Test Suite for Random and Pseudorandom Number Generators for Cryptographic Applications* (abril de 2010).  
Define os 15 testes estatísticos usados na certificação.  
https://doi.org/10.6028/NIST.SP.800-22r1a

**[3]** NIST SP 800-90B — *Recommendation for the Entropy Sources Used for Random Bit Generation* (janeiro de 2018).  
Base para avaliação de qualidade das fontes de entropia (`getrandom`, HWRNG).  
https://doi.org/10.6028/NIST.SP.800-90B

### Algoritmos

**[4]** Matsumoto, M. & Nishimura, T. — *Mersenne Twister: A 623-dimensionally equidistributed uniform pseudo-random number generator* (1998).  
ACM Transactions on Modeling and Computer Simulation, 8(1), 3–30.  
Referência de por que o MT **não deve** ser usado em iGaming: o estado interno é completamente reconstruível após 624 outputs observados.  
https://doi.org/10.1145/272991.272995

**[5]** Lemire, D. — *Fast Random Integer Generation in an Interval* (2019).  
ACM Transactions on Modeling and Computer Simulation, 29(1).  
Descreve o viés de módulo e a solução por rejection sampling — base do `scaling.RandRange`.  
https://doi.org/10.1145/3230636

**[6]** Knuth, D. E. — *The Art of Computer Programming, Vol. 2: Seminumerical Algorithms*, 3ª ed. (1997), §3.4.2.  
Algoritmo de Fisher-Yates para permutações uniformes sem viés — base do `scaling.Shuffle`.

**[7]** Ferguson, N., Schneier, B. & Kohno, T. — *Cryptography Engineering* (2010), Capítulo 9.  
Discussão sobre forward secrecy em DRBGs e o papel da função de update pós-geração.

### Ferramentas de Teste

**[8]** Brown, R. G. — *Dieharder: A Random Number Test Suite* (versão 3.31.1).  
Extensão da suíte Diehard de Marsaglia; usada para testes complementares ao NIST STS.  
https://webhome.phy.duke.edu/~rgb/General/dieharder.php

**[9]** NIST Statistical Test Suite (STS) versão 2.1.2.  
Implementação de referência dos 15 testes do NIST SP 800-22.  
https://csrc.nist.gov/projects/random-bit-generation/documentation-and-software

### Implementação Go

**[10]** Go standard library — `crypto/aes` (AES-NI acelerado em x86-64).  
https://pkg.go.dev/crypto/aes

**[11]** Loukides, M. et al. — Linux `getrandom(2)` man page.  
Documenta o comportamento de bloqueio, flags e garantias de entropia do kernel.  
https://man7.org/linux/man-pages/man2/getrandom.2.html

---

## Licença

Proprietário — Lucky & Fun. Todos os direitos reservados.  
Distribuição restrita: uso interno e submissão à BMM Testlabs Brasil.
