# RNG Service — Contexto de Projeto para Claude Code

> **Como usar este arquivo**: Coloque-o na raiz do repositório. Ao iniciar qualquer sessão no
> Claude Code, mencione "leia o CONTEXT.md antes de começar". Ele contém todas as decisões
> de arquitetura, requisitos de certificação e restrições técnicas acordadas.

---

## 1. Visão geral do produto

### O que é

Um **serviço de geração de números aleatórios (RNG — Random Number Generator)** para iGaming,
projetado desde o início para ser certificado pela **BMM Testlabs** — o laboratório de
certificação de jogos mais antigo do mundo, com laboratório no Brasil e licenças em 5 estados
brasileiros (SP, RJ, PR, PB, MG).

### Objetivos de negócio

| Objetivo | Descrição |
|---|---|
| **Uso próprio** | Alimentar os jogos próprios: bingo (`landf_game_bingo`) e VLT (Video Lottery Terminal) da empresa Lucky & Fun |
| **SaaS B2B** | Licenciar o serviço para outros operadores iGaming no Brasil como produto independente com receita recorrente |
| **Certificação BMM** | Obter certificado formal da BMM Testlabs válido para operação regulada no Brasil |
| **Ativo regulatório** | O certificado é um ativo de barreira de entrada — poucos fornecedores brasileiros têm RNG próprio certificado |

### Empresa e contexto regulatório

- Empresa: Lucky & Fun (em processo de abertura no Brasil)
- CNAEs relevantes: 9200-3/99 (operação VLT), 6201-5/01 e 6201-5/02 (desenvolvimento de software)
- Mercado-alvo principal: iGaming regulado no Brasil (regulamentação federal em vigor desde jan/2025)
- Jurisdições secundárias: outros mercados Latino-Americanos onde a BMM já opera (Argentina, Peru)

---

## 2. Decisões de arquitetura

### Stack tecnológico

| Camada | Tecnologia escolhida | Justificativa |
|---|---|---|
| Linguagem core | **Go** (preferência) ou **Rust** | Ambos têm bindings maduros para OpenSSL/libsodium; Go tem ecossistema gRPC mais simples; Rust tem garantias de memória mais fortes |
| Protocolo externo | **REST (HTTP/2) + gRPC** | REST para clientes B2B (integração simples); gRPC para uso interno (bingo/VLT) com baixa latência e streaming |
| Autenticação | **mTLS + JWT + API Key por tenant** | mTLS para comunicação serviço-a-serviço; JWT para sessões; API Key para clientes B2B |
| Fonte de entropia | **`getrandom()` syscall Linux** como primária + **HWRNG** como secundária | `getrandom()` é aceito pela BMM; bloqueia até ter entropia suficiente; não usa `/dev/urandom` diretamente |
| Algoritmo CSPRNG | **AES-256-CTR DRBG** (NIST SP 800-90A) | Padrão NIST, aceito por todos os labs de certificação; determinístico dado seed, mas criptograficamente seguro |
| Algoritmo alternativo | **ChaCha20-based CSPRNG** | Fallback; mais rápido em hardware sem AES-NI; mesma segurança |
| Signing de outputs | **HMAC-SHA256** | Cada batch de outputs é assinado; permite auditoria pós-fato pela BMM |
| Audit store | **PostgreSQL append-only** ou **immudb** | Retenção mínima 5 anos; imutabilidade comprovável; hash chain verificável |
| Observabilidade | **Prometheus + Grafana** | Métricas de distribuição em tempo real; alertas de desvio estatístico |

### Por que AES-256-CTR DRBG e não Mersenne Twister (GLib `GRand`)

A GLib usa internamente Mersenne Twister (MT19937). Este algoritmo é **explicitamente rejeitado**
pela BMM e qualquer lab de certificação de iGaming pelos seguintes motivos:

1. **Não é criptograficamente seguro (não-CSPRNG)**: após observar ~624 outputs consecutivos, um
   atacante consegue reconstruir o estado interno completo e prever todos os outputs futuros
2. **Previsibilidade**: tem período longo (2^19937-1) mas saídas são matematicamente previsíveis
3. **Sem proteção de estado**: o estado interno pode vazar via side-channel

O AES-256-CTR DRBG resolve todos esses pontos: o estado interno é protegido pela chave AES;
mesmo conhecendo todos os outputs anteriores, é computacionalmente inviável reconstruir o estado.

### Arquitetura em camadas

```
┌─────────────────────────────────────────────────────────┐
│                    CLIENTES                              │
│  Bingo/VLT (uso próprio)  │  Operadores B2B licenciados │
└──────────────┬────────────┴──────────┬──────────────────┘
               │                       │
               ▼                       ▼
┌─────────────────────────────────────────────────────────┐
│                  API GATEWAY                             │
│  mTLS · rate limit por tenant · JWT auth · API Key      │
│  REST endpoint · gRPC endpoint · versionamento          │
│  Audit log de cada request (tenant_id obrigatório)      │
└──────────────────────────┬──────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│               CORE RNG ENGINE                            │
│                                                         │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────┐ │
│  │ Entropy Pool│→ │    CSPRNG    │→ │Scaling/Mapping │ │
│  │getrandom()  │  │AES-256-CTR  │  │sem viés        │ │
│  │+ HWRNG      │  │DRBG          │  │distribuição    │ │
│  └─────────────┘  └──────────────┘  │uniforme        │ │
│                                     └────────────────┘ │
└──────────────────────────┬──────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│           AUDIT & EVIDENCE LAYER (exigido BMM)          │
│                                                         │
│  ┌──────────────┐ ┌──────────────┐ ┌─────────────────┐ │
│  │Immutable Log │ │Re-seed       │ │Output Signing   │ │
│  │hash chain    │ │Scheduler     │ │HMAC-SHA256      │ │
│  │por output    │ │periódico +   │ │por batch        │ │
│  │+ tenant_id   │ │evento        │ │verificável      │ │
│  └──────────────┘ └──────────────┘ └─────────────────┘ │
└──────────────────────────┬──────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│         OBSERVABILIDADE & HEALTH (revisão trimestral)   │
│  self-test NIST contínuo · alertas desvio estatístico   │
│  dashboard distribuição · hash do binário · tamper det. │
└──────────────────────────┬──────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│                   AUDIT STORE                           │
│  append-only · retenção mínima 5 anos · hash chain      │
└─────────────────────────────────────────────────────────┘
```

### Multi-tenancy — regra crítica para o modelo B2B

Cada request ao serviço RNG **obrigatoriamente** carrega um `tenant_id`. Esse ID aparece em:
- Cada entrada do audit log
- Cada hash do hash chain
- Cada output signed com HMAC
- Cada métrica de Prometheus

Isso é necessário porque a BMM certifica o **serviço**, não cada operador individual. A
separação por tenant no audit trail permite que a BMM valide o serviço sem re-certificar
cada cliente que contratar. É também um requisito de compliance para evitar que dados de
um operador vaze para outro.

---

## 3. Requisitos de certificação BMM

### O que a BMM testa

A BMM aplica três baterias de testes estatísticos em sequência:

#### 3.1 NIST SP 800-22 (15 testes + sub-testes)

| Teste | O que verifica |
|---|---|
| Frequency (Monobit) | Proporção de 0s e 1s deve ser ~50% |
| Block Frequency | Frequência de 1s em blocos de M bits |
| Runs | Sequências ininterruptas de 0s ou 1s |
| Longest Run of Ones | Maior sequência de 1s em blocos de 128 bits |
| Binary Matrix Rank | Rank de matrizes binárias (correlação entre bits) |
| Discrete Fourier Transform (Spectral) | Detecção de periodicidade |
| Non-overlapping Template Matching | Padrões específicos não devem se repetir demais |
| Overlapping Template Matching | Variante com janela deslizante |
| Maurer's Universal Statistical | Compressibilidade da sequência |
| Linear Complexity | Tamanho do menor LFSR que reproduz a sequência |
| Serial | Frequência de padrões de m bits |
| Approximate Entropy | Regularidade da sequência |
| Cumulative Sums | Soma acumulada de ±1 deve ser próxima de zero |
| Random Excursions | Visitas a estados em passeios aleatórios |
| Random Excursions Variant | Variante com mais estados |

**Amostra mínima recomendada**: 1 bilhão de outputs antes de submeter à BMM.

#### 3.2 Testes Diehard (Marsaglia, 1995)

| Teste | O que verifica |
|---|---|
| Birthday Spacings | Distribuição de espaçamentos entre "aniversários" |
| Overlapping Permutations | Padrões em permutações sobrepostas |
| Ranks of Matrices | Ranks de matrizes 6×8 e 31×31 |
| Monkey Tests | Palavras formadas por sequências de bits |
| Count the 1s | Contagem de bits 1 em bytes e streams |
| Parking Lot | Simulação de carros estacionando aleatoriamente |
| Minimum Distance | Distância mínima entre pontos aleatórios |
| Random Spheres | Raio de esferas aleatórias |
| Squeeze | Convergência de divisões sucessivas |
| Overlapping Sums | Soma de floats sobrepostos |
| Runs | Ascendentes e descendentes |
| Craps | Simulação do jogo de dados |

#### 3.3 Testes Empíricos de Knuth (Art of Computer Programming, Vol. 2)

| Teste | O que verifica |
|---|---|
| Frequency | Contagem de cada número no sample |
| Serial | Pares de números consecutivos (grupos de 2) |
| Gap | Tamanho dos gaps entre ocorrências do mesmo número |
| Poker | Número de valores únicos em grupos de 5 |
| Coupon Collector | Quantos draws para completar todos os valores |
| Permutation | Padrões de ordenação em grupos |
| Run | Sequências ascendentes e descendentes |
| Maximum of t | Distribuição do máximo em grupos |

#### 3.4 Auditoria operacional (Fase 4 do processo)

Além dos testes estatísticos, a BMM audita:

- **Build pipeline**: reprodutível, assinado digitalmente, hash SHA256 do binário em produção
  deve coincidir com o submetido
- **Custódia de chaves**: chaves do HMAC e seed master devem estar em HSM (Hardware Security
  Module) ou solução equivalente (ex: AWS KMS, HashiCorp Vault com HSM backend); acesso
  restrito e auditado
- **Tamper detection**: o serviço deve verificar a própria integridade em runtime (hash do
  binário em execução vs hash registrado)
- **Isolamento**: o processo RNG deve rodar isolado; o estado interno do CSPRNG não pode ser
  acessível por outros processos ou via API
- **Ambiente de execução**: SO, versão do kernel, bibliotecas criptográficas (OpenSSL/libsodium)
  devem estar documentados e fixos — qualquer mudança requer re-certificação

### Processo BMM em fases e prazos

```
Fase 1: Pré-compliance (semanas 1–8)
├── Implementar core RNG com AES-256-CTR DRBG
├── Rodar NIST SP 800-22 localmente (tool: sts-2.1.2)
├── Rodar Diehard localmente (tool: dieharder)
├── Gerar e validar 1 bilhão de samples
├── Montar documentação técnica completa
└── Entregável: pacote de pré-submissão

Fase 2: Submissão formal à BMM Brasil (semanas 8–10)
├── Contato: bmm.com/bmm-brazil-hub (escritório São Paulo)
├── Enviar: código-fonte ou binário assinado + docs + SLA de acesso
├── Assinar: Certification Agreement com a BMM
└── Entregável: protocolo de submissão

Fase 3: Testes estatísticos BMM (semanas 10–16)
├── BMM roda suas próprias baterias (NIST + Diehard + Knuth)
├── BMM pode solicitar acesso direto ao serviço para testes ao vivo
├── Se falhar: BMM informa não-conformidades → corrigir → re-submeter
└── Entregável: relatório de testes (pass/fail com p-values)

Fase 4: Auditoria operacional (semanas 16–22)
├── BMM audita build pipeline, custódia de chaves, tamper detection
├── BMM verifica ambiente de execução (OS, libs, configuração)
├── BMM pode solicitar pentest ou auditoria de segurança adicional
└── Entregável: relatório de auditoria operacional

Fase 5: Emissão do certificado (semana 22+)
├── PCCC (comitê de certificação BMM) vota pela emissão
├── Certificado emitido com escopo: produto/versão/jurisdição
├── Certificado disponível no portal BMM para verificação de terceiros
└── Manutenção: revisão trimestral com self-test logs + relatório distribuição
```

### Gatilhos de re-certificação obrigatória

Qualquer um dos eventos abaixo exige novo processo de submissão:
- Mudança de algoritmo CSPRNG
- Troca da fonte de entropia (ex: adicionar HWRNG externo)
- Atualização do OS ou versão do kernel em produção
- Mudança de versão da biblioteca criptográfica (OpenSSL, libsodium)
- Expansão para nova jurisdição regulatória
- Mudança no mecanismo de scaling/mapping de outputs
- Qualquer alteração no código do módulo de geração

---

## 4. Especificação técnica detalhada dos módulos

### 4.1 Entropy Pool

```
Responsabilidade: coletar entropia de alta qualidade para seeding do CSPRNG

Fontes (em ordem de prioridade):
1. getrandom(buf, size, 0) — syscall Linux, bloqueia até ter entropia suficiente
   - Nunca usar GRND_NONBLOCK em produção
   - Verificar errno == EINTR e retry em loop
2. /dev/hwrng — se disponível no hardware (VLT geralmente tem TPM)
3. Intel RDSEED / AMD RDSEED — instrução de hardware para entropia

Política de re-seeding:
- Re-seed obrigatório a cada N outputs (N configurável, padrão: 1.000.000)
- Re-seed obrigatório a cada T segundos (T configurável, padrão: 3600s = 1h)
- Re-seed obrigatório em eventos de segurança (restart do serviço, detecção de anomalia)
- Re-seed nunca pode usar outputs anteriores do próprio CSPRNG como entropia

O que logar por re-seed:
- timestamp UTC
- tenant_id (ou "system" para re-seeds automáticos)
- fonte de entropia usada
- hash SHA256 da nova seed (nunca a seed em si)
- contador de outputs desde o último re-seed
```

### 4.2 CSPRNG Core (AES-256-CTR DRBG)

```
Algoritmo: AES-256 em modo CTR como base do DRBG (Deterministic Random Bit Generator)
Padrão: NIST SP 800-90A Rev. 1

Parâmetros:
- Chave AES: 256 bits
- Nonce/counter: 128 bits, incrementado a cada bloco
- Tamanho do bloco de output: 16 bytes (128 bits) por operação AES
- Security strength: 256 bits

Estado interno (NUNCA exposto via API):
- key: [32]byte  — chave AES-256 atual
- v:   [16]byte  — counter/nonce atual

Operações:
- Generate(n uint64) []byte  — gera n bytes aleatórios
- Reseed(entropy []byte)     — atualiza key e v com nova entropia
- HealthCheck() error        — valida que o estado interno não está corrompido

Implementação de referência (Go):
  import "crypto/aes"
  import "golang.org/x/crypto/chacha20"  // alternativa ChaCha20

Bibliotecas aceitas pela BMM:
- OpenSSL >= 1.1.1 (EVP_RAND_CTX com RAND-CTR-DRBG)
- libsodium >= 1.0.18 (randombytes_buf usa ChaCha20)
- Go stdlib crypto/rand (usa getrandom() diretamente — ok para seeding, não para o DRBG)

NÃO usar:
- math/rand (Go) — não é CSPRNG
- rand.Intn() sem seed criptográfico — não é CSPRNG
- GLib GRand / Mersenne Twister — explicitamente rejeitado pela BMM
- time.Now().UnixNano() como seed — previsível
```

### 4.3 Scaling / Mapping

```
Responsabilidade: converter os bytes brutos do CSPRNG em números no range desejado
sem introduzir viés estatístico.

Problema do módulo simples:
  // ERRADO — introduz viés quando max não é potência de 2
  n := binary.BigEndian.Uint64(raw) % max

Solução correta — rejection sampling:
  func RandRange(max uint64) uint64 {
    // Calcula o maior múltiplo de max que cabe em uint64
    threshold := (math.MaxUint64 - max + 1) % max
    for {
      n := readUint64FromCSPRNG()
      if n >= threshold {
        return n % max
      }
      // Rejeita e tenta novamente — elimina viés
    }
  }

Para floats [0.0, 1.0):
  // Usa 53 bits (precisão de float64) dividido por 2^53
  func RandFloat64() float64 {
    n := readUint64FromCSPRNG() >> 11  // 53 bits
    return float64(n) / (1 << 53)
  }

Para baralhos (Fisher-Yates shuffle):
  func Shuffle(deck []int) {
    for i := len(deck) - 1; i > 0; i-- {
      j := RandRange(uint64(i + 1))
      deck[i], deck[j] = deck[j], deck[i]
    }
  }

Casos de uso específicos do bingo:
- Sorteio de bola (1–75 ou 1–90): RandRange(75) + 1
- Sorteio sem repetição: Shuffle de slice com todas as bolas
- Verificação de cartela: determinístico dado seed da rodada (não usa RNG)
```

### 4.4 API REST

```
Base URL: https://rng.landf.com.br/v1

Autenticação:
  Header: Authorization: Bearer <JWT>
  Header: X-API-Key: <tenant_api_key>
  TLS: mTLS com certificado de cliente para operadores B2B

Endpoints:

POST /generate
  Body: {
    "tenant_id": "string",         // obrigatório
    "game_id": "string",           // obrigatório — identifica o jogo
    "round_id": "string",          // obrigatório — identifica a rodada
    "count": 1,                    // quantidade de números
    "min": 1,                      // valor mínimo (inclusive)
    "max": 75,                     // valor máximo (inclusive)
    "seed_override": null          // null em produção; usado só em replay de auditoria
  }
  Response: {
    "request_id": "uuid",
    "tenant_id": "string",
    "game_id": "string",
    "round_id": "string",
    "values": [42],
    "timestamp_utc": "2025-01-01T00:00:00Z",
    "signature": "hmac-sha256-hex",
    "audit_hash": "sha256-hex"     // hash desta entrada no audit log
  }

POST /generate/batch
  Body: {
    "tenant_id": "string",
    "game_id": "string",
    "round_id": "string",
    "requests": [
      {"count": 90, "min": 1, "max": 90}  // sorteio completo de bingo
    ]
  }

POST /generate/shuffle
  Body: {
    "tenant_id": "string",
    "game_id": "string",
    "round_id": "string",
    "items": [1, 2, 3, ..., 75]   // baralho/conjunto a embaralhar
  }
  Response: {
    ...campos padrão...,
    "shuffled": [34, 12, 67, ...]
  }

GET /health
  Response: {
    "status": "ok" | "degraded" | "error",
    "entropy_pool": "ok" | "low",
    "csprng": "ok" | "error",
    "audit_store": "ok" | "error",
    "last_reseed_utc": "2025-01-01T00:00:00Z",
    "outputs_since_reseed": 12345,
    "binary_hash": "sha256-hex"    // hash do binário em execução
  }

GET /stats
  Response: {
    "tenant_id": "string",
    "period": "1h" | "24h" | "7d",
    "total_requests": 1000000,
    "distribution_chi_square_p_value": 0.4821,  // deve ser > 0.01
    "runs_test_p_value": 0.3214,
    "last_nist_selftest_utc": "..."
  }

GET /audit/{round_id}
  Description: retorna o audit trail de uma rodada específica para verificação
  Response: {
    "round_id": "string",
    "entries": [...],
    "hash_chain_valid": true,
    "signature_valid": true
  }
```

### 4.5 gRPC (uso interno — bingo/VLT)

```protobuf
syntax = "proto3";
package rng.v1;

service RNGService {
  rpc Generate(GenerateRequest) returns (GenerateResponse);
  rpc GenerateBatch(GenerateBatchRequest) returns (GenerateBatchResponse);
  rpc Shuffle(ShuffleRequest) returns (ShuffleResponse);
  rpc HealthCheck(HealthCheckRequest) returns (HealthCheckResponse);
  rpc StreamGenerate(GenerateRequest) returns (stream GenerateResponse);
}

message GenerateRequest {
  string tenant_id  = 1;
  string game_id    = 2;
  string round_id   = 3;
  uint32 count      = 4;
  uint64 min        = 5;
  uint64 max        = 6;
}

message GenerateResponse {
  string request_id   = 1;
  repeated uint64 values = 2;
  string timestamp_utc = 3;
  string signature    = 4;
  string audit_hash   = 5;
}
```

### 4.6 Audit & Evidence Layer

```
Objetivo: criar trilha de auditoria irrefutável que a BMM possa verificar

Hash chain (similar a blockchain simplificado):
  entry_n.hash = SHA256(
    entry_{n-1}.hash ||    // hash da entrada anterior
    entry_n.timestamp ||   // timestamp UTC nanoseconds
    entry_n.tenant_id ||   // tenant
    entry_n.round_id  ||   // rodada
    entry_n.values    ||   // outputs gerados
    entry_n.signature      // HMAC dos valores
  )

  A primeira entrada usa hash zero (64 zeros) como predecessor.

Output signing:
  signature = HMAC-SHA256(
    key   = signing_key_for_tenant,   // chave por tenant, rotacionada mensalmente
    data  = tenant_id || round_id || timestamp || values_bytes
  )

Schema do audit log (PostgreSQL):
  CREATE TABLE rng_audit_log (
    id              BIGSERIAL PRIMARY KEY,
    entry_hash      CHAR(64) NOT NULL UNIQUE,
    prev_hash       CHAR(64) NOT NULL,
    tenant_id       VARCHAR(64) NOT NULL,
    game_id         VARCHAR(128) NOT NULL,
    round_id        VARCHAR(128) NOT NULL,
    request_id      UUID NOT NULL,
    values_json     JSONB NOT NULL,
    value_count     INTEGER NOT NULL,
    min_value       BIGINT NOT NULL,
    max_value       BIGINT NOT NULL,
    signature       CHAR(64) NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reseed_event    BOOLEAN NOT NULL DEFAULT FALSE
  );
  -- Nunca permitir UPDATE ou DELETE nesta tabela
  -- Usar RLS (Row Level Security) para isolamento por tenant
  -- Índice por tenant_id + created_at para queries de auditoria

Retenção: mínimo 5 anos (exigência regulatória brasileira para iGaming)
```

### 4.7 Self-test NIST contínuo

```
O serviço deve rodar testes estatísticos continuamente em background:

Frequência: a cada hora (configurável)
Amostra: 10.000 outputs por execução (rápido, suficiente para detecção de falhas graves)
Testes mínimos em produção: Frequency, Runs, Block Frequency

Alertas:
- p-value < 0.001 em qualquer teste → alerta CRITICAL → pausar geração → notificar ops
- p-value < 0.01 em qualquer teste  → alerta WARNING → continuar mas notificar
- p-value entre 0.01 e 0.99        → normal
- p-value > 0.999 em qualquer teste → alerta WARNING (outputs "bons demais" = suspeito)

Métricas Prometheus expostas:
  rng_nist_frequency_p_value{tenant="all"}
  rng_nist_runs_p_value{tenant="all"}
  rng_outputs_total{tenant="xxx"}
  rng_reseeds_total{reason="scheduled|event|startup"}
  rng_binary_hash_matches{} 1.0  -- 0.0 se hash não bater = tamper detected
```

### 4.8 Tamper Detection

```
O serviço verifica a própria integridade em runtime:

Startup:
1. Calcular SHA256 do próprio binário em execução (/proc/self/exe)
2. Comparar com hash registrado em tempo de build (embutido como constante no binário
   e também registrado no audit store)
3. Se não bater: recusar inicialização, logar CRITICAL, alertar ops

Runtime (a cada 5 minutos):
1. Re-calcular hash do binário
2. Comparar com hash de startup
3. Se diferente: pausar geração, alertar ops CRITICAL

Build-time hash embedding (Go):
  var BinaryHash = "SHA256_PLACEHOLDER"  // substituído por ldflags no build
  // Makefile:
  //   HASH=$(sha256sum ./bin/rng-service | cut -d' ' -f1)
  //   go build -ldflags="-X main.BinaryHash=${HASH}" ...
```

---

## 5. Estrutura de diretórios do repositório

```
rng-service/
├── CONTEXT.md                    ← este arquivo
├── README.md
├── Makefile
├── go.mod
├── go.sum
│
├── cmd/
│   └── rng-service/
│       └── main.go               ← entry point
│
├── internal/
│   ├── entropy/
│   │   ├── pool.go               ← Entropy Pool (getrandom + hwrng)
│   │   └── pool_test.go
│   │
│   ├── csprng/
│   │   ├── aes_ctr_drbg.go       ← AES-256-CTR DRBG core
│   │   ├── aes_ctr_drbg_test.go
│   │   └── chacha20.go           ← alternativa ChaCha20
│   │
│   ├── scaling/
│   │   ├── range.go              ← rejection sampling, shuffle
│   │   └── range_test.go
│   │
│   ├── audit/
│   │   ├── log.go                ← hash chain + signing
│   │   ├── log_test.go
│   │   └── store_postgres.go     ← implementação PostgreSQL
│   │
│   ├── gateway/
│   │   ├── rest.go               ← REST handlers
│   │   ├── grpc.go               ← gRPC handlers
│   │   ├── middleware.go         ← auth, rate limit, tenant
│   │   └── middleware_test.go
│   │
│   ├── health/
│   │   ├── checker.go            ← health check + tamper detection
│   │   └── nist_selftest.go      ← testes NIST em background
│   │
│   └── config/
│       └── config.go             ← configuração via env vars
│
├── proto/
│   └── rng/v1/
│       └── rng.proto             ← definição gRPC
│
├── tests/
│   ├── nist/
│   │   ├── run_nist.sh           ← script para rodar sts-2.1.2 no output do serviço
│   │   └── run_diehard.sh        ← script para rodar dieharder
│   │
│   ├── integration/
│   │   └── api_test.go           ← testes de integração completos
│   │
│   └── bmm_submission/
│       ├── generate_samples.go   ← gera 1 bilhão de samples para submissão
│       └── README.md             ← instruções de submissão à BMM
│
├── deploy/
│   ├── Dockerfile
│   ├── docker-compose.yml        ← dev local com postgres
│   └── k8s/                     ← manifests Kubernetes
│
└── docs/
    ├── bmm-submission-package/   ← documentação para a BMM
    │   ├── algorithm-description.md
    │   ├── entropy-sources.md
    │   ├── security-architecture.md
    │   └── operational-controls.md
    └── api/
        └── openapi.yaml
```

---

## 6. Ordem de implementação recomendada

### Sprint 1 — Core certificável (prioridade máxima)

1. `internal/entropy/pool.go` — Entropy Pool com `getrandom()`
2. `internal/csprng/aes_ctr_drbg.go` — AES-256-CTR DRBG
3. `internal/scaling/range.go` — rejection sampling + shuffle
4. Testes unitários de cada módulo
5. `tests/nist/run_nist.sh` — rodar NIST SP 800-22 nos outputs

**Critério de aceite do Sprint 1**: todos os 15 testes NIST passam com p-value > 0.01

### Sprint 2 — Audit trail

1. `internal/audit/log.go` — hash chain + HMAC signing
2. `internal/audit/store_postgres.go` — persistência
3. Schema do banco de dados
4. Testes de integridade do hash chain

### Sprint 3 — API e gateway

1. `internal/gateway/rest.go` — endpoints REST
2. `internal/gateway/grpc.go` — endpoints gRPC
3. `internal/gateway/middleware.go` — auth + rate limit + tenant
4. Integração com bingo (`landf_game_bingo`)

### Sprint 4 — Observabilidade e hardening

1. `internal/health/checker.go` — tamper detection
2. `internal/health/nist_selftest.go` — self-test contínuo
3. Métricas Prometheus
4. Dashboard Grafana

### Sprint 5 — Pacote de submissão BMM

1. Gerar 1 bilhão de samples e rodar NIST + Diehard completos
2. Montar documentação técnica (`docs/bmm-submission-package/`)
3. Contato com BMM Brasil para iniciar Fase 2

---

## 7. Variáveis de ambiente

```bash
# Core
RNG_ENV=production                          # production | staging | development
RNG_PORT_REST=8080
RNG_PORT_GRPC=8081
RNG_BINARY_HASH=sha256_do_binario           # injetado em build time via ldflags

# Entropia
RNG_HWRNG_PATH=/dev/hwrng                  # opcional; deixar vazio se não disponível
RNG_RESEED_INTERVAL_OUTPUTS=1000000        # re-seed a cada N outputs
RNG_RESEED_INTERVAL_SECONDS=3600           # re-seed a cada N segundos

# CSPRNG
RNG_ALGORITHM=aes-256-ctr-drbg             # aes-256-ctr-drbg | chacha20

# Audit
DATABASE_URL=postgres://user:pass@host:5432/rng_audit
RNG_AUDIT_RETENTION_YEARS=5

# Chaves (em produção: usar Vault ou KMS, nunca env var direta)
RNG_SIGNING_KEY_PATH=/run/secrets/signing_key   # montado via Docker secret ou K8s secret

# Observabilidade
RNG_METRICS_PORT=9090
RNG_SELFTEST_INTERVAL_SECONDS=3600
RNG_SELFTEST_SAMPLE_SIZE=10000

# TLS
RNG_TLS_CERT_PATH=/certs/server.crt
RNG_TLS_KEY_PATH=/certs/server.key
RNG_TLS_CA_PATH=/certs/ca.crt              # para mTLS
```

---

## 8. Ferramentas externas necessárias para testes

```bash
# NIST SP 800-22 — Statistical Test Suite
# Download: https://csrc.nist.gov/projects/random-bit-generation
wget https://csrc.nist.gov/CSRC/media/Projects/Random-Bit-Generation/documents/sts-2.1.2.zip
# Compilar localmente; rodar contra dump binário de outputs do serviço

# Dieharder (suite Diehard modernizada)
sudo apt install dieharder
# Uso: ./bin/rng-service dump | dieharder -a -g 200

# TestU01 (opcional, mais completo)
# http://simul.iro.umontreal.ca/testu01/tu01.html

# go test com -race para detectar race conditions no CSPRNG
go test -race ./...

# Verificação de entropia disponível no sistema
cat /proc/sys/kernel/random/entropy_avail   # deve ser > 1000 em produção
```

---

## 9. Decisões pendentes / a definir

| Decisão | Opções | Impacto |
|---|---|---|
| Linguagem core | Go vs Rust | Rust: mais seguro contra bugs de memória; Go: ecossistema gRPC mais simples |
| HSM para chaves | AWS KMS vs HashiCorp Vault vs hardware HSM | Hardware HSM é mais aceito pela BMM mas caro; KMS é mais prático |
| Deploy inicial | Docker Compose vs Kubernetes | K8s para produção; Compose para dev/staging |
| Multi-região | Sim/Não no V1 | A BMM certifica por jurisdição; adicionar regiões = re-certificação |
| Rate limiting | por tenant / por IP / por round_id | Evitar abuso B2B; proteger contra enumeração de outputs |

---

## 10. Referências

- **BMM Brasil**: https://bmm.com/bmm-brazil-hub
- **NIST SP 800-90A** (DRBG): https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final
- **NIST SP 800-22** (testes estatísticos): https://csrc.nist.gov/publications/detail/sp/800-22/rev-1a/final
- **BMM Certification Scheme v2.5**: https://bmm.com/wp-content/uploads/2024/07/BMM-Testlabs-Certification-Scheme-v2.5.pdf
- **Dieharder**: https://webhome.phy.duke.edu/~rgb/General/dieharder.php
- **libsodium**: https://libsodium.gitbook.io/doc/
- **Go crypto/rand**: https://pkg.go.dev/crypto/rand
- **Projeto de jogo bingo**: github.com/lucky-and-fun/landf_game_bingo
