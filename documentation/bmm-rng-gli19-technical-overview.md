# bmm-rng-gli19 — Visão Técnica Completa

**Repositório**: github.com/cletrix/bmm-rng-gli19  
**Organização**: Lucky & Fun  
**Audiência**: Engenheiros com background em sistemas, criptografia aplicada e infraestrutura  
**Status atual**: Estrutura e documentação completas; implementação Go do core em andamento (Sprint 1)

---

## 1. Por que este projeto existe

O mercado brasileiro de iGaming foi regulamentado em janeiro de 2025. Qualquer operador de jogos
de azar eletrônico — bingos, VLTs (Video Lottery Terminals), cassinos online — precisa que seus
jogos sejam certificados por um laboratório independente acreditado. No Brasil, os principais
são a **BMM Testlabs** e a **GLI (Gaming Laboratories International)**.

O componente mais crítico de qualquer jogo de azar é o **RNG (Random Number Generator)**.
Sem aleatoriedade verificavelmente uniforme e imprevisível, o jogo é manipulável. Os labs
de certificação exigem que o RNG passe em baterias de testes estatísticos rigorosas antes
que qualquer jogo possa operar legalmente.

A Lucky & Fun tem dois produtos próprios que precisam de RNG certificado:

- `landf_game_bingo` — jogo de bingo em Haxe/OpenFL
- VLT — terminal físico de loteria de vídeo

Em vez de depender de um RNG embutido em uma plataforma terceira (o que significa depender
da certificação alheia e pagar royalties), a decisão foi construir e certificar um **serviço
próprio de RNG**. Um serviço certificado também pode ser licenciado para outros operadores
iGaming no Brasil, gerando receita B2B recorrente.

O nome `bmm-rng-gli19` referencia as duas normas de certificação alvo: BMM Testlabs e
GLI-19 (o padrão técnico específico da GLI para RNGs de iGaming).

---

## 2. O problema de aleatoriedade em iGaming

### 2.1 Por que `rand()` e Mersenne Twister não servem

```
Estado interno do MT19937: 624 palavras de 32 bits = 19.968 bits

Após observar 624 outputs consecutivos, o estado interno
é completamente reconstruível por inversão de matrizes.

    Output₁, Output₂, ..., Output₆₂₄
           ↓ (inversão do twist)
    Estado interno recuperado
           ↓
    Output₆₂₅, Output₆₂₆, ... todos previsíveis
```

Em um jogo de bingo online com 90 bolas, um atacante que registrar ~7 rodadas completas
consecutivas consegue reconstruir o estado do MT e prever todas as bolas seguintes.
Não é ataque teórico — existe implementação pública em menos de 200 linhas de Python.

A GLib (`GRand`, `g_random_int`) usa MT19937 internamente. A maioria das linguagens
(`rand()` em C, `Math.random()` em JavaScript pré-2015, `Random` em Java sem
`SecureRandom`) também. Todos explicitamente rejeitados pela BMM.

### 2.2 O que um CSPRNG garante

Um CSPRNG (Cryptographically Secure Pseudo-Random Number Generator) oferece:

- **Next-bit unpredictability**: conhecer todos os bits anteriores não ajuda a prever o próximo
  com probabilidade melhor que 50%
- **State compromise resistance**: mesmo que o estado interno vaze em um instante T, os outputs
  anteriores a T permanecem imprevisíveis (forward secrecy, se implementado com update pós-geração)
- **Statistical indistinguishability**: os outputs são computacionalmente indistinguíveis de
  ruído branco verdadeiro

O AES-256-CTR DRBG provê as três propriedades. A segurança reduz para a segurança do AES-256,
que tem resistência de 256 bits — computacionalmente intratável.

### 2.3 O problema do viés de módulo

```c
// ERRADO — viés estatístico
int bola = rand() % 90 + 1;

// Por quê: RAND_MAX = 2^31-1 = 2147483647
// 2147483647 % 90 = 7
// Bolas 1..7 têm probabilidade ligeiramente maior que bolas 8..90
// A BMM detecta isso no teste de Frequência do NIST SP 800-22
```

A solução correta é rejection sampling:

```go
func RandRange(max uint64) uint64 {
    // Threshold: o menor múltiplo de max dentro de uint64
    // Qualquer valor abaixo do threshold é rejeitado para eliminar o viés
    threshold := (math.MaxUint64 - max + 1) % max
    for {
        n := readUint64()        // 8 bytes do CSPRNG
        if n >= threshold {
            return n % max       // aceito: distribuição uniforme
        }
        // rejeitado: tenta novamente
    }
}
```

O loop termina em expectativa de menos de 2 iterações para qualquer `max`.

---

## 3. Algoritmo: AES-256-CTR DRBG

O núcleo do serviço implementa o **CTR_DRBG** definido no NIST SP 800-90A Rev.1,
Seção 10.2.1, sem derivation function (mais simples e igualmente seguro dado
entropia adequada na seed).

### 3.1 Estado interno

```
┌─────────────────────────────────────────────────────┐
│                ESTADO INTERNO (privado)              │
│                                                     │
│   Key:  [32]byte  ← chave AES-256 atual             │
│   V:    [16]byte  ← counter/nonce (128 bits)        │
│                                                     │
│   reseed_counter: uint64  ← outputs desde re-seed   │
└─────────────────────────────────────────────────────┘
```

O estado NUNCA é exposto via API. Nenhum getter, nenhum dump de estado,
nenhum campo público. A única interface é: `Generate(n) → bytes`.

### 3.2 Operação Generate

```
CTR_DRBG_Generate(n_bytes):
  output = []
  
  while len(output) < n_bytes:
    V = V + 1 (mod 2^128)           ← incrementa counter
    block = AES_256_Encrypt(Key, V) ← cifra o counter
    output = output || block        ← concatena 16 bytes
  
  // Forward secrecy: atualiza Key e V com output derivado
  // Nenhuma relação recuperável entre estado anterior e próximo
  (Key, V) = CTR_DRBG_Update(nil, Key, V)
  
  reseed_counter += 1
  return output[:n_bytes]
```

### 3.3 Operação Reseed

```
CTR_DRBG_Reseed(entropy):
  // Mistura nova entropia no estado via XOR após cifragem
  (Key, V) = CTR_DRBG_Update(entropy, Key, V)
  reseed_counter = 0
```

### 3.4 Por que AES-256-CTR e não ChaCha20

```
Critério              AES-256-CTR DRBG    ChaCha20-DRBG
──────────────────────────────────────────────────────
Padrão NIST           SP 800-90A ✓        não padronizado
Precedente BMM/GLI    alto ✓              crescente
Hardware acelerado    AES-NI (x86/ARM) ✓  software-only
Velocidade (AES-NI)   ~4 GB/s             ~1.5 GB/s
Segurança             256 bits ✓          256 bits ✓
Escolha do projeto    primária ✓          alternativa (futuro)
```

O AES-NI está disponível em qualquer CPU x86-64 dos últimos 12 anos e na maioria dos
ARM modernos (incluindo Apple M-series). O Go usa AES-NI automaticamente via `crypto/aes`.

---

## 4. Arquitetura do serviço

### 4.1 Fluxo de dados end-to-end

```
┌──────────────────────────────────────────────────────────────────────┐
│                            CLIENTES                                  │
│                                                                      │
│  landf_game_bingo (Haxe)          Operadores B2B (qualquer stack)   │
│  VLT (C++/Haxe)                   curl / SDK / client lib           │
│         │                                    │                       │
│         │ gRPC (protobuf, HTTP/2)            │ REST (JSON, HTTP/2)  │
└─────────┼────────────────────────────────────┼──────────────────────┘
          │                                    │
          ▼                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       API GATEWAY                                   │
│                                                                     │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────────────────┐  │
│  │ mTLS        │  │ Autenticação │  │ Rate Limiting             │  │
│  │ (serviço    │  │ JWT HS256    │  │ por tenant_id             │  │
│  │  a serviço) │  │ + API Key   │  │ configurável (padrão:     │  │
│  └─────────────┘  └──────────────┘  │ 100 req/s)               │  │
│                                     └───────────────────────────┘  │
│  Middleware injeta tenant_id em cada request (obrigatório)          │
└─────────────────────────────────────┬───────────────────────────────┘
                                      │
                    ┌─────────────────┴──────────────────┐
                    │                                     │
                    ▼                                     ▼
┌───────────────────────────────┐  ┌───────────────────────────────────┐
│       CORE RNG ENGINE         │  │       AUDIT & EVIDENCE LAYER      │
│                               │  │                                   │
│  ┌─────────────────────────┐  │  │  ┌─────────────────────────────┐ │
│  │     Entropy Pool        │  │  │  │       Immutable Log         │ │
│  │                         │  │  │  │                             │ │
│  │  getrandom(2) syscall   │  │  │  │  entry_hash = SHA256(       │ │
│  │  ├─ bloqueia até ter    │  │  │  │    prev_hash ||             │ │
│  │  │  entropia suficiente │  │  │  │    timestamp ||             │ │
│  │  └─ GRND_NONBLOCK=false │  │  │  │    tenant_id ||             │ │
│  │                         │  │  │  │    round_id  ||             │ │
│  │  /dev/hwrng (opcional)  │  │  │  │    values    ||             │ │
│  │  └─ XOR com getrandom   │  │  │  │    signature               │ │
│  └──────────┬──────────────┘  │  │  │  )                         │ │
│             │ seed (48 bytes) │  │  └─────────────────────────────┘ │
│             ▼                 │  │                                   │
│  ┌─────────────────────────┐  │  │  ┌─────────────────────────────┐ │
│  │  AES-256-CTR DRBG       │  │  │  │    Output Signing           │ │
│  │                         │  │  │  │                             │ │
│  │  Key:  [32]byte         │  │  │  │  sig = HMAC-SHA256(         │ │
│  │  V:    [16]byte         │  │  │  │    key_tenant,              │ │
│  │                         │──┼──┼─▶│    tenant||round||ts||vals  │ │
│  │  Generate(n) → []byte   │  │  │  │  )                         │ │
│  │  Reseed(entropy)        │  │  │  └─────────────────────────────┘ │
│  └──────────┬──────────────┘  │  │                                   │
│             │ bytes brutos    │  │  ┌─────────────────────────────┐ │
│             ▼                 │  │  │  Re-seed Scheduler          │ │
│  ┌─────────────────────────┐  │  │  │                             │ │
│  │  Scaling / Mapping      │  │  │  │  Gatilhos:                 │ │
│  │                         │  │  │  │  • 1.000.000 outputs        │ │
│  │  RandRange(max)         │  │  │  │  • 3.600 segundos           │ │
│  │  └─ rejection sampling  │  │  │  │  • restart do serviço       │ │
│  │                         │  │  │  │  • anomalia detectada       │ │
│  │  Shuffle([]T)           │  │  │  └─────────────────────────────┘ │
│  │  └─ Fisher-Yates        │  │  │                                   │
│  │                         │  │  │  PostgreSQL (append-only)        │ │
│  │  RandFloat64()          │  │  │  └─ trigger bloqueia UPDATE/DEL  │ │
│  │  └─ 53-bit precision    │  │  │  └─ retenção: 5 anos            │ │
│  └─────────────────────────┘  │  └───────────────────────────────────┘
└───────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                  OBSERVABILIDADE & HEALTH                           │
│                                                                     │
│  Tamper Detection (a cada 5 min)                                    │
│  └─ SHA256(/proc/self/exe) vs BinaryHash (embutido em build time)  │
│  └─ Se divergir: pausar geração + alerta CRITICAL                  │
│                                                                     │
│  Self-test NIST (a cada 1h, configurável)                          │
│  └─ Frequency + Block Frequency + Runs em 10.000 outputs           │
│  └─ p-value < 0.001 → CRITICAL (parar)                            │
│  └─ p-value < 0.01  → WARNING                                      │
│  └─ p-value > 0.999 → WARNING (bom demais = suspeito)             │
│                                                                     │
│  Prometheus (:9090)                                                 │
│  └─ rng_outputs_total{tenant}                                      │
│  └─ rng_nist_frequency_p_value                                     │
│  └─ rng_reseeds_total{reason}                                      │
│  └─ rng_binary_hash_matches (0.0 = tamper detectado)              │
└─────────────────────────────────────────────────────────────────────┘
```

### 4.2 Multi-tenancy: por que é crítico

```
Request do Operador A:
  { tenant_id: "operador-a", round_id: "r-001", ... }
         │
         ▼
  audit_log entry:
    entry_hash = SHA256("PREV_HASH" || "operador-a" || "r-001" || ...)
    signature  = HMAC(key_operador_a, ...)

Request do Operador B:
  { tenant_id: "operador-b", round_id: "r-001", ... }
         │
         ▼
  audit_log entry:
    entry_hash = SHA256("PREV_HASH" || "operador-b" || "r-001" || ...)
    signature  = HMAC(key_operador_b, ...)
```

A BMM certifica o **serviço**, não cada cliente. A separação por tenant no audit trail
permite que a BMM valide qualquer cliente individualmente sem acessar dados de outros.
É também o que torna o modelo B2B viável: cada operador pode verificar seus próprios
resultados de forma independente, offline, usando apenas seu HMAC key e os hashes públicos.

---

## 5. Hash chain: como funciona e por que importa

O audit trail usa uma estrutura análoga a uma blockchain simplificada:

```
Bloco 0 (gênesis):
  prev_hash = "0000...0000" (64 zeros)
  values    = [34, 12, 67, ...]
  entry_hash = SHA256(prev_hash || timestamp || tenant || round || values || sig)
               = "a3f7..."

Bloco 1:
  prev_hash = "a3f7..."      ← hash do bloco anterior
  values    = [81, 3, 55, ...]
  entry_hash = SHA256(prev_hash || timestamp || tenant || round || values || sig)
               = "b9c2..."

Bloco 2:
  prev_hash = "b9c2..."
  ...
```

**Propriedade crítica**: modificar qualquer bloco invalida todos os blocos subsequentes.
Um auditor (a BMM, um regulador, o próprio operador) pode verificar a integridade de toda
a cadeia offline em O(n) operações SHA256. Não é possível inserir, remover ou modificar
um resultado retroativamente sem invalidar a cadeia.

A assinatura HMAC-SHA256 por batch prova adicionalmente que os valores vieram especificamente
do sistema certificado (e não foram gerados por outro processo e injetados no audit log).

---

## 6. Testes estatísticos: o que a BMM verifica

### 6.1 Visão geral das baterias

```
                    NIST SP 800-22 Rev.1a
                    (15 testes + sub-testes)
                           │
           ┌───────────────┼───────────────┐
           │               │               │
    Frequência       Estrutural       Aleatório
    ─────────        ──────────       ─────────
    Frequency        Matrix Rank      Random Excursions
    Block Freq       Linear Complex   Random Excursions Var
    Runs             Serial
    Longest Runs     Approx Entropy
    DFT (Spectral)   Cum Sums
                     Non-overlap Templ
                     Overlap Templ
                     Maurer's Universal

                    Dieharder (~100 testes)
                    (Diehard de Marsaglia modernizado)
                           │
           ┌───────────────┼───────────────┐
           │               │               │
    Birthday       Overlapping        Parking Lot
    Spacings       Permutations       Min Distance
    Matrix Ranks   Monkey Tests       Random Spheres
    Count 1s       Squeeze            Craps
    ...

                    Testes Empíricos de Knuth
                    (Art of Computer Programming Vol.2)
                           │
           ┌───────────────┴───────────────┐
           │                               │
    Frequência, Serial, Gap, Poker  Coupon, Perm, Run, Max
```

### 6.2 O que cada resultado significa

Cada teste retorna um **p-value** calculado assumindo a hipótese nula de aleatoriedade perfeita.

```
p-value = P(estatística ≥ observada | sequência verdadeiramente aleatória)

p-value < 0.01  → rejeita hipótese nula → sequência NÃO é aleatória → REPROVADO
p-value ≥ 0.01  → não rejeita hipótese nula → APROVADO (naquele teste)
p-value > 0.999 → estatisticamente suspeito ("bom demais para ser verdade")
                  pode indicar gerador constante ou output zerado
```

O critério BMM: **todos os 15 testes NIST SP 800-22 com p-value ≥ 0.01** na amostra
de 1 bilhão de bits submetida.

### 6.3 Por que 1 bilhão de bits

```
Teste: Frequency (mais simples)
Precisa detectar: desvio de 0.01% na proporção de 0s e 1s

Para detectar um desvio desse tamanho com 99% de confiança:
n ≥ (z_α/2 / ε)² = (2.576 / 0.0001)² ≈ 660.000.000 bits

→ 1 bilhão de bits dá margem confortável para todos os 15 testes
→ Gerado e armazenado em arquivo binário antes da submissão
→ A BMM pode re-executar os testes no mesmo arquivo para reprodutibilidade
```

---

## 7. Entropia: a fundação de tudo

### 7.1 getrandom(2) — por que é a escolha certa

```
                    Linux Kernel
                    ┌──────────────────────────────────────┐
                    │         CSPRNG do Kernel             │
                    │    (ChaCha20 desde Linux 4.8)        │
                    │                                      │
                    │  Fontes de entropia do hardware:     │
                    │  • Interrupções de hardware          │
                    │  • Jitter de timing do CPU           │
                    │  • RDSEED/RDRAND (Intel/AMD)         │
                    │  • TPM (se disponível)               │
                    │  • Eventos de rede, disco, etc.      │
                    └──────────────────┬───────────────────┘
                                       │
                    getrandom(buf, size, flags=0)
                                       │
                    ┌──────────────────▼───────────────────┐
                    │  BLOQUEIA até entropy_avail ≥ 256    │
                    │  (garante entropia real antes de     │
                    │   retornar qualquer byte)            │
                    └──────────────────────────────────────┘
                                       │
                                  48 bytes (seed)
                                       │
                                  CTR_DRBG_Reseed()
```

`getrandom()` com `flags=0` (sem `GRND_NONBLOCK`) bloqueia se o pool de entropia do
kernel não tiver bits suficientes. Em VMs novas ou containers recém-criados isso pode
demorar alguns segundos no primeiro boot. O serviço trata o EINTR corretamente (loop).

### 7.2 HWRNG opcional

Em hardware VLT com TPM ou chip de entropia dedicado (`/dev/hwrng`), o serviço lê
bytes adicionais e faz XOR com os bytes do `getrandom()`. Se o HWRNG falhar, degrada
graciosamente para apenas `getrandom()` — nunca bloqueia o serviço.

```go
func (p *Pool) Collect(size int) ([]byte, error) {
    primary := make([]byte, size)
    if _, err := getrandom(primary); err != nil {
        return nil, err  // getrandom() falha = erro fatal
    }

    if p.hwrng != nil {
        secondary := make([]byte, size)
        if n, err := p.hwrng.Read(secondary); err == nil && n == size {
            for i := range primary {
                primary[i] ^= secondary[i]  // XOR: só melhora, nunca piora
            }
        }
        // hwrng falhou? ignora, continua com getrandom apenas
    }
    return primary, nil
}
```

---

## 8. API: contratos de interface

### 8.1 REST — endpoints principais

```
POST /v1/generate
Body:
{
  "tenant_id": "operador-a",       // obrigatório
  "game_id":   "bingo-90",         // obrigatório
  "round_id":  "2025-01-01-r001",  // obrigatório, único por rodada
  "count":     1,                  // quantos números
  "min":       1,                  // inclusive
  "max":       90                  // inclusive
}

Response:
{
  "request_id":   "550e8400-...",         // UUID v4
  "tenant_id":    "operador-a",
  "game_id":      "bingo-90",
  "round_id":     "2025-01-01-r001",
  "values":       [42],
  "timestamp_utc":"2025-01-01T12:00:00.000000000Z",
  "signature":    "a3f7b2c1...",          // HMAC-SHA256 hex
  "audit_hash":   "b9c2d4e5..."           // posição no hash chain
}

POST /v1/generate/shuffle
Body: { "tenant_id": "...", "game_id": "...", "round_id": "...",
        "items": [1,2,3,...,90] }
Response: { ...campos padrão..., "shuffled": [34,12,67,...] }

GET /v1/health
Response:
{
  "status":             "ok",
  "entropy_pool":       "ok",
  "csprng":             "ok",
  "audit_store":        "ok",
  "last_reseed_utc":    "2025-01-01T11:00:00Z",
  "outputs_since_reseed": 123456,
  "binary_hash":        "sha256_do_executavel_em_execucao"
}

GET /v1/audit/{round_id}
Response:
{
  "round_id":          "2025-01-01-r001",
  "entries":           [...],
  "hash_chain_valid":  true,
  "signature_valid":   true
}
```

### 8.2 gRPC — para uso interno (bingo/VLT)

```protobuf
service RNGService {
  rpc Generate(GenerateRequest) returns (GenerateResponse);
  rpc Shuffle(ShuffleRequest)   returns (ShuffleResponse);
  rpc HealthCheck(Empty)        returns (HealthCheckResponse);

  // Para sorteio de bingo completo: stream de 90 bolas em sequência
  rpc StreamGenerate(GenerateRequest) returns (stream GenerateResponse);
}
```

O gRPC usa HTTP/2 com framing binário (protobuf) — latência ~5x menor que REST/JSON
para o mesmo payload. Relevante para VLT onde cada resultado precisa de resposta
em < 50ms.

---

## 9. Estrutura do repositório anotada

```
bmm-rng-gli19/
│
├── CLAUDE.md                    ← instrução para Claude Code (AI coding assistant)
├── README.md                    ← documentação técnica principal (publicável)
├── Makefile                     ← automação completa de build, test, BMM package
├── go.mod                       ← módulo: github.com/lucky-and-fun/rng-service
│                                   deps diretas: lib/pq, prometheus/client_golang
│                                   (núcleo criptográfico usa só stdlib Go)
│
├── cmd/rng-service/
│   └── main.go                  ← entry point; injeta BinaryHash via -ldflags
│
├── internal/                    ← pacotes privados (não importáveis externamente)
│   ├── entropy/                 ← pool.go: getrandom() + HWRNG + política reseed
│   ├── csprng/                  ← aes_ctr_drbg.go: AES-256-CTR DRBG core
│   ├── scaling/                 ← range.go: rejection sampling + Fisher-Yates
│   ├── audit/                   ← log.go: hash chain + HMAC; store_postgres.go
│   ├── gateway/                 ← rest.go, grpc.go, middleware.go
│   ├── health/                  ← checker.go: tamper detect; nist_selftest.go
│   └── config/                  ← config.go: env vars
│
├── proto/rng/v1/
│   └── rng.proto                ← definição gRPC (compilar com protoc)
│
├── tests/
│   ├── nist/
│   │   ├── run_nist.sh          ← roda NIST STS 2.1.2 em 1M bits (CI rápido)
│   │   └── run_billion.sh       ← roda NIST + Dieharder em 1B bits (pré-BMM)
│   └── integration/             ← testes de integração (requer PostgreSQL)
│
├── deploy/
│   ├── Dockerfile
│   ├── docker-compose.yml       ← dev local: serviço + PostgreSQL
│   └── schema.sql               ← DDL da tabela rng_audit_log (append-only)
│
├── docs/bmm-submission-package/ ← 7 documentos técnicos para a BMM
│   ├── 01-design-document.md
│   ├── 02-algorithm-specification.md
│   ├── 03-entropy-sources.md
│   ├── 04-statistical-testing.md
│   ├── 05-security-controls.md
│   ├── 06-audit-trail.md
│   └── 07-compliance-checklist.md
│
├── sourcecode/vertex-rng-1.0.1/ ← código C/C++ de referência (provavelmente
│                                   implementação de referência BMM/GLI para comparação)
├── binaries/                    ← binários de referência (mesmo propósito)
├── reference/                   ← material normativo da BMM/GLI19
└── documentation/               ← documentação regulatória adicional
```

---

## 10. Tamper detection: como o serviço se auto-verifica

```
BUILD TIME:
  go build -o ./bin/rng-service ./cmd/rng-service
  HASH=$(sha256sum ./bin/rng-service | cut -d' ' -f1)
  go build -ldflags="-X main.BinaryHash=${HASH}" -o ./bin/rng-service ...
  
  Resultado: BinaryHash está gravada DENTRO do binário como constante.
  O binário sabe qual deveria ser o seu próprio hash.

RUNTIME (startup):
  hash_em_disco = SHA256(/proc/self/exe)  ← hash atual do executável
  if hash_em_disco != BinaryHash {
      log.Fatal("TAMPER DETECTED: binary hash mismatch")
      // serviço recusa inicialização
  }

RUNTIME (a cada 5 minutos):
  hash_atual = SHA256(/proc/self/exe)
  if hash_atual != hash_no_startup {
      pausar_geracao()
      alertar_ops("CRITICAL: binary modified at runtime")
  }
```

Isso detecta: substituição do binário em produção, modificação de biblioteca linkada
dinamicamente, e certos tipos de memory corruption que afetam o código em disco.
A BMM exige essa classe de controle na Fase 4 (auditoria operacional).

---

## 11. Schema do banco de dados

```sql
CREATE TABLE rng_audit_log (
    id              BIGSERIAL       PRIMARY KEY,
    entry_hash      CHAR(64)        NOT NULL UNIQUE,  -- SHA256 hex
    prev_hash       CHAR(64)        NOT NULL,          -- encadeamento
    tenant_id       VARCHAR(64)     NOT NULL,
    game_id         VARCHAR(128)    NOT NULL,
    round_id        VARCHAR(128)    NOT NULL,
    request_id      UUID            NOT NULL,
    values_json     JSONB           NOT NULL,          -- os números gerados
    value_count     INTEGER         NOT NULL,
    min_value       BIGINT          NOT NULL,
    max_value       BIGINT          NOT NULL,
    signature       CHAR(64)        NOT NULL,          -- HMAC-SHA256 hex
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    reseed_event    BOOLEAN         NOT NULL DEFAULT FALSE
);

-- Imutabilidade via trigger (PostgreSQL)
CREATE OR REPLACE FUNCTION prevent_audit_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'rng_audit_log is append-only: UPDATE and DELETE are forbidden';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_immutability
    BEFORE UPDATE OR DELETE ON rng_audit_log
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

-- Índices para queries de auditoria
CREATE INDEX idx_audit_tenant_time ON rng_audit_log (tenant_id, created_at);
CREATE INDEX idx_audit_round       ON rng_audit_log (round_id);
CREATE INDEX idx_audit_chain       ON rng_audit_log (entry_hash, prev_hash);

-- Particionamento por mês (retenção 5 anos = 60 partições)
-- PARTITION BY RANGE (created_at) com pg_partman para automação
```

---

## 12. Processo de certificação BMM: linha do tempo técnica

```
Semana  1──────8: FASE 1 — Pré-compliance
│
│  ┌─ Implementar core (Sprints 1–4)
│  ├─ Rodar NIST SP 800-22 localmente (sts-2.1.2)
│  ├─ Rodar Dieharder localmente
│  └─ Gerar sample de 1 bilhão de bits e validar
│     └─ make test-nist-billion  (pode levar horas em hardware modesto)
│
Semana  8──────10: FASE 2 — Submissão formal
│
│  ┌─ Enviar pacote: make bmm-package
│  │  └─ código-fonte ou binário assinado
│  │  └─ 7 documentos técnicos (docs/bmm-submission-package/)
│  │  └─ resultados dos testes locais
│  │  └─ arquivo binário com 1B bits de output
│  └─ Assinar Certification Agreement com BMM Brasil (SP)
│
Semana 10──────16: FASE 3 — Testes estatísticos BMM
│
│  ┌─ BMM roda suas próprias baterias (NIST + Diehard + Knuth)
│  ├─ BMM pode solicitar acesso ao serviço em staging para testes ao vivo
│  └─ Se reprovar: BMM informa não-conformidades → corrigir → re-submeter
│     (cada re-submissão reinicia o clock desta fase)
│
Semana 16──────22: FASE 4 — Auditoria operacional
│
│  ┌─ Build pipeline: CI/CD reprodutível, assinatura de release
│  ├─ Custódia de chaves: Vault/KMS, acesso auditado
│  ├─ Tamper detection: verificado em ambiente de staging
│  ├─ Isolamento: RNG em processo separado, sem debug endpoints em produção
│  └─ Ambiente documentado: SO, versão kernel, versão OpenSSL/Go runtime
│
Semana 22+: FASE 5 — Emissão e manutenção
│
│  ┌─ PCCC (comitê BMM) vota pela emissão
│  ├─ Certificado disponível no portal BMM
│  └─ Revisão trimestral: self-test logs + relatório de distribuição
│
GATILHOS DE RE-CERTIFICAÇÃO (reiniciam o processo):
  • Mudança de algoritmo CSPRNG
  • Troca da fonte de entropia
  • Atualização de OS/kernel em produção
  • Atualização da lib criptográfica (Go runtime, OpenSSL)
  • Expansão para nova jurisdição
  • Qualquer alteração no código dos módulos entropy/, csprng/, scaling/
```

---

## 13. Próximos passos concretos

### Sprint 1 — Core certificável (AGORA)

**Critério de aceite: `go test -race ./...` passando + NIST quick green**

```
internal/entropy/pool.go
  └─ Pool struct com getrandom(), HWRNG opcional, política de reseed
  └─ Testa: Collect() retorna bytes com entropia real, reseed conta corretamente

internal/csprng/aes_ctr_drbg.go
  └─ DRBG struct: Key [32]byte, V [16]byte
  └─ Generate(n uint64) []byte — incrementa V, cifra com AES-256, update pós-geração
  └─ Reseed(entropy []byte) — CTR_DRBG_Update com nova entropia
  └─ HealthCheck() error — verifica estado interno não-corrompido
  └─ Testa: vetores NIST SP 800-90A (determinísticos, publicados), race detector

internal/scaling/range.go
  └─ RandRange(max uint64) uint64 — rejection sampling
  └─ Shuffle(s []int) — Fisher-Yates
  └─ RandFloat64() float64 — 53-bit precision
  └─ Testa: distribuição uniforme com chi-quadrado, zero bias em RandRange

make test-nist-quick
  └─ Gera 1M bits, roda NIST STS 2.1.2, verifica p-values > 0.01
```

### Sprint 2 — Audit trail

```
internal/audit/log.go
  └─ HashChain: NewEntry() calcula entry_hash encadeado
  └─ Sign(): HMAC-SHA256 por batch
  └─ Verify(): verifica cadeia offline

internal/audit/store_postgres.go
  └─ Append(): INSERT com trigger de imutabilidade
  └─ GetByRound(): query para auditoria
  └─ VerifyChain(): verifica hash chain completo de um tenant

deploy/schema.sql
  └─ DDL completo com trigger, índices, particionamento

make test-integration
  └─ Sobe PostgreSQL, insere 10.000 entradas, verifica hash chain
```

### Sprint 3 — API e gateway

```
internal/gateway/rest.go     ← handlers HTTP, validação de request
internal/gateway/grpc.go     ← handlers gRPC gerados do proto
internal/gateway/middleware.go ← JWT, API key, rate limit, tenant inject

proto/rng/v1/rng.proto → gerar com: protoc --go_out=. --go-grpc_out=. proto/rng/v1/rng.proto

Integração com landf_game_bingo:
  └─ Cliente gRPC em Haxe via FFI ou proxy local
  └─ Substituir qualquer chamada de rand() no bingo pelo serviço
```

### Sprint 4 — Hardening e observabilidade

```
internal/health/checker.go      ← tamper detection em startup e runtime
internal/health/nist_selftest.go ← Frequency + Runs + BlockFreq em background

make build-release              ← build com BinaryHash embutido via -ldflags

Dashboard Grafana:
  └─ Painel 1: p-values dos self-tests ao longo do tempo
  └─ Painel 2: taxa de re-seeds por razão
  └─ Painel 3: outputs por tenant
  └─ Painel 4: binary_hash_matches (deve ser sempre 1.0)
```

### Sprint 5 — Pacote de submissão BMM

```
make test-nist-billion          ← gera 1B bits, NIST completo + Dieharder
                                   (estimar 6–12h em hardware padrão)

make bmm-package                ← consolida resultados + docs em
                                   docs/bmm-submission-package/

Verificar docs/bmm-submission-package/07-compliance-checklist.md
  └─ Todos os itens ✓ antes de contatar a BMM Brasil
  └─ Contato: bmm.com/bmm-brazil-hub (escritório São Paulo)
```

---

## 14. Decisões de design e trade-offs documentados

| Decisão | Escolha | Alternativa descartada | Razão |
|---|---|---|---|
| Linguagem | Go | Rust | Ecossistema gRPC mais maduro; `crypto/aes` usa AES-NI automaticamente |
| Algoritmo CSPRNG | AES-256-CTR DRBG | ChaCha20-DRBG | Maior precedente regulatório; padrão NIST explícito |
| Fonte de entropia | `getrandom(2)` | `/dev/urandom` | getrandom() bloqueia até ter entropia — mais seguro no boot |
| Deps criptográficas | stdlib Go apenas | OpenSSL via CGO, libsodium | Menor superfície de ataque; sem CGO = build mais simples e reprodutível |
| Audit store | PostgreSQL | immudb, InfluxDB | PostgreSQL com trigger de imutabilidade é suficiente e amplamente auditável |
| Tamper detection | SHA256 do executável | Runtime attestation (TPM) | Simples, sem dep de hardware; TPM pode ser adicionado depois |
| Multi-tenant | tenant_id no request | Instâncias separadas por tenant | Uma instância certificada serve N tenants; re-certificação só do serviço |

---

## 15. Referências normativas

| Documento | Relevância |
|---|---|
| NIST SP 800-90A Rev.1 | Especificação do CTR_DRBG implementado |
| NIST SP 800-22 Rev.1a | Os 15 testes estatísticos que a BMM aplica |
| NIST SP 800-90B | Avaliação de qualidade das fontes de entropia |
| GLI-19 Standard | Norma técnica GLI para RNGs de iGaming |
| Matsumoto & Nishimura 1998 | Por que MT19937 não serve (referência) |
| Lemire 2019 | Rejection sampling sem viés (base do RandRange) |
| Knuth, TAOCP Vol.2 §3.4.2 | Fisher-Yates shuffle (base do Shuffle) |
| Ferguson, Schneier & Kohno 2010 | Forward secrecy em DRBGs |

---

*Documento gerado em maio/2026 a partir do estado atual do repositório.*  
*Atualizar após cada sprint concluído.*
