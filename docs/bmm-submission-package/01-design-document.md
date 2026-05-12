# Documento de Projeto — Lucky & Fun RNG Service

**Versão:** 1.0  
**Data:** 2026-05-11  
**Classificação:** Confidencial — submissão BMM Testlabs Brasil

---

## 1. Visão Geral

O `rng-service` é um serviço de geração de números aleatórios criptograficamente seguros (CSPRNG) desenvolvido para alimentar jogos de iGaming operados pela Lucky & Fun, incluindo Bingo e Video Lottery Terminals (VLT). O serviço opera como back-end central, expondo interfaces REST (clientes B2B) e gRPC (jogos internos), e é projetado para certificação regulatória junto à BMM Testlabs Brasil.

## 2. Arquitetura do Sistema

```
┌─────────────────────────────────────────────────────────────┐
│  Clientes                                                   │
│  ├── Jogos internos (Bingo, VLT)  → gRPC (mTLS)           │
│  └── Operadores B2B               → REST (JWT / API Key)   │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│  API Gateway (internal/gateway)                             │
│  ├── Autenticação: JWT HS256 + API Key por tenant           │
│  ├── Rate limiting: token bucket por tenant                 │
│  └── Roteamento: /v1/generate, /batch, /shuffle, /health   │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│  Core RNG Engine                                            │
│  ├── Entropy Pool (internal/entropy)                        │
│  │   ├── Primária: getrandom(2) — Linux CSPRNG do kernel   │
│  │   └── Secundária: /dev/hwrng — opcional, XOR'd          │
│  ├── CSPRNG (internal/csprng)                               │
│  │   └── AES-256-CTR DRBG (NIST SP 800-90A Rev.1 §10.2.1) │
│  └── Scaling (internal/scaling)                             │
│      ├── Rejection sampling — sem viés estatístico          │
│      └── Fisher-Yates shuffle — permutações uniformes      │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│  Camada de Auditoria (internal/audit)                       │
│  ├── Hash chain: SHA-256 encadeado por output               │
│  ├── Assinatura: HMAC-SHA-256 por batch, chave por tenant   │
│  └── Persistência: PostgreSQL append-only (retenção 5 anos) │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│  Health & Hardening (internal/health)                       │
│  ├── Tamper detection: SHA-256 do executável em runtime     │
│  ├── Self-test NIST: Frequency + Runs + BlockFreq em loop  │
│  └── Métricas: Prometheus isolado (porta 9090)              │
└─────────────────────────────────────────────────────────────┘
```

## 3. Decisões de Design

### 3.1 Escolha do Algoritmo

O AES-256-CTR DRBG (NIST SP 800-90A Rev.1, Seção 10.2.1) foi escolhido por:

- **Aprovação regulatória**: é o algoritmo mais auditado e amplamente aceito por corpos de certificação globais de iGaming.
- **Segurança comprovada**: baseia-se em AES-256, cujo período de ciclo e resistência a ataques são amplamente documentados.
- **Determinismo auditável**: dado o mesmo seed, produz a mesma sequência — permite re-derivação forense de qualquer rodada.
- **Desempenho**: AES-NI (aceleração de hardware) disponível em x86-64 modern; throughput ≥ 1 GB/s.

**Alternativas rejeitadas:**

| Algoritmo | Motivo da rejeição |
|---|---|
| `math/rand` (Go) | Não é CSPRNG; previsível |
| Mersenne Twister | Previsível após 624 outputs; explicitamente rejeitado pela BMM |
| ChaCha20-DRBG | Aceitável, porém sem aprovação histórica BMM; reservado como fallback |
| `time.Now()` como seed | Previsível por timing |

### 3.2 Política de Reseed

Re-seed obrigatório nas condições:
- A cada **1.000.000 outputs** gerados (limite NIST SP 800-90A Rev.1 §10.2.1, Tabela 3)
- A cada **3.600 segundos** (1 hora de operação)
- No **startup** do serviço

Após cada chamada `Generate`, o estado interno sofre `CTR_DRBG_Update(nil)` para garantir **forward secrecy** — o comprometimento do estado atual não revela outputs passados.

### 3.3 Mapeamento de Range

O mapeamento `[0, max)` usa **rejection sampling** com o threshold `t = (2^b - (2^b % max))`:
- Amostras `u ∈ [t, 2^b)` são descartadas e reamostradas
- Elimina o viés de módulo presente em `u % max`
- Probabilidade de rejeição máxima: 50% (para `max = 2^(b-1) + 1`), negligível na prática

O `%` sobre inteiros sem sinal grande é implementado como `(-max) % max` em Go (POSIX mod), que compila para operação eficiente.

### 3.4 Multi-tenancy

Cada request carrega `tenant_id` obrigatório. O ID aparece em:
- Cada entrada do audit log
- O hash chain (contexto de encadeamento)
- O HMAC de assinatura (chave per-tenant)
- Métricas Prometheus (label `tenant`)
- Rate limiting (bucket per-tenant)

Isso permite à BMM certificar o serviço sem re-certificar cada cliente B2B individualmente.

## 4. Componentes de Software

| Linguagem | Go 1.23.0 |
|---|---|
| Biblioteca padrão Go | `crypto/aes`, `crypto/hmac`, `crypto/sha256`, `crypto/rand`, `encoding/binary` |
| Dependências externas | `github.com/lib/pq` (driver PostgreSQL), `github.com/prometheus/client_golang` (métricas) |
| Sistema Operacional | Linux (produção); macOS (desenvolvimento) |
| Kernel mínimo | Linux 3.17 (suporte a `getrandom(2)`) |

Nenhuma biblioteca criptográfica de terceiros é usada para o núcleo do DRBG — apenas a implementação de AES presente na biblioteca padrão do Go (`crypto/aes`), que por sua vez usa AES-NI quando disponível.

## 5. Ambiente de Produção

- **CPU**: x86-64 com suporte a AES-NI (Intel Xeon / AMD EPYC)
- **Kernel**: Linux ≥ 5.4 (LTS)
- **Entropia disponível**: ≥ 1.000 bits em `/proc/sys/kernel/random/entropy_avail` antes do startup
- **Banco de dados**: PostgreSQL 16 com tablespace dedicado para `rng_audit_log`
- **Rede**: Comunicação interna via mTLS; endpoints externos via TLS 1.3

## 6. Controles Que Requerem Re-certificação

As seguintes mudanças invalidam a certificação atual e exigem nova submissão à BMM:

- Alteração do algoritmo de geração (DRBG)
- Alteração das fontes de entropia ou da política de reseed
- Atualização da versão major do Go runtime (`crypto/aes`)
- Mudança do sistema operacional ou versão major do kernel
- Alteração do intervalo de reseed (outputs ou tempo)
- Qualquer alteração nos pacotes `internal/csprng`, `internal/entropy` ou `internal/scaling`
