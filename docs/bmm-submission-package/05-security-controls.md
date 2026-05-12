# Controles de Segurança

---

## 1. Autenticação e Autorização

### 1.1 Clientes B2B (REST)

Dois mecanismos suportados, verificados em ordem:

**JWT HS256:**
- Algoritmo: HMAC-SHA-256 (HS256)
- Secret: configurado via `RNG_JWT_SECRET` (mínimo 32 bytes)
- Claims obrigatórios: `sub` (tenant_id), `exp` (expiração)
- Verificação: implementação pura stdlib Go sem dependência externa
- Header: `Authorization: Bearer <token>`

**API Key:**
- Formato: string opaca mapeada a `tenant_id` via `RNG_API_KEYS="key1:tenant-a,key2:tenant-b"`
- Header: `X-Api-Key: <key>`
- Uso típico: integrações server-to-server sem necessidade de rotação JWT

**Verificação de tenant:** O `tenant_id` extraído do token é sempre comparado com o `tenant_id` no corpo do request. Divergência retorna `HTTP 403 Forbidden`.

### 1.2 Jogos Internos (gRPC)

- mTLS obrigatório — certificados de cliente por tenant
- Autorização via metadata `x-tenant-id`

### 1.3 Requests não autenticados

Retornam `HTTP 401 Unauthorized` sem expor detalhes internos. Não há endpoint público sem autenticação.

## 2. Rate Limiting

**Algoritmo:** Token bucket por `tenant_id`  
**Capacidade:** 2 × RPS configurado (burst de 2 segundos)  
**Configuração:** `RNG_RATE_LIMIT_RPS` (default: 100 req/s por tenant)

O rate limiter é aplicado **depois** da autenticação, garantindo que o tenant_id esteja disponível para bucketing. Requests acima do limite retornam `HTTP 429 Too Many Requests`.

## 3. Tamper Detection

**Objetivo:** Detectar modificação do binário em execução após deploy.

**Mecanismo:**
1. No startup, o serviço computa `SHA-256(os.Executable())` → `startupHash`
2. Compara com `BinaryHash` embutido em build-time via `-ldflags "-X main.BinaryHash=..."`
3. A cada 5 minutos, repete o cálculo e compara com `startupHash`
4. Divergência: log de alerta CRITICAL + métrica `rng_binary_hash_matches=0`

**Build com hash embutido:**
```bash
HASH=$(sha256sum ./bin/rng-service | cut -d' ' -f1)
go build -ldflags="-X main.BinaryHash=${HASH}" -o ./bin/rng-service ./cmd/rng-service
# Equivalente a: make build-release
```

**Modo de desenvolvimento:** Se `BinaryHash == "dev-build"` (não embutido), o check de startup é pulado e o serviço registra que está em modo dev. Este modo nunca deve ser usado em produção.

**Limitação:** A tamper detection protege contra modificação pós-deploy; não protege contra comprometimento da cadeia de build. A integridade da cadeia de build é responsabilidade do pipeline CI/CD (checksums de artefatos).

## 4. Gerenciamento de Chaves de Assinatura

**Uso:** HMAC-SHA-256 para assinar cada batch de outputs.

**Configuração atual (StaticKeyStore):**
- Chave wildcard `"*"` usada para todos os tenants (simplificado)
- Chave carregada via `RNG_SIGNING_KEY` (mínimo 32 bytes)
- Em produção: usar `RNG_SIGNING_KEY_PATH` apontando para volume de segredo (Docker/K8s secrets)

**Requisito de tamanho:** Mínimo 32 bytes. Chaves menores são rejeitadas em startup com erro.

**Rotação de chaves:** A rotação de chaves de assinatura **não** invalida o DRBG nem exige re-certificação. Apenas os registros de auditoria assinados com a chave antiga precisam ser re-verificados com a chave antiga armazenada.

## 5. Comunicação Segura

| Canal | Protocolo | Requisito |
|---|---|---|
| B2B REST | TLS 1.3 | Obrigatório em produção |
| gRPC interno | mTLS (TLS 1.3) | Obrigatório; rejeitar conexões sem cert |
| Banco de dados | TLS (PostgreSQL) | `sslmode=require` no `DATABASE_URL` |
| Métricas Prometheus | HTTP interno | Não exposto externamente; firewall/VPC |

## 6. Segredos — Variáveis de Ambiente

| Variável | Conteúdo | Recomendação de produção |
|---|---|---|
| `RNG_JWT_SECRET` | Secret HMAC para JWT | Montar como arquivo; ler via `RNG_JWT_SECRET_PATH` |
| `RNG_API_KEYS` | Mapeamento key→tenant | Gerenciar via secrets manager |
| `RNG_SIGNING_KEY` | Chave de assinatura HMAC | Jamais em env var — usar mount de volume |
| `DATABASE_URL` | String de conexão com senha | Secrets manager; rotação automática |

**Regra:** Nenhum segredo deve aparecer em logs, audit records ou respostas de API. O endpoint `/v1/health` não retorna configurações sensíveis.

## 7. Proteções de Código

| Proteção | Implementação |
|---|---|
| Race conditions | `sync.Mutex` no estado do DRBG; `atomic.Uint64` para contadores |
| SQL injection | Queries parametrizadas (sem interpolação de string) |
| Timing attacks em comparação de chaves | `crypto/subtle.ConstantTimeCompare` para API Keys e assinaturas |
| Overflow em geração de range | `uint64` aritmética; threshold calculado com `-max % max` |
| Panic em prod | `recover()` em handlers HTTP — retorna 500 sem vazar stack trace |
