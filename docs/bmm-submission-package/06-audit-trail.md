# Trilha de Auditoria e Rastreabilidade

**Implementação:** `internal/audit/`

---

## 1. Objetivo

A trilha de auditoria garante que cada número gerado pelo sistema possa ser verificado independentemente por auditores, reguladores e operadores, provando que:

1. O número foi gerado pelo sistema certificado (assinatura HMAC)
2. O número não foi modificado retroativamente (hash chain)
3. O número pertence ao contexto declarado (tenant, jogo, rodada)

## 2. Estrutura de um Registro de Auditoria

Cada geração cria uma entrada com os seguintes campos:

```json
{
  "request_id":  "550e8400-e29b-41d4-a716-446655440000",  // UUID v4 aleatório
  "tenant_id":   "tenant-a",
  "game_id":     "bingo-90",
  "round_id":    "round-2026-001",
  "values":      [42, 17, 83, 5, 61],                     // outputs gerados
  "count":       5,
  "timestamp_ns": 1747000000000000000,                    // Unix nanoseconds
  "prev_hash":   "abc123...",                              // hash da entrada anterior
  "entry_hash":  "def456...",                              // hash desta entrada
  "signature":   "HMAC-SHA256:7f9e..."                    // assinatura HMAC
}
```

## 3. Hash Chain (Encadeamento por SHA-256)

O hash chain garante a integridade da sequência de registros — qualquer modificação retroativa é detectável.

**Cálculo do `entry_hash`:**

```
data = prev_hash_bytes (32 bytes)
     || timestamp_ns (8 bytes, big-endian uint64)
     || uint32_be(len(tenant_id)) || tenant_id
     || uint32_be(len(round_id))  || round_id
     || uint32_be(count)
     || para cada value: int64_be(value)
     || signature_bytes (32 bytes)

entry_hash = hex(SHA256(data))
```

O primeiro registro usa `prev_hash = "000...000"` (64 zeros = `ZeroHash`).

**Verificação:**

Dado uma sequência de registros `[e1, e2, ..., en]`:
1. Verificar `e1.prev_hash == ZeroHash` (ou hash da última entrada da sessão anterior)
2. Para `i = 2..n`: verificar `e[i].prev_hash == e[i-1].entry_hash`
3. Para cada `ei`: recalcular `entry_hash` e comparar

Qualquer divergência indica adulteração retroativa.

## 4. Assinatura HMAC-SHA-256

A assinatura autentica os valores gerados em relação ao contexto, usando uma chave por tenant.

**Cálculo da `signature`:**

```
message = uint32_be(len(tenant_id)) || tenant_id
        || uint32_be(len(round_id))  || round_id
        || timestamp_ns (8 bytes, big-endian uint64)
        || uint32_be(count)
        || para cada value: int64_be(value)

signature = "HMAC-SHA256:" + hex(HMAC-SHA256(key_tenant, message))
```

A chave HMAC é obtida do `KeyStore` pelo `tenant_id`. Isso garante que um tenant não pode forjar assinaturas de outro.

## 5. Persistência

### 5.1 PostgreSQL (produção)

Tabela `rng_audit_log` com trigger de imutabilidade:
- `UPDATE` e `DELETE` são bloqueados por trigger PostgreSQL
- `TRUNCATE` é bloqueado
- Row-Level Security (RLS) ativa por padrão
- Índices em `tenant_id`, `round_id`, `created_at` para queries eficientes

**Schema:**
```sql
CREATE TABLE rng_audit_log (
    id          BIGSERIAL PRIMARY KEY,
    request_id  UUID        NOT NULL UNIQUE,
    tenant_id   TEXT        NOT NULL,
    game_id     TEXT        NOT NULL,
    round_id    TEXT        NOT NULL,
    values_json JSONB       NOT NULL,
    count       INT         NOT NULL,
    entry_hash  TEXT        NOT NULL UNIQUE,
    prev_hash   TEXT        NOT NULL,
    signature   TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- Trigger: bloqueia UPDATE/DELETE
```

**Retenção:** 5 anos (requisito regulatório). Implementar política de arquivamento antes da remoção.

### 5.2 In-Memory (desenvolvimento/testes)

O `InMemoryStore` implementa a mesma interface `Store` e suporta `VerifyChain()`. Não persiste entre restarts — adequado apenas para testes.

## 6. Consulta de Registros

### Por round (API REST)

```
GET /v1/audit/{round_id}
X-Api-Key: key-tenant-a

Response:
{
  "round_id": "round-2026-001",
  "entries": [
    { "request_id": "...", "values": [...], "entry_hash": "...", ... }
  ]
}
```

Somente entradas do tenant autenticado são retornadas.

### Verificação programática

```go
entries, _ := store.GetByRound(ctx, roundID)
ok, err := audit.VerifyEntries(entries, audit.ZeroHash)
// ok == true → cadeia íntegra
```

## 7. Verificação Independente por Auditores

Para que a BMM ou auditores externos verifiquem um registro:

1. Obter a chave HMAC do tenant referente (fornecida separadamente pelo operador)
2. Obter a sequência de entradas para o `round_id` via API ou export do banco
3. Para cada entrada:
   - Recalcular `signature` com `HMAC-SHA256(key, message)` e comparar
   - Recalcular `entry_hash` com `SHA256(data)` e comparar
4. Verificar encadeamento (`prev_hash` de cada entrada aponta para `entry_hash` da anterior)

A verificação é computacionalmente barata e não requer acesso ao sistema em produção.

## 8. Diagrama de Fluxo por Request

```
Cliente → POST /v1/generate
             │
             ▼
        Autenticação (tenant_id extraído)
             │
             ▼
        drbg.Generate(count × 8 bytes)
             │
             ▼
        scaling.RandRangeInclusive(min, max) × count
             │
             ▼
        audit.NewRequestID()           → UUID v4
        entry.Sign(key)                → HMAC-SHA256
        chain.Seal(&entry)             → SHA256 chain
             │
             ▼
        store.Append(&entry)           → PostgreSQL
             │
             ▼
        metrics.RecordOutput(tenant, n)
             │
             ▼
        Response JSON {values, signature, audit_hash, request_id}
```
