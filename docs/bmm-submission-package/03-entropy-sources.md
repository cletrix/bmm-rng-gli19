# Fontes de Entropia e Política de Reseed

**Implementação:** `internal/entropy/pool.go`, `internal/entropy/getrandom_linux.go`

---

## 1. Fontes de Entropia

### 1.1 Fonte Primária: `getrandom(2)` — Linux CSPRNG do Kernel

**Interface:** syscall `getrandom(buf, len, 0)` — sem flag `GRND_NONBLOCK`  
**Implementação:** `internal/entropy/getrandom_linux.go`

O `getrandom(2)` é a interface canônica do kernel Linux para entropia criptograficamente segura (disponível desde Linux 3.17). Ao ser chamado sem `GRND_NONBLOCK`, **bloqueia** até que o pool de entropia do kernel esteja inicializado (urandom pool initialized), garantindo que nunca retorne dados fracos no startup.

**Qualidade:** O kernel alimenta o pool via:
- Timing de interrupções de hardware (teclado, rede, disco)
- RDRAND/RDSEED (Intel/AMD) quando disponível
- Ruído de driver (jitter de clock, latências de I/O)

O pool de entropia do kernel é adequado para uso criptográfico por si só. O DRBG AES-256-CTR adiciona uma camada de isolamento: mesmo que o estado do kernel pool seja comprometido após o seed, os outputs passados permanecem seguros (forward secrecy).

**Retry em EINTR:** A implementação faz loop em `EINTR` (interrupção por sinal), garantindo que a chamada sempre complete.

### 1.2 Fonte Secundária: HWRNG (`/dev/hwrng`)

**Interface:** leitura direta de `/dev/hwrng`  
**Disponibilidade:** opcional; path configurável via `RNG_HWRNG_PATH`

O HWRNG é um gerador de números aleatórios por hardware — tipicamente baseado em ruído térmico, shot noise ou efeito fotovoltaico quântico. Quando disponível:

1. Lê-se N bytes do HWRNG
2. Os bytes são XOR'd com a saída do `getrandom(2)`
3. O resultado é usado como seed

**Vantagem:** Se um dos dois (kernel ou hardware) for comprometido, o XOR garante que o seed ainda contenha a entropia da fonte não comprometida. A resistência de segurança é `max(H_kernel, H_hardware)`, não a soma.

**Fallback:** Se `/dev/hwrng` não estiver disponível ou falhar na leitura, o sistema usa somente `getrandom(2)` sem degradação. A ausência do HWRNG é registrada em log mas não impede a operação.

### 1.3 Fallback em Desenvolvimento (macOS)

Em ambientes macOS (desenvolvimento, CI), `getrandom(2)` não existe. O código usa build tags:
- `//go:build linux` → `getrandom_linux.go` (produção)
- `//go:build !linux` → `getrandom_other.go` usa `crypto/rand.Read` (wrapper de `/dev/urandom`)

**Importante:** O fallback macOS nunca é usado em produção Linux.

## 2. Coleta de Entropia para Reseed

A função `CollectForReseed(size, tenantID, outputsSince)` decide se o reseed é necessário baseado em:

```
reseed_needed = (outputsSince >= cfg.ReseedIntervalOutputs)
             || (time.Since(lastReseed) >= cfg.ReseedIntervalSeconds)
```

Se reseed for necessário:
1. `getrandom(2)` coleta `size = 48` bytes (SeedLen do DRBG)
2. Se HWRNG disponível: XOR com 48 bytes do hardware
3. Retorna o seed + metadados (`ReseedEvent` com tenant, motivo, timestamp)
4. O caller chama `drbg.Reseed(seed)` com o material coletado

## 3. Política de Reseed

| Gatilho | Condição | Ação |
|---|---|---|
| Startup | Sempre | Reseed inicial com `reason="startup"` |
| Volume | ≥ 1.000.000 outputs | Reseed com `reason="scheduled"` |
| Temporal | ≥ 3.600 segundos | Reseed com `reason="scheduled"` |
| Health check | DRBG informa `ErrReseedRequired` | Reseed com `reason="event"` |

O reseed é contabilizado em métricas Prometheus (`rng_reseeds_total{reason=...}`) e registrado no audit log.

## 4. Verificação de Entropia Disponível

Em produção, verificar antes do startup:

```bash
cat /proc/sys/kernel/random/entropy_avail
# Deve ser ≥ 1000 (bits disponíveis no pool do kernel)
```

O `getrandom(2)` bloqueia automaticamente se o pool não estiver pronto, então este check é informativo. Em servidores Linux modernos com RDRAND, o pool inicializa em < 1 segundo após o boot.

## 5. Pontos Que Não Usar

- ❌ `GRND_NONBLOCK` em `getrandom` — pode retornar dados insuficientemente seeded no boot
- ❌ `/dev/urandom` diretamente em código Go — `getrandom(2)` é a interface correta
- ❌ `math/rand` com seed de `time.Now()` — previsível
- ❌ Seed de apenas PID + timestamp — previsível via timing attacks
