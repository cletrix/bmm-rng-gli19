# Checklist de Conformidade — Autoavaliação

**Avaliação realizada por:** Equipe Técnica Lucky & Fun  
**Data:** 2026-05-11  
**Versão do software:** rng-service v1.0  

---

## Legenda

- ✅ Implementado e verificado
- ⚠️ Implementado parcialmente / dependência de ambiente
- ❌ Não implementado
- 📋 Requer documentação adicional para submissão

---

## 1. Algoritmo e Geração

| Requisito | Status | Evidência |
|---|---|---|
| CSPRNG aprovado (NIST SP 800-90A) | ✅ | AES-256-CTR DRBG §10.2.1 |
| `math/rand` não utilizado | ✅ | grep no código-fonte |
| Mersenne Twister não utilizado | ✅ | grep no código-fonte |
| Seed com entropia mínima de 256 bits | ✅ | SeedLen=48 bytes; `getrandom(2)` |
| Rejection sampling (sem viés de módulo) | ✅ | `internal/scaling/range.go` |
| Fisher-Yates para shuffle | ✅ | `internal/scaling/range.go` |
| Forward secrecy após geração | ✅ | `CTR_DRBG_Update(nil)` pós-Generate |
| Estado interno não exposto por API | ✅ | Sem endpoint de dump de estado |

## 2. Entropia

| Requisito | Status | Evidência |
|---|---|---|
| Fonte de entropia primária: kernel CSPRNG | ✅ | `getrandom(2)` sem `GRND_NONBLOCK` |
| Bloqueio até pool inicializado | ✅ | Flag `0` (sem NONBLOCK) |
| Suporte a HWRNG como fonte secundária | ✅ | `/dev/hwrng` via `RNG_HWRNG_PATH` |
| Política de reseed: limite de outputs | ✅ | 1.000.000 outputs |
| Política de reseed: limite temporal | ✅ | 3.600 segundos |
| Reseed no startup | ✅ | `CollectForReseed` na inicialização |
| Entropia ≥ 1000 bits disponível em prod | ⚠️ | Verificar `/proc/sys/kernel/random/entropy_avail` |

## 3. Testes Estatísticos

| Requisito | Status | Evidência |
|---|---|---|
| NIST SP 800-22 (todos 15 testes) | 📋 | Executar `run_billion.sh` em prod Linux |
| p-value ≥ 0.01 em todos os testes | 📋 | Preencher §4.1 do doc 04 |
| Dieharder (suíte completa) | 📋 | Executar `run_billion.sh` em prod Linux |
| Self-test contínuo em produção | ✅ | `health.SelfTester` — 3 testes/hora |
| Alerta em p-value crítico | ✅ | `StatusFail` → log CRITICAL + métrica |
| Volume de teste: ≥ 1 bilhão de bits | 📋 | Script pronto; executar antes da submissão |

## 4. Auditoria e Rastreabilidade

| Requisito | Status | Evidência |
|---|---|---|
| Cada output tem request_id único | ✅ | UUID v4 via `crypto/rand` |
| Hash chain por output | ✅ | SHA-256 encadeado com prev_hash |
| Assinatura HMAC por batch | ✅ | HMAC-SHA-256 por tenant |
| tenant_id em todos os registros | ✅ | Campo obrigatório em cada Entry |
| round_id rastreável | ✅ | Campo obrigatório; queryable por API |
| Imutabilidade do audit log | ✅ | Trigger PostgreSQL bloqueia UPDATE/DELETE |
| Retenção de 5 anos | ⚠️ | Schema pronto; política de archiving pendente |
| Verificação offline por auditores | ✅ | `audit.VerifyEntries()` + HMAC replay |

## 5. Segurança de Acesso

| Requisito | Status | Evidência |
|---|---|---|
| Autenticação obrigatória em todos endpoints | ✅ | `authMiddleware` — 401 sem token |
| JWT HS256 (stdlib, sem dep externa) | ✅ | `internal/gateway/middleware.go` |
| API Key por tenant | ✅ | `RNG_API_KEYS` |
| Isolamento de tenant (cross-tenant proibido) | ✅ | Verificação tenant_id em cada handler |
| Rate limiting por tenant | ✅ | Token bucket, `RNG_RATE_LIMIT_RPS` |
| TLS para comunicação externa | ⚠️ | Suportado; configurar certificados em prod |
| mTLS para gRPC interno | ⚠️ | Proto definido; implementação gRPC pendente |

## 6. Tamper Detection e Integridade do Binário

| Requisito | Status | Evidência |
|---|---|---|
| Hash do binário embutido em build | ✅ | `make build-release` com `-ldflags` |
| Verificação no startup | ✅ | `health.New(BinaryHash)` |
| Verificação periódica (5 min) | ✅ | Goroutine em `main.go` |
| Alerta em tamper detectado | ✅ | Log CRITICAL + `rng_binary_hash_matches=0` |
| Modo dev distinguível de produção | ✅ | `BinaryHash=="dev-build"` → IsDev() |

## 7. Observabilidade e Monitoramento

| Requisito | Status | Evidência |
|---|---|---|
| Métricas Prometheus expostas | ✅ | Porta 9090 /metrics |
| p-values NIST como métricas | ✅ | `rng_nist_test_p_value{test=...}` |
| Contador de outputs por tenant | ✅ | `rng_outputs_total{tenant=...}` |
| Contador de reseeds por motivo | ✅ | `rng_reseeds_total{reason=...}` |
| Gauge de tamper detection | ✅ | `rng_binary_hash_matches` |
| Timestamp do último self-test | ✅ | `rng_selftest_last_run_timestamp_seconds` |
| Health endpoint público | ✅ | `GET /v1/health` |

## 8. Itens Pendentes para Submissão BMM

Os itens marcados com 📋 abaixo **devem ser concluídos** antes da submissão formal:

1. **Executar `run_billion.sh`** em servidor Linux de produção com STS 2.1.2 e dieharder instalados
2. **Preencher a tabela de resultados** no documento `04-statistical-testing.md` §4.1 e §4.2
3. **Adicionar o SHA-256 do binário testado** nos resultados (arquivo `binary_hash.txt`)
4. **Verificar entropia disponível** no servidor de produção antes dos testes (`/proc/sys/kernel/random/entropy_avail`)
5. **Configurar TLS/mTLS** em produção e documentar os certificados usados
6. **Implementar gRPC** (Sprint 3 de gRPC pendente) se uso interno via gRPC for incluído na certificação
7. **Definir política de archiving** do audit log PostgreSQL para retenção de 5 anos

## 9. Declaração

Declaramos que o software `rng-service v1.0` foi desenvolvido seguindo os requisitos de NIST SP 800-90A Rev.1 para geração de números aleatórios criptograficamente seguros, e que as informações contidas neste pacote de submissão são precisas na data de submissão.

**Responsável técnico:** ___________________________  
**Data:** ___________________________  
**Assinatura:** ___________________________
