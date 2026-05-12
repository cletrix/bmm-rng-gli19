# Especificação do Algoritmo — AES-256-CTR DRBG

**Referência normativa:** NIST SP 800-90A Rev.1 (junho de 2015), Seção 10.2.1  
**Implementação:** `internal/csprng/aes_ctr_drbg.go`

---

## 1. Visão Geral

O DRBG implementado é o **CTR_DRBG sem derivation function (DF)**, usando AES-256 como função de bloco subjacente. A ausência de DF é permitida quando a fonte de entropia fornece entropia de comprimento exato e qualidade suficiente (full-entropy seed), conforme §10.2.1 do padrão.

## 2. Parâmetros de Instanciação

| Parâmetro | Valor | Referência NIST |
|---|---|---|
| Função de bloco | AES-256 | §10.2 |
| `keylen` (comprimento da chave) | 256 bits (32 bytes) | Tabela 3 |
| `outlen` (tamanho do bloco AES) | 128 bits (16 bytes) | Tabela 3 |
| `seedlen = keylen + outlen` | 384 bits (48 bytes) | §10.2.1 |
| Resistência à segurança | 256 bits | Tabela 3 |
| Limite de reseed (`reseed_interval`) | 1.000.000 requests | Tabela 3 |
| `prediction_resistance_flag` | Não suportado | §10.2.1 |
| Derivation function | Não utilizada | §10.2.1.2 |

## 3. Estado Interno

O estado interno do DRBG consiste em:

```
working_state = {
    Key : array de 32 bytes   // chave AES-256 atual
    V   : array de 16 bytes   // contador big-endian de 128 bits
}
```

O estado é mantido em memória protegida (zeroed on reseed) e nunca exposto via API externa. O campo `outputBytes` é um contador atômico usado para acionar reseed automático.

## 4. Algoritmo CTR_DRBG_Update

Executa a atualização do estado após cada operação Generate ou Reseed.

**Entrada:** `provided_data` (48 bytes, ou zeros se nil)  
**Estado antes:** `{Key, V}`  
**Estado depois:** `{Key', V'}`

```
temp = nil
para i = 1 até 3:
    V = V + 1  (incremento big-endian de 128 bits, sem overflow wraparound)
    output_block = AES_256_encrypt(Key, V)
    temp = temp || output_block
temp[0..47] = temp[0..47] XOR provided_data
Key = temp[0..31]
V   = temp[32..47]
```

**Resultado:** estado atualizado `{Key', V'}` com os novos 48 bytes.

## 5. Instanciação (New)

```
Entradas: entropy_input (48 bytes full-entropy)
Saída:    estado inicial {Key, V}

Key = 0x00...00  (32 zeros)
V   = 0x00...00  (16 zeros)
seed_material = entropy_input XOR 0x00...00
               = entropy_input
{Key, V} = CTR_DRBG_Update(seed_material, Key, V)
```

## 6. Geração (Generate)

```
Entradas: requested_number_of_bytes (n)
Saída:    pseudo_random_bytes (n bytes), ou erro se reseed necessário

Se outputBytes >= reseed_interval: retornar ErrReseedRequired

temp = nil
enquanto len(temp) < n:
    V = V + 1
    output_block = AES_256_encrypt(Key, V)
    temp = temp || output_block

returned_bits = temp[0..n-1]
{Key, V} = CTR_DRBG_Update(nil, Key, V)   // forward secrecy
outputBytes += n
retornar returned_bits
```

A chamada final `CTR_DRBG_Update(nil)` garante **forward secrecy**: o comprometimento do estado `{Key, V}` após a geração não revela os bytes retornados, pois estes foram produzidos com o estado anterior.

## 7. Reseed (Reseed)

```
Entradas: entropy_input (48 bytes)
seed_material = entropy_input XOR 0x00...00
               = entropy_input
{Key, V} = CTR_DRBG_Update(seed_material, Key, V)
outputBytes = 0
```

## 8. Incremento do Contador V

O contador `V` é um inteiro big-endian de 128 bits. O incremento é:

```
para i = 15 até 0 (byte mais significativo por último):
    V[i] = V[i] + 1
    se V[i] != 0: parar  // sem overflow neste byte
// overflow: V retorna a 0 (wraparound natural de 128 bits)
```

O período do gerador é `2^128` blocos × 16 bytes = `2^132` bytes antes do wrap.

## 9. Health Check

O `HealthCheck()` gera 32 bytes internamente (sem expor) e verifica que:
1. Não há erro na geração
2. Todos os bytes não são zero (detector de saída constante)

Este teste é executado no startup e pode ser chamado periodicamente.

## 10. Comparação com o Padrão

| Requisito NIST SP 800-90A Rev.1 | Status |
|---|---|
| Algoritmo de bloco: AES | ✓ AES-256 |
| `outlen` = 128 bits | ✓ |
| `keylen` = 256 bits | ✓ |
| `seedlen` = 384 bits | ✓ |
| CTR_DRBG_Update após Generate | ✓ |
| Limite de reseed ≤ 2^48 requests | ✓ (1.000.000 << 2^48) |
| Zeroização do estado após reseed | ✓ |
| Estado interno não exposto | ✓ |
| Forward secrecy via Update pós-Generate | ✓ |

## 11. Código-Fonte de Referência

Arquivo: `internal/csprng/aes_ctr_drbg.go`

Funções principais:
- `New(entropy []byte) (*DRBG, error)` — instanciação
- `Generate(n uint64) ([]byte, error)` — geração
- `Reseed(entropy []byte) error` — reseed
- `updateLocked(provided []byte) error` — CTR_DRBG_Update
- `increment(v *[16]byte)` — incremento big-endian de V
- `HealthCheck() error` — verificação de saúde
