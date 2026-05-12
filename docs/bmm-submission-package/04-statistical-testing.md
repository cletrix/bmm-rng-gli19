# Testes Estatísticos — Metodologia e Resultados

---

## 1. Suíte de Testes

### 1.1 NIST SP 800-22 Rev.1a (15 testes)

**Referência:** NIST SP 800-22 Rev.1a, "A Statistical Test Suite for Random and Pseudorandom Number Generators for Cryptographic Applications"  
**Ferramenta:** NIST Statistical Test Suite (STS) versão 2.1.2

Os 15 testes e seus critérios de aceite (p-value ≥ 0.01):

| # | Teste | Seção NIST | Hipótese nula |
|---|---|---|---|
| 1 | Frequency (Monobit) | §2.1 | Proporção de 0s e 1s é ~50% |
| 2 | Block Frequency | §2.2 | Proporção de 1s por bloco de M bits é ~50% |
| 3 | Runs | §2.3 | Comprimento e número de runs compatíveis com aleatoriedade |
| 4 | Longest Run of Ones in a Block | §2.4 | Comprimento max de runs de 1 por bloco |
| 5 | Binary Matrix Rank | §2.5 | Rank de submatrizes binárias |
| 6 | Discrete Fourier Transform | §2.6 | Picos no espectro de potência < limite esperado |
| 7 | Non-overlapping Template Matching | §2.7 | Ocorrências de padrões específicos |
| 8 | Overlapping Template Matching | §2.8 | Ocorrências com janela deslizante |
| 9 | Maurer's Universal Statistical | §2.9 | Entropia por bit da sequência |
| 10 | Linear Complexity | §2.10 | Complexidade linear de subsequências |
| 11 | Serial | §2.11 | Frequências de padrões de m bits |
| 12 | Approximate Entropy | §2.12 | Entropia de blocos sobrepostos |
| 13 | Cumulative Sums | §2.13 | Máxima excursão da soma cumulativa |
| 14 | Random Excursions | §2.14 | Distribuição de visitas em caminhada aleatória |
| 15 | Random Excursions Variant | §2.15 | Variante com mais estados |

**Critério de aceite BMM:** p-value ≥ 0.01 em todos os 15 testes.  
**Critério de alerta (self-test contínuo):** p-value < 0.01 ou > 0.999.

### 1.2 Dieharder

**Ferramenta:** dieharder versão 3.31.1+  
**Origem:** Extensão da suíte Diehard de G. Marsaglia

Dieharder inclui os testes originais de Marsaglia (Diehard) mais testes adicionais, totalizando ~100 testes. É complementar ao NIST STS, com maior sensibilidade a correlações de longa distância.

**Critério de aceite:** ≥ 95% dos testes com p-value ∈ (0.005, 0.995). Resultados "WEAK" são aceitáveis em quantidade ≤ 5%.

## 2. Parâmetros de Teste

### 2.1 NIST SP 800-22 (suíte completa — submissão BMM)

```
Bits testados:       1.000.000.000 (1 bilhão)
Arquivo de entrada:  binário raw (MSB-first)
Streams:             1 (sequência contínua)
```

### 2.2 NIST SP 800-22 (self-test contínuo em produção)

```
Testes executados:   Frequency, Block Frequency, Runs (3 de 15)
Bits por execução:   10.000 (configurável via RNG_SELFTEST_SAMPLE_SIZE)
Frequência:          A cada 1 hora (configurável via RNG_SELFTEST_INTERVAL)
Critério de alerta:  p-value < 0.001 → CRITICAL; < 0.01 → WARNING
```

## 3. Como Executar os Testes

### 3.1 Build do binário de teste

```bash
# Requer Linux com sts-2.1.2 compilado e dieharder instalado
make build-release
```

### 3.2 Suíte completa (1 bilhão de bits)

```bash
# Instalar NIST STS
wget https://csrc.nist.gov/CSRC/media/Projects/Random-Bit-Generation/documents/sts-2.1.2.zip
unzip sts-2.1.2.zip -d ./tests/nist/
cd ./tests/nist/sts-2.1.2 && make && cd -

# Instalar dieharder (Debian/Ubuntu)
sudo apt install dieharder

# Executar suíte completa
./tests/nist/run_billion.sh
```

### 3.3 Teste rápido (1 milhão de bits — desenvolvimento)

```bash
./tests/nist/run_nist.sh
```

### 3.4 Self-test contínuo em produção

```bash
# Via endpoint de health (retorna os 3 p-values mais recentes)
curl http://localhost:8080/v1/health | jq .nist_selftest

# Via Prometheus
curl http://localhost:9090/metrics | grep rng_nist
```

## 4. Resultados dos Testes Estatísticos

> **Nota:** Esta seção deve ser preenchida após a execução da suíte completa em ambiente de produção Linux. Os resultados devem ser obtidos e incluídos antes da submissão à BMM.

### 4.1 Resultado NIST SP 800-22 (1 bilhão de bits)

**Data de execução:** ___________  
**Versão do binário (SHA-256):** ___________  
**Sistema:** ___________  

| # | Teste | p-value | Resultado |
|---|---|---|---|
| 1 | Frequency (Monobit) | ________ | ⬜ PASS / ⬜ FAIL |
| 2 | Block Frequency | ________ | ⬜ PASS / ⬜ FAIL |
| 3 | Runs | ________ | ⬜ PASS / ⬜ FAIL |
| 4 | Longest Run | ________ | ⬜ PASS / ⬜ FAIL |
| 5 | Matrix Rank | ________ | ⬜ PASS / ⬜ FAIL |
| 6 | Spectral (DFT) | ________ | ⬜ PASS / ⬜ FAIL |
| 7 | Non-overlapping Templates | ________ | ⬜ PASS / ⬜ FAIL |
| 8 | Overlapping Templates | ________ | ⬜ PASS / ⬜ FAIL |
| 9 | Universal Statistical | ________ | ⬜ PASS / ⬜ FAIL |
| 10 | Linear Complexity | ________ | ⬜ PASS / ⬜ FAIL |
| 11 | Serial | ________ | ⬜ PASS / ⬜ FAIL |
| 12 | Approximate Entropy | ________ | ⬜ PASS / ⬜ FAIL |
| 13 | Cumulative Sums | ________ | ⬜ PASS / ⬜ FAIL |
| 14 | Random Excursions | ________ | ⬜ PASS / ⬜ FAIL |
| 15 | Random Excursions Variant | ________ | ⬜ PASS / ⬜ FAIL |

**Arquivo de resultados:** `test-results/billion_YYYYMMDD/nist_final_report.txt`

### 4.2 Resultado Dieharder

**Testes totais:** ___  **PASSED:** ___  **WEAK:** ___  **FAILED:** ___

**Arquivo de resultados:** `test-results/billion_YYYYMMDD/dieharder_results.txt`

## 5. Interpretação dos Resultados

Um p-value muito próximo de 1 (> 0.999) também é suspeito — indica que os dados são "bons demais para serem aleatórios" (possível constante ou contador). O self-test contínuo alerta nesse caso com `StatusWarnHigh`.

O RTP (Return to Player) dos jogos não é determinado pelo RNG — o RNG gera números uniformes em `[min, max]` e a lógica de jogo determina o RTP. O RNG certifica apenas a uniformidade e imprevisibilidade dos outputs.
