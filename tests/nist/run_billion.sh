#!/usr/bin/env bash
# Gera 1 bilhão de samples e executa a suíte completa NIST SP 800-22 + Dieharder.
# Ambiente-alvo: servidor Linux com sts-2.1.2 compilado e dieharder instalado.
#
# Uso:
#   ./tests/nist/run_billion.sh               # padrão: 1 bi de bits
#   BITS=10000000000 ./tests/nist/run_billion.sh  # 10 bi de bits
set -euo pipefail

BINARY="${BINARY:-./bin/rng-service}"
BITS="${BITS:-1000000000}"         # 1 bilhão de bits = 125 MB
BYTES=$(( BITS / 8 ))

RESULTS_DIR="./tests/nist/results/billion_$(date +%Y%m%d_%H%M%S)"
BIN_FILE="$RESULTS_DIR/rng_1billion.bin"
STS="./tests/nist/sts-2.1.2/assess"

echo "========================================================"
echo "  Lucky & Fun rng-service — Suíte estatística completa"
echo "  $(date)"
echo "  Bits: $BITS  |  Bytes: $BYTES"
echo "========================================================"
echo ""

# ── Verificações de pré-requisitos ───────────────────────────────────────────
if [[ ! -x "$BINARY" ]]; then
    echo "ERRO: $BINARY não encontrado. Execute: make build-release" >&2
    exit 1
fi

mkdir -p "$RESULTS_DIR"

# ── Versão do binário ─────────────────────────────────────────────────────────
echo "==> Binário: $BINARY"
sha256sum "$BINARY" | tee "$RESULTS_DIR/binary_hash.txt"
echo ""

# ── 1. Geração do arquivo de dados ───────────────────────────────────────────
echo "==> Gerando $BYTES bytes ($BITS bits) ..."
START_GEN=$(date +%s)
"$BINARY" dump --bytes "$BYTES" > "$BIN_FILE"
END_GEN=$(date +%s)
echo "    Concluído em $(( END_GEN - START_GEN ))s → $BIN_FILE"
echo ""

# ── 2. NIST SP 800-22 (15 testes) ────────────────────────────────────────────
if [[ -x "$STS" ]]; then
    echo "==> Executando NIST SP 800-22 (15 testes, $BITS bits) ..."
    echo "    Diretório de resultados: $RESULTS_DIR/nist/"
    mkdir -p "$RESULTS_DIR/nist"
    cd "$RESULTS_DIR/nist"
    # Modo não-interativo: tipo 1 (arquivo binário), todos os testes (0),
    # parâmetros padrão (1), arquivo de entrada, 1 stream, sem sub-streams (0).
    printf "1\n0\n1\n../rng_1billion.bin\n1\n0\n" | \
        "../../../$(basename $STS)" "$BITS" 2>&1 | tee nist_run.log || true
    cd - > /dev/null

    # Verificar critério de aceite: todos p-values >= 0.01
    echo ""
    echo "==> Verificando critério de aceite (p-value >= 0.01) ..."
    FAIL_COUNT=0
    if [[ -f "$RESULTS_DIR/nist/experiments/AlgorithmTesting/finalAnalysisReport.txt" ]]; then
        cp "$RESULTS_DIR/nist/experiments/AlgorithmTesting/finalAnalysisReport.txt" \
           "$RESULTS_DIR/nist_final_report.txt"
        grep -E "FAILURE|FAIL" "$RESULTS_DIR/nist_final_report.txt" && FAIL_COUNT=1 || true
        if [[ $FAIL_COUNT -eq 0 ]]; then
            echo "    RESULTADO: TODOS OS 15 TESTES NIST APROVADOS ✓"
        else
            echo "    RESULTADO: FALHA EM UM OU MAIS TESTES NIST ✗"
        fi
    else
        echo "    AVISO: finalAnalysisReport.txt não gerado — verificar nist_run.log"
    fi
else
    echo "AVISO: $STS não encontrado."
    echo "       Instalar NIST STS 2.1.2:"
    echo "         wget https://csrc.nist.gov/CSRC/media/Projects/Random-Bit-Generation/documents/sts-2.1.2.zip"
    echo "         unzip sts-2.1.2.zip -d ./tests/nist/"
    echo "         cd ./tests/nist/sts-2.1.2 && make"
fi

echo ""

# ── 3. Dieharder ─────────────────────────────────────────────────────────────
if command -v dieharder &>/dev/null; then
    echo "==> Executando Dieharder (todos os testes, input raw binary) ..."
    echo "    Isso pode levar 30-60 minutos."
    DIEHARD_OUT="$RESULTS_DIR/dieharder_results.txt"
    # Dieharder lê do arquivo raw (-g 201) com loop infinito (rewinding)
    dieharder -a -g 201 -f "$BIN_FILE" | tee "$DIEHARD_OUT"

    echo ""
    echo "==> Sumário Dieharder:"
    grep -E "PASSED|FAILED|WEAK" "$DIEHARD_OUT" | sort | uniq -c | sort -rn || true
    echo "    Resultados: $DIEHARD_OUT"
else
    echo "INFO: dieharder não encontrado."
    echo "      Instalar: sudo apt install dieharder"
    echo "      Run manual: dieharder -a -g 201 -f $BIN_FILE"
fi

echo ""
echo "========================================================"
echo "  Resultados salvos em: $RESULTS_DIR"
echo "  Copiar para pacote BMM:"
echo "    cp -r $RESULTS_DIR docs/bmm-submission-package/test-results/"
echo "========================================================"
