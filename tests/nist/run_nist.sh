#!/usr/bin/env bash
# Run NIST SP 800-22 and dieharder statistical tests against rng-service output.
#
# Requirements:
#   - rng-service binary built: make build
#   - NIST STS 2.1.2: https://csrc.nist.gov/projects/random-bit-generation
#     Compile and place the 'assess' binary at: ./tests/nist/sts-2.1.2/assess
#   - dieharder (optional): sudo apt install dieharder
#
# Sprint 1 acceptance: all 15 NIST tests must pass with p-value > 0.01.
set -euo pipefail

BINARY="${BINARY:-./bin/rng-service}"
BITS="${BITS:-1000000}"   # 1 million bits (NIST minimum)
BYTES=$(( BITS / 8 ))

TMPDIR="${TMPDIR:-/tmp}"
BIN_FILE="$TMPDIR/rng_nist_input.bin"
RESULTS_DIR="./tests/nist/results"

# ---------------------------------------------------------------------------
# 1. Verify binary exists
# ---------------------------------------------------------------------------
if [[ ! -x "$BINARY" ]]; then
    echo "ERROR: $BINARY not found. Run: make build" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# 2. Generate random data
# ---------------------------------------------------------------------------
echo "==> Generating $BYTES bytes ($BITS bits) from $BINARY ..."
"$BINARY" dump --bytes "$BYTES" > "$BIN_FILE"
echo "    Written to $BIN_FILE"

# ---------------------------------------------------------------------------
# 3. NIST SP 800-22 (Statistical Test Suite 2.1.2)
# ---------------------------------------------------------------------------
STS="./tests/nist/sts-2.1.2/assess"

if [[ -x "$STS" ]]; then
    echo ""
    echo "==> Running NIST SP 800-22 (15 tests) ..."
    echo "    Bit stream length: $BITS"
    echo ""

    mkdir -p "$RESULTS_DIR"
    # STS reads a binary file when invoked with: assess <bits> < input_file
    # The tool is interactive; pipe the choices: input type 1 (binary file),
    # run all tests (0), use default parameters, stream count 1.
    printf "1\n0\n1\n$BIN_FILE\n1\n0\n" | "$STS" "$BITS" || true

    echo ""
    echo "==> NIST results written to: experiments/AlgorithmTesting/"
    echo "    Check finalAnalysisReport.txt for p-values."
    echo "    Acceptance criterion: p-value > 0.01 for all 15 tests."
else
    echo ""
    echo "INFO: NIST STS binary not found at $STS."
    echo "      To install:"
    echo "        wget https://csrc.nist.gov/CSRC/media/Projects/Random-Bit-Generation/documents/sts-2.1.2.zip"
    echo "        unzip sts-2.1.2.zip -d ./tests/nist/"
    echo "        cd ./tests/nist/sts-2.1.2 && make"
    echo ""
    echo "      Manual run after install:"
    echo "        cd tests/nist/sts-2.1.2 && ./assess $BITS"
    echo "        (choose: file input → select $BIN_FILE → run all 15 tests)"
fi

# ---------------------------------------------------------------------------
# 4. Dieharder (optional)
# ---------------------------------------------------------------------------
echo ""
if command -v dieharder &>/dev/null; then
    echo "==> Running dieharder (all tests, raw binary input) ..."
    echo "    This may take several minutes."
    "$BINARY" dump --bytes 0 | dieharder -a -g 200 | tee "$RESULTS_DIR/dieharder_$(date +%Y%m%d_%H%M%S).txt"
    echo "==> dieharder complete."
else
    echo "INFO: dieharder not found. To install: sudo apt install dieharder"
    echo "      Manual run: $BINARY dump --bytes 0 | dieharder -a -g 200"
fi

echo ""
echo "==> Done. Data file: $BIN_FILE"
