#!/usr/bin/env bash
set -euo pipefail

TIMEOUT="${TIMEOUT:-60s}"
VERBOSE="${VERBOSE:-}"

args=("-count=1" "-timeout=$TIMEOUT")
if [ -n "$VERBOSE" ]; then
    args+=("-v")
fi

echo "=== Running tests ==="
echo ""

# Vet first.
echo "--- go vet ---"
go vet ./...
echo "OK"
echo ""

# Unit tests per package.
packages=(
    "genome/internal/randutil"
    "genome/crypto"
    "genome/morph"
    "genome/mux"
    "genome/transport"
    "genome/socks5"
)

fail=0
for pkg in "${packages[@]}"; do
    echo "--- ${pkg} ---"
    if go test "${args[@]}" "$pkg"; then
        echo ""
    else
        fail=1
        echo "FAILED"
        echo ""
    fi
done

# Integration tests.
echo "--- genome/proxy (integration) ---"
if go test "${args[@]}" "genome/proxy"; then
    echo ""
else
    fail=1
    echo "FAILED"
    echo ""
fi

# Race detector (shorter timeout, only critical packages).
echo "--- Race detector ---"
if CGO_ENABLED=1 go test -race -count=1 -timeout="$TIMEOUT" \
    genome/mux genome/transport genome/proxy 2>&1; then
    echo "OK"
else
    # Race detector may be unavailable (no C compiler, CGO disabled).
    if ! go env CC >/dev/null 2>&1 || [ "$(go env CGO_ENABLED)" = "0" ]; then
        echo "SKIPPED (no C compiler / CGO unavailable)"
    else
        fail=1
        echo "Race detector FAILED"
    fi
fi

echo ""
if [ $fail -eq 0 ]; then
    echo "=== All tests passed ==="
else
    echo "=== Some tests FAILED ==="
    exit 1
fi
