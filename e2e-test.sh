#!/usr/bin/env bash
set -euo pipefail

# --- Config ---
PSK=$(openssl rand -hex 32)
SERVER_PORT=19000
SOCKS_PORT=11080
SERVER_ADDR="127.0.0.1:${SERVER_PORT}"
SOCKS_ADDR="127.0.0.1:${SOCKS_PORT}"
TIMEOUT=10

# Detect platform binaries.
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "win32" ]]; then
    SUFFIX=".exe"
else
    SUFFIX=""
fi

ARCH=$(go env GOARCH)
OS=$(go env GOOS)
CLIENT="dist/chameleon-client-${OS}-${ARCH}${SUFFIX}"
SERVER="dist/chameleon-server-${OS}-${ARCH}${SUFFIX}"

if [ ! -f "$CLIENT" ] || [ ! -f "$SERVER" ]; then
    echo "Error: binaries not found. Run build.sh first."
    echo "  Expected: $CLIENT"
    echo "  Expected: $SERVER"
    exit 1
fi

# --- Cleanup on exit ---
PIDS=()
cleanup() {
    echo ""
    echo "Cleaning up..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
}
trap cleanup EXIT

# --- Start server ---
echo "=== E2E Test ==="
echo "PSK: ${PSK}"
echo ""

echo "Starting server on ${SERVER_ADDR}..."
"$SERVER" -listen ":${SERVER_PORT}" -psk "$PSK" -log debug &
PIDS+=($!)
sleep 1

# --- Start client ---
echo "Starting client (SOCKS5 on ${SOCKS_ADDR})..."
"$CLIENT" -server "$SERVER_ADDR" -socks "$SOCKS_ADDR" -psk "$PSK" -log debug &
PIDS+=($!)
sleep 1

# --- Tests ---
FAIL=0

run_test() {
    local name="$1"
    local url="$2"
    local expect="$3"

    echo ""
    echo "--- Test: ${name} ---"
    BODY=$(curl -s --max-time "$TIMEOUT" --socks5 "$SOCKS_ADDR" "$url" 2>&1) || {
        echo "FAIL: curl error"
        FAIL=1
        return
    }

    if echo "$BODY" | grep -q "$expect"; then
        echo "PASS"
    else
        echo "FAIL: expected '${expect}' in response"
        echo "Got: ${BODY:0:200}"
        FAIL=1
    fi
}

# Test 1: HTTP (plaintext).
run_test "HTTP GET (example.com)" \
    "http://example.com" \
    "Example Domain"

# Test 2: HTTPS.
run_test "HTTPS GET (example.com)" \
    "https://example.com" \
    "Example Domain"

# Test 3: HTTP with headers.
echo ""
echo "--- Test: HTTP headers ---"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$TIMEOUT" \
    --socks5 "$SOCKS_ADDR" "https://httpbin.org/get" 2>&1) || {
    echo "FAIL: curl error"
    FAIL=1
}
if [ "$STATUS" = "200" ]; then
    echo "PASS (HTTP 200)"
else
    echo "FAIL: got HTTP ${STATUS}"
    FAIL=1
fi

# Test 4: Download a file and verify size.
echo ""
echo "--- Test: File download ---"
TMPFILE=$(mktemp)
curl -s --max-time "$TIMEOUT" --socks5 "$SOCKS_ADDR" \
    "https://www.google.com/robots.txt" -o "$TMPFILE" 2>&1 || {
    echo "FAIL: curl error"
    FAIL=1
}
SIZE=$(wc -c < "$TMPFILE")
rm -f "$TMPFILE"
if [ "$SIZE" -gt 100 ]; then
    echo "PASS (downloaded ${SIZE} bytes)"
else
    echo "FAIL: file too small (${SIZE} bytes)"
    FAIL=1
fi

# --- Result ---
echo ""
echo "========================"
if [ $FAIL -eq 0 ]; then
    echo "=== All E2E tests passed ==="
else
    echo "=== Some E2E tests FAILED ==="
    exit 1
fi
