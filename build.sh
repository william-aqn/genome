#!/usr/bin/env bash
set -euo pipefail

VERSION="${VERSION:-dev}"
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS="-X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildTime=${BUILD_TIME}"

OUT_DIR="dist"
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

TARGETS=(
    "linux/amd64"
    "linux/arm64"
    "windows/amd64"
    "windows/arm64"
)

for target in "${TARGETS[@]}"; do
    GOOS="${target%/*}"
    GOARCH="${target#*/}"
    suffix=""
    if [ "$GOOS" = "windows" ]; then
        suffix=".exe"
    fi

    echo "Building ${GOOS}/${GOARCH}..."

    GOOS=$GOOS GOARCH=$GOARCH go build -ldflags "$LDFLAGS" -trimpath \
        -o "${OUT_DIR}/chameleon-client-${GOOS}-${GOARCH}${suffix}" ./cmd/client

    GOOS=$GOOS GOARCH=$GOARCH go build -ldflags "$LDFLAGS" -trimpath \
        -o "${OUT_DIR}/chameleon-server-${GOOS}-${GOARCH}${suffix}" ./cmd/server
done

echo ""
echo "Build complete:"
ls -lh "$OUT_DIR"/
