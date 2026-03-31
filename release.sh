#!/usr/bin/env bash
#
# Build binaries and create a GitHub release.
#
# Usage:
#   ./release.sh v0.1.0
#   ./release.sh v0.1.0 --draft
#
set -euo pipefail

VERSION="${1:?Usage: $0 <version-tag> [--draft]}"
DRAFT=""
if [[ "${2:-}" == "--draft" ]]; then
    DRAFT="--draft"
fi

# --- Preflight ---
command -v go >/dev/null  || { echo "Error: go not found"; exit 1; }
command -v gh >/dev/null  || { echo "Error: gh not found. Install: https://cli.github.com"; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "Error: not logged in. Run: gh auth login"; exit 1; }

echo "=== Building ${VERSION} ==="

# --- Build ---
export VERSION
bash build.sh

# --- Tag ---
if git rev-parse "$VERSION" >/dev/null 2>&1; then
    echo "Tag ${VERSION} already exists, using it."
else
    echo "Creating tag ${VERSION}..."
    git tag "$VERSION"
    git push origin "$VERSION"
fi

# --- Release ---
echo ""
echo "Creating GitHub release..."

NOTES="## Chameleon ${VERSION}

### Install (Linux server, one line)
\`\`\`bash
curl -sSL https://raw.githubusercontent.com/william-aqn/genome/main/install-server.sh | sudo bash
\`\`\`

### Binaries
| File | OS | Arch |
|------|----|------|
| chameleon-client-linux-amd64 | Linux | x86_64 |
| chameleon-client-linux-arm64 | Linux | ARM64 |
| chameleon-client-windows-amd64.exe | Windows | x86_64 |
| chameleon-client-windows-arm64.exe | Windows | ARM64 |
| chameleon-server-linux-amd64 | Linux | x86_64 |
| chameleon-server-linux-arm64 | Linux | ARM64 |
| chameleon-server-windows-amd64.exe | Windows | x86_64 |
| chameleon-server-windows-arm64.exe | Windows | ARM64 |
"

gh release create "$VERSION" \
    --title "Chameleon ${VERSION}" \
    --notes "$NOTES" \
    $DRAFT \
    dist/*

echo ""
echo "=== Release ${VERSION} published ==="
echo "https://github.com/william-aqn/genome/releases/tag/${VERSION}"
