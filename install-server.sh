#!/usr/bin/env bash
#
# Chameleon server — one-line install:
#   curl -sSL https://raw.githubusercontent.com/USER/genome/main/install-server.sh | bash
#
# Or with custom port:
#   curl -sSL ... | bash -s -- --port 443
#
set -euo pipefail

INSTALLER_VERSION="0.1.1"
echo "Chameleon installer v${INSTALLER_VERSION}"
echo ""

# --- Defaults ---
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/chameleon"
SERVICE_NAME="chameleon-server"
PORT=$(shuf -i 10000-59999 -n 1)
REPO="william-aqn/genome"

# --- Parse args ---
while [[ $# -gt 0 ]]; do
    case $1 in
        --port)  PORT="$2"; shift 2 ;;
        --dir)   INSTALL_DIR="$2"; shift 2 ;;
        --repo)  REPO="$2"; shift 2 ;;
        *)       echo "Unknown option: $1"; exit 1 ;;
    esac
done

# --- Helpers ---
info()  { echo -e "\033[1;32m>>>\033[0m $*"; }
warn()  { echo -e "\033[1;33m>>>\033[0m $*"; }
fail()  { echo -e "\033[1;31m>>>\033[0m $*"; exit 1; }

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "'$1' is required but not found."
}

# --- Detect arch ---
detect_arch() {
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64)  echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        *) fail "Unsupported architecture: $arch" ;;
    esac
}

# --- Detect init system ---
has_systemd() {
    [ -d /run/systemd/system ] 2>/dev/null
}

# --- Check root ---
if [ "$(id -u)" -ne 0 ]; then
    fail "Run as root: curl -sSL ... | sudo bash"
fi

need_cmd curl
need_cmd openssl

ARCH=$(detect_arch)
info "Detected architecture: linux/${ARCH}"

# --- Detect existing installation ---
BINARY_NAME="chameleon-server-linux-${ARCH}"
BINARY_URL="https://github.com/${REPO}/releases/latest/download/${BINARY_NAME}"
BINARY_PATH="${INSTALL_DIR}/${SERVICE_NAME}"
IS_UPGRADE=false

if [ -f "${BINARY_PATH}" ] && [ -f "${CONFIG_DIR}/psk" ]; then
    IS_UPGRADE=true
    info "Existing installation detected — upgrading binary only."
fi

# --- Download binary ---
download_binary() {
    info "Downloading ${BINARY_NAME}..."

    # Method 1: GitHub release direct URL.
    if curl -fSL --max-time 30 -o "${BINARY_PATH}" "${BINARY_URL}" 2>&1; then
        chmod +x "${BINARY_PATH}"
        info "Installed to ${BINARY_PATH}"
        return
    fi
    warn "Method 1 (release URL) failed."

    # Method 2: GitHub API — get asset ID, download with Accept: octet-stream.
    # This bypasses the browser_download_url redirect chain entirely.
    info "Trying GitHub API direct download..."
    API_URL="https://api.github.com/repos/${REPO}/releases/latest"
    ASSET_ID=$(curl -fsSL --max-time 10 "$API_URL" 2>/dev/null \
        | grep -B3 "\"name\": \"${BINARY_NAME}\"" \
        | grep '"id"' | head -1 \
        | grep -o '[0-9]*' || true)
    if [ -n "$ASSET_ID" ]; then
        info "Asset ID: ${ASSET_ID}"
        if curl -fSL --max-time 30 \
            -H "Accept: application/octet-stream" \
            -o "${BINARY_PATH}" \
            "https://api.github.com/repos/${REPO}/releases/assets/${ASSET_ID}" 2>&1; then
            chmod +x "${BINARY_PATH}"
            info "Installed to ${BINARY_PATH}"
            return
        fi
        warn "Method 2 (API octet-stream) failed."
    else
        warn "Method 2: could not resolve asset ID."
    fi

    # Method 3: Download source tarball and build.
    if command -v go >/dev/null 2>&1; then
        warn "Downloading source and building..."
        BUILD_TMP=$(mktemp -d)
        trap "rm -rf ${BUILD_TMP}" EXIT
        TARBALL="https://api.github.com/repos/${REPO}/tarball"
        if curl -fsSL --max-time 30 "$TARBALL" | tar xz -C "${BUILD_TMP}" 2>/dev/null; then
            cd "${BUILD_TMP}"/*
            info "Building from source..."
            go build -trimpath -o "${BINARY_PATH}" ./cmd/server
            chmod +x "${BINARY_PATH}"
            cd /
            info "Built and installed to ${BINARY_PATH}"
            return
        fi
        warn "Method 3 (source build) failed."
    fi

    echo ""
    fail "All download methods failed. Upload the binary manually:\n\n" \
         "  scp chameleon-server-linux-amd64 root@THIS_SERVER:${BINARY_PATH}\n\n" \
         "  Then re-run this script."
}
download_binary

# --- Upgrade: restart and exit early ---
if [ "$IS_UPGRADE" = true ]; then
    PSK=$(cat "${CONFIG_DIR}/psk")
    # Read port from existing config.
    if [ -f "${CONFIG_DIR}/server.json" ]; then
        PORT=$(grep -o '"listen_addr"[^"]*":[0-9]*"' "${CONFIG_DIR}/server.json" | grep -o '[0-9]*' || echo "$PORT")
    fi
    if has_systemd && systemctl is-enabled --quiet "${SERVICE_NAME}" 2>/dev/null; then
        systemctl restart "${SERVICE_NAME}"
        sleep 1
        if systemctl is-active --quiet "${SERVICE_NAME}"; then
            info "Service restarted with new binary!"
        else
            warn "Restart may have failed. Check: journalctl -u ${SERVICE_NAME}"
        fi
    else
        warn "Restart the server manually to use the new binary."
    fi
    EXTERNAL_IP=$(curl -4 -s --max-time 5 https://ifconfig.me 2>/dev/null \
               || curl -4 -s --max-time 5 https://api.ipify.org 2>/dev/null \
               || hostname -I 2>/dev/null | awk '{print $1}' \
               || echo "YOUR_SERVER_IP")
    echo ""
    echo "=============================================="
    echo "  Chameleon server upgraded!"
    echo "=============================================="
    echo ""
    echo "  Server:  ${EXTERNAL_IP}:${PORT}"
    echo "  PSK:     ${PSK}"
    echo "  Binary:  ${BINARY_PATH}"
    echo "=============================================="
    exit 0
fi

# --- Generate PSK ---
mkdir -p "${CONFIG_DIR}"
PSK_FILE="${CONFIG_DIR}/psk"

if [ -f "$PSK_FILE" ]; then
    info "PSK already exists at ${PSK_FILE}, keeping it."
    PSK=$(cat "$PSK_FILE")
else
    PSK=$(openssl rand -hex 32)
    echo "$PSK" > "$PSK_FILE"
    chmod 600 "$PSK_FILE"
    info "Generated PSK → ${PSK_FILE}"
fi

# --- Write config ---
CONFIG_FILE="${CONFIG_DIR}/server.json"
cat > "$CONFIG_FILE" <<EOF
{
  "psk": "${PSK}",
  "listen_addr": ":${PORT}",
  "cipher_suite": "chacha20",
  "log_level": "info",
  "idle_timeout_sec": 300
}
EOF
chmod 600 "$CONFIG_FILE"
info "Config → ${CONFIG_FILE}"

# --- Firewall ---
open_firewall() {
    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "active"; then
        info "Opening UDP port ${PORT} in ufw..."
        ufw allow "${PORT}/udp" >/dev/null
    elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
        info "Opening UDP port ${PORT} in firewalld..."
        firewall-cmd --permanent --add-port="${PORT}/udp" >/dev/null
        firewall-cmd --reload >/dev/null
    elif command -v iptables >/dev/null 2>&1; then
        # Only add if rule doesn't already exist.
        if ! iptables -C INPUT -p udp --dport "${PORT}" -j ACCEPT 2>/dev/null; then
            info "Opening UDP port ${PORT} in iptables..."
            iptables -A INPUT -p udp --dport "${PORT}" -j ACCEPT
            # Persist if possible.
            if command -v netfilter-persistent >/dev/null 2>&1; then
                netfilter-persistent save 2>/dev/null || true
            elif command -v iptables-save >/dev/null 2>&1 && [ -d /etc/iptables ]; then
                iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
            fi
        fi
    else
        warn "No firewall manager found. Make sure UDP port ${PORT} is open."
    fi
}
open_firewall

# --- Systemd service ---
if has_systemd; then
    info "Installing systemd service..."
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=Chameleon Tunnel Server
After=network.target

[Service]
Type=simple
ExecStart=${BINARY_PATH} -config ${CONFIG_FILE}
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "${SERVICE_NAME}"
    systemctl restart "${SERVICE_NAME}"

    sleep 1
    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        info "Service running!"
    else
        warn "Service may have failed to start. Check: journalctl -u ${SERVICE_NAME}"
    fi
else
    warn "systemd not found. Start manually:"
    echo "  ${BINARY_PATH} -config ${CONFIG_FILE}"
fi

# --- Detect external IP ---
EXTERNAL_IP=$(curl -4 -s --max-time 5 https://ifconfig.me 2>/dev/null \
           || curl -4 -s --max-time 5 https://api.ipify.org 2>/dev/null \
           || hostname -I 2>/dev/null | awk '{print $1}' \
           || echo "YOUR_SERVER_IP")

# --- Print instructions ---
echo ""
echo "=============================================="
echo "  Chameleon server installed successfully!"
echo "=============================================="
echo ""
echo "  Server:  ${EXTERNAL_IP}:${PORT}"
echo "  PSK:     ${PSK}"
echo ""
echo "  --- Client connection ---"
echo ""
echo "  Option 1: CLI flags"
echo "    ./chameleon-client -server ${EXTERNAL_IP}:${PORT} -psk ${PSK}"
echo ""
echo "  Option 2: Config file (client.json):"
echo "    {"
echo "      \"psk\": \"${PSK}\","
echo "      \"listen_addr\": \":0\","
echo "      \"peer_addr\": \"${EXTERNAL_IP}:${PORT}\","
echo "      \"socks_addr\": \"127.0.0.1:1080\""
echo "    }"
echo "    ./chameleon-client -config client.json"
echo ""
echo "  Then use any app:"
echo "    curl --socks5 127.0.0.1:1080 https://example.com"
echo ""
if has_systemd; then
echo "  --- Manage service ---"
echo "    systemctl status  ${SERVICE_NAME}"
echo "    systemctl stop    ${SERVICE_NAME}"
echo "    systemctl restart ${SERVICE_NAME}"
echo "    journalctl -u ${SERVICE_NAME} -f"
echo ""
fi
echo "  Config:  ${CONFIG_FILE}"
echo "  PSK:     ${PSK_FILE}"
echo "  Binary:  ${BINARY_PATH}"
echo "=============================================="
