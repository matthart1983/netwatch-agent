#!/bin/sh
set -e

# NetWatch Agent installer & updater
#
# Install:  curl -sSL <api-url>/install.sh | sudo sh -s -- --api-key KEY --endpoint URL
# Update:   curl -sSL <api-url>/install.sh | sudo sh -s -- --update
# Remove:   curl -sSL <api-url>/install.sh | sudo sh -s -- --remove

API_KEY=""
ENDPOINT=""
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/netwatch-agent"
DATA_DIR="/var/lib/netwatch-agent"
SERVICE_USER="netwatch"
SERVICE_GROUP="netwatch"
MODE="install"

find_nologin_shell() {
  for shell in /usr/sbin/nologin /sbin/nologin /bin/false; do
    if [ -x "$shell" ]; then
      echo "$shell"
      return 0
    fi
  done
  echo "/bin/false"
}

refresh_service_group() {
  if id "$SERVICE_USER" >/dev/null 2>&1; then
    SERVICE_GROUP=$(id -gn "$SERVICE_USER" 2>/dev/null || echo "$SERVICE_USER")
  fi
}

stop_service() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl stop netwatch-agent 2>/dev/null || true
  elif command -v rc-service >/dev/null 2>&1; then
    rc-service netwatch-agent stop 2>/dev/null || true
  fi
}

disable_service() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable netwatch-agent 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
  elif command -v rc-update >/dev/null 2>&1; then
    rc-update del netwatch-agent default 2>/dev/null || true
  fi
}

ensure_service_user() {
  if id "$SERVICE_USER" >/dev/null 2>&1; then
    refresh_service_group
    return 0
  fi

  echo "Creating service user '$SERVICE_USER' ..."
  NOLOGIN_SHELL=$(find_nologin_shell)

  if command -v useradd >/dev/null 2>&1; then
    useradd --system --no-create-home --shell "$NOLOGIN_SHELL" "$SERVICE_USER"
  elif command -v adduser >/dev/null 2>&1; then
    adduser -S -D -H -s "$NOLOGIN_SHELL" "$SERVICE_USER" 2>/dev/null \
      || adduser --system --disabled-password --no-create-home --shell "$NOLOGIN_SHELL" "$SERVICE_USER"
  else
    echo "Error: could not create service user. Install 'useradd' or 'adduser' and retry."
    exit 1
  fi

  refresh_service_group
}

install_systemd_unit() {
  cat > /etc/systemd/system/netwatch-agent.service <<EOF
[Unit]
Description=NetWatch Agent — network metrics collector
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/netwatch-agent
Restart=always
RestartSec=5
User=$SERVICE_USER
Group=$SERVICE_GROUP
EnvironmentFile=-$CONFIG_DIR/env

NoNewPrivileges=no
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$DATA_DIR
ReadOnlyPaths=$CONFIG_DIR /proc /sys
PrivateTmp=yes
AmbientCapabilities=CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable netwatch-agent
  systemctl start netwatch-agent
}

install_openrc_service() {
  cat > /etc/init.d/netwatch-agent <<EOF
#!/sbin/openrc-run
description="NetWatch Agent — network metrics collector"
command="$INSTALL_DIR/netwatch-agent"
command_user="$SERVICE_USER:$SERVICE_GROUP"
pidfile="/run/netwatch-agent.pid"
command_background="yes"

depend() {
  need net
}
EOF

  chmod +x /etc/init.d/netwatch-agent
  rc-update add netwatch-agent default
  rc-service netwatch-agent start
}

enable_and_start_service() {
  if command -v setcap >/dev/null 2>&1; then
    setcap cap_net_raw+ep "$INSTALL_DIR/netwatch-agent" 2>/dev/null || true
  fi

  if command -v systemctl >/dev/null 2>&1; then
    install_systemd_unit
  elif command -v rc-service >/dev/null 2>&1 && command -v rc-update >/dev/null 2>&1 && [ -d /etc/init.d ]; then
    install_openrc_service
  else
    echo "Error: supported service manager not found. systemd or OpenRC is required."
    echo "       Binary was installed to $INSTALL_DIR/netwatch-agent"
    echo "       Config was written to $CONFIG_DIR/config.toml"
    exit 1
  fi
}

# Parse args
while [ $# -gt 0 ]; do
  case $1 in
    --api-key)   API_KEY="$2"; shift 2 ;;
    --endpoint)  ENDPOINT="$2"; shift 2 ;;
    --update)    MODE="update"; shift ;;
    --remove)    MODE="remove"; shift ;;
    --help|-h)   MODE="help"; shift ;;
    *)           echo "Unknown option: $1"; exit 1 ;;
  esac
done

# ── Help ─────────────────────────────────────────────────
if [ "$MODE" = "help" ]; then
  echo "NetWatch Agent Installer"
  echo ""
  echo "INSTALL:"
  echo "  sudo ./install.sh --api-key YOUR_KEY --endpoint https://your-api/api/v1/ingest"
  echo ""
  echo "UPDATE (preserves config):"
  echo "  sudo ./install.sh --update"
  echo ""
  echo "REMOVE:"
  echo "  sudo ./install.sh --remove"
  exit 0
fi

# ── Remove ───────────────────────────────────────────────
if [ "$MODE" = "remove" ]; then
  echo "Removing NetWatch Agent..."
  stop_service
  disable_service
  rm -f /etc/systemd/system/netwatch-agent.service
  rm -f /etc/init.d/netwatch-agent
  rm -f "$INSTALL_DIR/netwatch-agent"
  rm -rf "$DATA_DIR"
  rm -rf "$CONFIG_DIR"
  echo "✅ Agent removed. Binary, config, and data directory all cleaned up."
  exit 0
fi

# ── Check root ───────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
  echo "Error: This script must be run as root (use sudo)"
  exit 1
fi

OS_NAME=$(uname -s)
if [ "$OS_NAME" = "Darwin" ]; then
  echo "Error: netwatch-agent service install is Linux-only."
  echo ""
  echo "For private macOS dev/debug support, build and run the agent locally instead:"
  echo "  cargo build --package netwatch-agent"
  echo "  ./target/debug/netwatch-agent setup"
  echo "  ./target/debug/netwatch-agent"
  echo ""
  echo "Optional macOS dev service:"
  echo "  ./target/debug/netwatch-agent launchd-install"
  exit 1
fi

# ── Update mode: read existing config ────────────────────
if [ "$MODE" = "update" ]; then
  if [ ! -f "$CONFIG_DIR/config.toml" ]; then
    echo "Error: No existing config found at $CONFIG_DIR/config.toml"
    echo "       Run with --api-key and --endpoint for a fresh install."
    exit 1
  fi
  OLD_VERSION=$("$INSTALL_DIR/netwatch-agent" --version 2>/dev/null || echo "unknown")
  echo "Updating NetWatch Agent (current: $OLD_VERSION)..."
fi

# ── Install mode: validate args ──────────────────────────
if [ "$MODE" = "install" ]; then
  if [ -z "$API_KEY" ]; then
    echo "Error: --api-key is required"
    echo "Usage: $0 --api-key YOUR_API_KEY --endpoint YOUR_ENDPOINT_URL"
    exit 1
  fi
  if [ -z "$ENDPOINT" ]; then
    echo "Error: --endpoint is required"
    echo "Usage: $0 --api-key YOUR_API_KEY --endpoint YOUR_ENDPOINT_URL"
    exit 1
  fi
fi

# ── Detect architecture ─────────────────────────────────
ARCH=$(uname -m)
case $ARCH in
  x86_64)  ARCH="x86_64" ;;
  aarch64) ARCH="aarch64" ;;
  arm64)   ARCH="aarch64" ;;
  *)       echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

echo "NetWatch Agent Installer"
echo "========================"
echo "Architecture: $ARCH"
echo "Mode: $MODE"
echo ""

# ── Download binary ──────────────────────────────────────
REPO="matthart1983/netwatch-agent"
DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/netwatch-agent-linux-${ARCH}"
echo "Downloading agent from $DOWNLOAD_URL ..."

if command -v curl >/dev/null 2>&1; then
  curl -fsSL -o /tmp/netwatch-agent "$DOWNLOAD_URL" 2>/dev/null
elif command -v wget >/dev/null 2>&1; then
  wget -qO /tmp/netwatch-agent "$DOWNLOAD_URL"
else
  echo "Error: curl or wget is required"
  exit 1
fi

if [ ! -f /tmp/netwatch-agent ] || [ ! -s /tmp/netwatch-agent ]; then
  echo ""
  echo "Error: Failed to download agent binary."
  echo ""
  echo "This can happen if:"
  echo "  - No release has been published yet (run: git tag v0.1.0 && git push origin v0.1.0)"
  echo "  - The repository is private"
  echo ""
  echo "Alternative: build from source"
  echo "  cargo build --release --package netwatch-agent"
  echo "  sudo cp target/release/netwatch-agent /usr/local/bin/"
  exit 1
fi

chmod +x /tmp/netwatch-agent
NEW_VERSION=$(/tmp/netwatch-agent --version 2>/dev/null || echo "unknown")

# ── Stop service if running ──────────────────────────────
stop_service

# ── Create service user (install only) ───────────────────
ensure_service_user

# ── Install binary ───────────────────────────────────────
echo "Installing binary ($NEW_VERSION) to $INSTALL_DIR/netwatch-agent ..."
mv /tmp/netwatch-agent "$INSTALL_DIR/netwatch-agent"

# ── Write config (install only — update preserves config) ─
if [ "$MODE" = "install" ]; then
  # Fresh install = fresh identity. Remove stale host-id so the agent
  # registers as a new host under the correct account.
  if [ -f "$DATA_DIR/host-id" ]; then
    echo "Removing stale host identity (fresh install)..."
    rm -f "$DATA_DIR/host-id"
  fi

  echo "Writing config to $CONFIG_DIR/config.toml ..."
  mkdir -p "$CONFIG_DIR"
  cat > "$CONFIG_DIR/config.toml" <<EOF
# NetWatch Agent configuration
endpoint = "$ENDPOINT"
api_key = "$API_KEY"
interval_secs = 15
health_interval_secs = 30
EOF
  chmod 600 "$CONFIG_DIR/config.toml"
  chown "$SERVICE_USER:$SERVICE_GROUP" "$CONFIG_DIR/config.toml"

  # Create data directory
  mkdir -p "$DATA_DIR"
  chown "$SERVICE_USER:$SERVICE_GROUP" "$DATA_DIR"
fi

# ── Enable and start ─────────────────────────────────────
enable_and_start_service

# ── Post-install verification ────────────────────────────
echo ""
echo "Verifying installation..."

sleep 3

if command -v systemctl >/dev/null 2>&1; then
  SVC_STATUS=$(systemctl is-active netwatch-agent 2>/dev/null || echo "unknown")
elif command -v rc-service >/dev/null 2>&1; then
  SVC_STATUS=$(rc-service netwatch-agent status >/dev/null 2>&1 && echo "active" || echo "failed")
else
  SVC_STATUS="unknown"
fi

if [ "$SVC_STATUS" != "active" ]; then
  echo ""
  echo "⚠️  Agent service is not running (status: $SVC_STATUS)"
  echo ""
  echo "Recent logs:"
  journalctl -u netwatch-agent -n 30 --no-pager 2>/dev/null || true
  echo ""
  echo "Common causes:"
  echo "  - Config error:  check $CONFIG_DIR/config.toml"
  echo "  - Permission:    check file ownership (should be $SERVICE_USER:$SERVICE_GROUP)"
  echo "  - Binary:        try running $INSTALL_DIR/netwatch-agent --version"
  exit 1
fi

# Wait for first successful send (up to 45 seconds)
VERIFIED=0
echo "Waiting for first snapshot..."
for i in 1 2 3 4 5 6 7 8 9; do
  if journalctl -u netwatch-agent --since "30 seconds ago" --no-pager 2>/dev/null | grep -q "snapshot sent"; then
    VERIFIED=1
    break
  fi
  sleep 5
done

HOST_ID=""
if [ -f "$DATA_DIR/host-id" ]; then
  HOST_ID=$(cat "$DATA_DIR/host-id")
fi

echo ""
if [ "$MODE" = "update" ]; then
  echo "✅ NetWatch Agent updated! ($OLD_VERSION → $NEW_VERSION)"
else
  echo "✅ NetWatch Agent installed and running! ($NEW_VERSION)"
fi

if [ "$VERIFIED" = "1" ]; then
  echo "✅ First snapshot sent successfully."
else
  echo ""
  echo "⚠️  No snapshot confirmed yet. The agent is running but hasn't reported back."
  echo "   This usually resolves within 30 seconds. If not, check:"
  echo ""
  journalctl -u netwatch-agent -n 10 --no-pager 2>/dev/null | grep -E "error|Error|warn|401|402|403|500|refused|timeout|dns" | head -5 || true
  echo ""
  echo "   Common causes:"
  echo "     401 Unauthorized  → API key is invalid or revoked"
  echo "     Connection error  → Firewall blocking HTTPS to the endpoint"
  echo "     Timestamp error   → System clock is wrong (check: date)"
fi

echo ""
[ -n "$HOST_ID" ] && echo "  Host ID: $HOST_ID"
echo "  Status:  systemctl status netwatch-agent"
echo "  Logs:    journalctl -u netwatch-agent -f"
echo "  Config:  $CONFIG_DIR/config.toml"
echo "  Update:  curl -sSL <api-url>/install.sh | sudo sh -s -- --update"
echo "  Remove:  curl -sSL <api-url>/install.sh | sudo sh -s -- --remove"
