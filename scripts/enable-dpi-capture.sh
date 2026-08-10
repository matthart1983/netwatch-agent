#!/usr/bin/env bash
#
# Enable cloud-initiated DPI capture on a NetWatch agent host, persistently,
# and verify it actually came up.
#
#   ./scripts/enable-dpi-capture.sh [user@host]        # enable + verify
#   ./scripts/enable-dpi-capture.sh [user@host] --check # verify only, no changes
#   ./scripts/enable-dpi-capture.sh [user@host] --off    # disable capture
#
# Why this exists: two agent flags gate capture and they are easy to conflate.
#
#   NETWATCH_PACKET_CAPTURE  local libpcap feed for the NetworkIntel detectors
#                            (port-scan / beaconing / DNS-tunnel)
#   NETWATCH_DPI_REMOTE      the outbound uplink that lets the cloud start a
#                            capture session — this is what the dashboard's
#                            Capture tab needs
#
# Setting them via the systemd EnvironmentFile is what makes them survive a
# restart. Setting them any other way does not: an agent that restarts without
# NETWATCH_DPI_REMOTE comes up with the uplink disabled and NEVER dials out, so
# the dashboard shows "CAPTURING" with zero packets and no error anywhere. That
# failure is silent from the UI, which is precisely why it is worth a script
# that verifies rather than assumes.
#
# Requires sudo on the target (it writes /etc/netwatch-agent/env and restarts
# the unit), so it allocates a TTY for the password prompt.

set -euo pipefail

TARGET="${1:-matt@192.168.0.54}"
MODE="${2:-enable}"
ENV_FILE="/etc/netwatch-agent/env"
UNIT="netwatch-agent"
REMOTE_SCRIPT="/tmp/nw-enable-dpi-capture.$$.sh"

case "$MODE" in
  enable|--on)  WANT=1 ;;
  --off|off)    WANT=0 ;;
  --check|check) WANT=check ;;
  *) echo "usage: $0 [user@host] [--check|--off]" >&2; exit 2 ;;
esac

say()  { printf '  %s\n' "$*"; }
head2() { printf '\n\033[1m%s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }

head2 "Target: $TARGET"

# ── preflight ────────────────────────────────────────────────────────────────
if ! ssh -o ConnectTimeout=8 -o BatchMode=yes "$TARGET" true 2>/dev/null; then
  bad "cannot reach $TARGET over ssh with key auth"
  exit 1
fi
ok "ssh reachable"

AGENT_VERSION="$(ssh -o BatchMode=yes "$TARGET" 'netwatch-agent --version 2>/dev/null || echo "not installed"')"
say "agent: $AGENT_VERSION"
if [[ "$AGENT_VERSION" == "not installed" ]]; then
  bad "netwatch-agent is not on PATH — install it before enabling capture"
  exit 1
fi

# The uplink shipped on the DPI branch; older builds have no client for it and
# will silently never connect no matter what the flags say.
if ! ssh -o BatchMode=yes "$TARGET" 'strings "$(command -v netwatch-agent)" 2>/dev/null | grep -q "/api/v1/agent/dpi/uplink"'; then
  bad "this agent build has no DPI uplink client — capture cannot work"
  say "  rebuild from a branch containing 'feat(dpi): outbound metadata uplink'"
  exit 1
fi
ok "agent build includes the DPI uplink client"

# ── check-only ───────────────────────────────────────────────────────────────
report_state() {
  head2 "Current state"
  ssh -o BatchMode=yes "$TARGET" bash -s <<'REMOTE'
set -u
ENV_FILE=/etc/netwatch-agent/env
if [ -r "$ENV_FILE" ]; then
  echo "  env file:"
  sed 's/^/    /' "$ENV_FILE" | grep -v '^\s*$' || echo "    (empty)"
else
  echo "  env file: absent or unreadable"
fi
echo "  service: $(systemctl is-active netwatch-agent 2>/dev/null)"
echo "  uplink sockets to :443: $(ss -tn state established 2>/dev/null | grep -c ':443' || true)"
last_up=$(journalctl -u netwatch-agent --no-pager 2>/dev/null | grep -E 'dpi uplink connected|DPI remote uplink disabled' | tail -1)
echo "  last uplink event: ${last_up:-<none>}"
REMOTE
}

if [[ "$WANT" == "check" ]]; then
  report_state
  exit 0
fi

# ── apply ────────────────────────────────────────────────────────────────────
# The remote script is staged as a file and then run under sudo, so the SSH
# quoting layer never has to carry the file contents (an earlier one-liner had
# its \n eaten and wrote an empty env file, which is the bug this script exists
# to stop repeating).
head2 "Writing $ENV_FILE"
ssh -o BatchMode=yes "$TARGET" "cat > $REMOTE_SCRIPT" <<REMOTE
#!/usr/bin/env bash
set -euo pipefail
install -d -m 0755 "\$(dirname $ENV_FILE)"
[ -f $ENV_FILE ] && cp -a $ENV_FILE ${ENV_FILE}.bak.\$(date +%s) || true
cat > $ENV_FILE <<'VARS'
# Managed by scripts/enable-dpi-capture.sh — persists across agent restarts.
NETWATCH_PACKET_CAPTURE=$WANT
NETWATCH_DPI_REMOTE=$WANT
VARS
chmod 0644 $ENV_FILE
systemctl restart $UNIT
REMOTE

# -t so sudo can prompt for a password.
ssh -t "$TARGET" "sudo bash $REMOTE_SCRIPT; rm -f $REMOTE_SCRIPT"

# ── verify ───────────────────────────────────────────────────────────────────
head2 "Verifying"
if [[ "$WANT" == "0" ]]; then
  ssh -o BatchMode=yes "$TARGET" "systemctl is-active $UNIT" >/dev/null && ok "agent restarted with capture disabled"
  report_state
  exit 0
fi

# Give the agent a moment to boot and dial out, polling rather than sleeping a
# fixed amount — the uplink normally lands in about a second.
CONNECTED=0
for _ in $(seq 1 20); do
  if ssh -o BatchMode=yes "$TARGET" \
      "journalctl -u $UNIT --no-pager --since '-90s' 2>/dev/null | grep -q 'dpi uplink connected'"; then
    CONNECTED=1; break
  fi
  sleep 2
done

ACTIVE="$(ssh -o BatchMode=yes "$TARGET" "systemctl is-active $UNIT" 2>/dev/null || true)"
[[ "$ACTIVE" == "active" ]] && ok "service active" || bad "service is '$ACTIVE'"

PANICS="$(ssh -o BatchMode=yes "$TARGET" "journalctl -u $UNIT --no-pager --since '-90s' 2>/dev/null | grep -c panicked || true")"
[[ "${PANICS:-0}" -eq 0 ]] && ok "no panics since restart" || bad "$PANICS panic(s) since restart — check the SDK version"

if ssh -o BatchMode=yes "$TARGET" "journalctl -u $UNIT --no-pager --since '-90s' 2>/dev/null | grep -q 'packet capture ready'"; then
  ok "local packet capture ready"
else
  warn "local packet capture did not report ready (needs CAP_NET_RAW)"
fi

if [[ "$CONNECTED" -eq 1 ]]; then
  ok "DPI uplink connected — the dashboard Capture tab will now stream"
else
  bad "DPI uplink did NOT connect within 40s"
  say "recent uplink lines:"
  ssh -o BatchMode=yes "$TARGET" "journalctl -u $UNIT --no-pager --since '-90s' 2>/dev/null | grep -iE 'uplink|dpi' | tail -5" | sed 's/^/    /'
  exit 1
fi

report_state

head2 "Next"
say "Open the host in the dashboard → Capture tab (scroll the tab strip right)"
say "then click the STOPPED pill to begin streaming."
