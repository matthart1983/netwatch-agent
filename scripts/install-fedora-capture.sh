#!/usr/bin/env bash
# Install the tested local build without changing host identity, credentials,
# existing service restrictions, or unrelated environment settings.
set -euo pipefail
ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
BIN="$ROOT_DIR/target/release/netwatch-agent"
UNIT=netwatch-agent
DEST=/usr/local/bin/netwatch-agent
ENV_FILE=/etc/netwatch-agent/env

if [[ ${EUID} != 0 ]]; then
  echo "Run: sudo bash $ROOT_DIR/scripts/install-fedora-capture.sh" >&2
  exit 1
fi
if [[ ${1:-} == --rollback ]]; then
  BACKUP=${2:?Supply the backup directory printed by installation}
  [[ "$BACKUP" == /var/lib/netwatch-agent/capture-backup-* && -d "$BACKUP" ]] || exit 1
  install -m 0755 "$BACKUP/netwatch-agent" "$DEST.rollback"
  mv -f "$DEST.rollback" "$DEST"
  if [[ -f "$BACKUP/env" ]]; then cp -a "$BACKUP/env" "$ENV_FILE"; else rm -f "$ENV_FILE"; fi
  command -v restorecon >/dev/null && restorecon "$DEST" || true
  systemctl restart "$UNIT"
  echo "Restored $BACKUP"
  exit 0
fi
[[ -x "$BIN" && -f "$BIN.sha256" ]] || { echo 'Build and checksum the release binary first.' >&2; exit 1; }
(cd "$(dirname "$BIN")" && sha256sum -c netwatch-agent.sha256)
"$BIN" --version
# Check a unique uplink marker without running a capture or exposing credentials.
python3 - "$BIN" <<'PY'
import sys
from pathlib import Path
if b'/api/v1/agent/dpi/uplink' not in Path(sys.argv[1]).read_bytes():
    raise SystemExit('Refusing binary without capture uplink support')
PY
systemctl cat "$UNIT" >/dev/null
IFACE=${1:-$(ip -o route show default | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1);exit}}')}
[[ -n "$IFACE" && "$IFACE" != any && -d "/sys/class/net/$IFACE" ]] || { echo 'Pass a physical capture interface as the first argument.' >&2; exit 1; }
BACKUP=$(mktemp -d /var/lib/netwatch-agent/capture-backup-XXXXXXXX)
chmod 0700 "$BACKUP"
cp -a "$DEST" "$BACKUP/netwatch-agent"
if [[ -f "$ENV_FILE" ]]; then cp -a "$ENV_FILE" "$BACKUP/env"; fi
# Config is left untouched, including the API key and persistent host identity.
python3 - "$ENV_FILE" "$IFACE" <<'PY'
import os,sys,tempfile
from pathlib import Path
p=Path(sys.argv[1]); iface=sys.argv[2]
if not all(c.isalnum() or c in '_.:-' for c in iface): raise SystemExit('Invalid interface')
old=p.stat() if p.exists() else None
lines=p.read_text().splitlines() if p.exists() else []
keys={'NETWATCH_DPI_REMOTE','NETWATCH_CAPTURE_INTERFACE'}
lines=[l for l in lines if l.partition('=')[0].strip() not in keys]
lines += ['NETWATCH_DPI_REMOTE=1',f'NETWATCH_CAPTURE_INTERFACE={iface}']
fd,tmp=tempfile.mkstemp(dir=p.parent,prefix='.capture-env-')
try:
    os.fchmod(fd, (old.st_mode & 0o777) if old else 0o600)
    if old: os.fchown(fd,old.st_uid,old.st_gid)
    with os.fdopen(fd,'w') as f: f.write('\n'.join(lines)+'\n')
    os.replace(tmp,p)
finally:
    if os.path.exists(tmp): os.unlink(tmp)
PY
install -m 0755 "$BIN" "$DEST.capture-new"
mv -f "$DEST.capture-new" "$DEST"
command -v restorecon >/dev/null && restorecon "$DEST" "$ENV_FILE" || true
printf 'Backup: %s\nRollback: sudo bash %s/scripts/install-fedora-capture.sh --rollback %s\n' "$BACKUP" "$ROOT_DIR" "$BACKUP"
systemctl restart "$UNIT"
INVOCATION=$(systemctl show "$UNIT" -p InvocationID --value)
for ((i=0;i<30;i++)); do
  LOG=$(journalctl "_SYSTEMD_INVOCATION_ID=$INVOCATION" --no-pager -o cat)
  if [[ "$LOG" == *'dpi uplink connected'* && "$LOG" == *'snapshot sent'* ]] && systemctl is-active --quiet "$UNIT"; then
    echo "Verified: capture uplink connected; normal telemetry sent; interface $IFACE."
    echo 'Open Fedora in Cloud, reconnect capture, and choose Start capture.'
    exit 0
  fi
  sleep 2
done
echo 'Verification failed. The replacement is installed; use the printed rollback command if needed.' >&2
journalctl -u "$UNIT" --since '-90 seconds' --no-pager -o cat | rg -i 'dpi|capture|panic|error' | tail -15 || true
exit 1
