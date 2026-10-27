#!/usr/bin/env bash
# One-time repair for older updaters that overwrite their running executable.
set -euo pipefail
if [[ $EUID != 0 ]]; then
  echo "Run with sudo: sudo bash $0" >&2
  exit 1
fi
case "$(uname -m)" in
  x86_64) artifact=netwatch-agent-linux-x86_64 ;;
  aarch64|arm64) artifact=netwatch-agent-linux-aarch64 ;;
  *) echo 'Unsupported architecture' >&2; exit 1 ;;
esac
version=v0.6.3
base="https://github.com/matthart1983/netwatch-agent/releases/download/$version"
work=$(mktemp -d)
staged=''
trap 'rm -rf -- "$work"; if [[ -n "$staged" ]]; then rm -f -- "$staged"; fi' EXIT
curl -fsSL "$base/$artifact" -o "$work/$artifact"
curl -fsSL "$base/SHA256SUMS" -o "$work/SHA256SUMS"
awk -v name="$artifact" '$2 == name { print }' "$work/SHA256SUMS" > "$work/checksum"
[[ -s "$work/checksum" ]]
(cd "$work" && sha256sum --check checksum)
chmod 755 "$work/$artifact"
"$work/$artifact" --version
install_dir=/usr/local/bin
staged=$(mktemp "$install_dir/.netwatch-agent.XXXXXX")
install -m 755 "$work/$artifact" "$staged"
# Same-filesystem rename leaves both the running service and updater inode intact.
mv -fT -- "$staged" "$install_dir/netwatch-agent"
staged=''
if command -v restorecon >/dev/null 2>&1; then
  restorecon "$install_dir/netwatch-agent"
fi
systemctl restart netwatch-agent
systemctl is-active --quiet netwatch-agent
"$install_dir/netwatch-agent" --version
echo 'Agent replaced and service active. Check journalctl -u netwatch-agent for telemetry receipt.'
