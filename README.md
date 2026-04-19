# netwatch-agent

Lightweight network and system monitoring agent for [NetWatch Cloud](https://netwatch.io). Runs on your Linux or macOS hosts, collects metrics every 15 seconds, and streams them to the hosted backend.

## What it collects

- **Network interfaces** — rx/tx bytes, packets, errors, drops, instantaneous rates, rolling history
- **Connections** — TCP/UDP socket list with PID/process attribution; kernel-measured SRTT on Linux (via `ss -i`) and macOS (via `nettop`)
- **Process bandwidth** — top-N processes by rx+tx rate, attributed from interface totals by ESTABLISHED-connection count
- **System** — CPU (total + per-core), memory, swap, load averages
- **Disks** — per-mount usage, read/write byte counters
- **Gateway / DNS health** — ICMP RTT + loss to the default gateway and primary DNS server, with 60-sample rolling history
- **Packet capture (opt-in)** — optional libpcap-based capture that feeds the built-in NetworkIntel detectors: port scanning, beaconing, DNS tunneling, bandwidth thresholds, plus DNS analytics (top domains, latency buckets, NXDOMAIN counts)

All metrics are sent as a single `Snapshot` payload defined by the [`netwatch-sdk`](https://github.com/matthart1983/netwatch-sdk) crate.

## Install

```sh
curl -sSL https://netwatch-api-production.up.railway.app/install.sh | sudo sh -s -- --api-key YOUR_API_KEY
```

Or, build from source:

```sh
cargo install --path .
# or
cargo build --release
sudo cp target/release/netwatch-agent /usr/local/bin/
```

## Configure

Interactive setup:

```sh
netwatch-agent setup
```

Or edit the config file manually:

```toml
# ~/.config/netwatch-agent/config.toml (macOS)
# /etc/netwatch-agent/config.toml (Linux)
endpoint = "https://netwatch-api-production.up.railway.app/api/v1/ingest"
api_key = "nw_ak_..."
interval_secs = 15
health_interval_secs = 30
# Optional: trigger a bandwidth alert when either direction exceeds this rate
# on consecutive samples. Default: 100 MB/s.
bandwidth_alert_bytes_per_sec = 100_000_000

# Optional: enable libpcap-based packet capture for the full NetworkIntel
# detector suite. Requires elevated privileges (CAP_NET_RAW on Linux, BPF
# device access on macOS — e.g. via Wireshark's ChmodBPF).
[packet_capture]
enabled = false
interface = "auto"
```

Environment variable overrides: `NETWATCH_API_KEY`, `NETWATCH_ENDPOINT`, `NETWATCH_INTERVAL`, `NETWATCH_CONFIG`.

## Run

```sh
netwatch-agent              # foreground
netwatch-agent status       # check systemd/launchd state
netwatch-agent config       # print effective config
netwatch-agent update       # self-update to latest release
```

### As a service

**Linux (systemd):**
```sh
sudo systemctl enable --now netwatch-agent
```

**macOS (launchd):**
```sh
netwatch-agent launchd-install
```

## Platform support

| Platform | Status |
|---|---|
| Linux | First-class — all collectors, full `ss -i` RTT |
| macOS | First-class — `lsof` + `nettop` RTT merge |
| Windows | Not supported |

## Security posture

- API key is stored in `config.toml` with `0o600` permissions. Never logged.
- No code executes based on server responses — the agent is write-only (POSTs snapshots, receives acknowledgement only).
- Packet capture is opt-in. When enabled, the BPF filter restricts kernel-side capture to TCP SYN packets and UDP/53 traffic — no payloads, no opaque packet storage.

## Relationship to other NetWatch projects

- [**netwatch-sdk**](https://github.com/matthart1983/netwatch-sdk) — the shared library this agent depends on. Wire format + collectors.
- [**netwatch-dashboard**](https://github.com/matthart1983/netwatch-dashboard) — the web UI where you view the metrics this agent reports.
- [**netwatch**](https://github.com/matthart1983/netwatch) — a standalone single-host TUI, unrelated to the Cloud product. Different code path, same philosophy.

## License

MIT © 2025-2026 Matt Hartley
