# NetWatch Agent

Lightweight Linux agent for [NetWatch Cloud](https://www.netwatchlabs.com). Collects system and network health metrics every 15 seconds and sends them to the cloud dashboard.

## Install

```sh
curl -sSL https://raw.githubusercontent.com/matthart1983/netwatch-agent/main/install.sh | sudo sh -s -- \
  --api-key YOUR_API_KEY \
  --endpoint https://netwatch-api-production.up.railway.app/api/v1/ingest
```

## What it collects

- CPU usage (total + per-core)
- Memory and swap usage
- Disk I/O and usage
- Network interface RX/TX
- TCP connection states
- Load average (1m, 5m, 15m)
- Gateway latency and packet loss
- DNS latency and packet loss

## Commands

```sh
netwatch-agent              # Run the agent daemon
netwatch-agent status       # Show agent status
netwatch-agent config       # Show current configuration
netwatch-agent setup        # Interactive first-run setup
netwatch-agent update       # Download and install latest version
netwatch-agent version      # Print version
```

## Requirements

- Linux (x86_64 or aarch64)
- systemd or OpenRC
- Outbound HTTPS access to the API endpoint

## License

MIT
