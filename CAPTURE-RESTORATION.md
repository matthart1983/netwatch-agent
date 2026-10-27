# Restored capture build

The public v0.5.0 binary installed on Fedora has no DPI uplink client. This
checkout restores the `feat/dpi-uplink` agent using an in-tree metadata library,
so it no longer depends on an unavailable sibling `netwatch-dpi` checkout.

Build and test:

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --release --locked
(cd target/release && sha256sum netwatch-agent > netwatch-agent.sha256)
```

Install on Fedora with the existing NetWatch service and configuration:

```sh
sudo bash scripts/install-fedora-capture.sh
```

The installer selects the default route interface (or accepts one as its first
argument), backs up the installed binary and environment under
`/var/lib/netwatch-agent/capture-backup-*`, preserves all unrelated environment
settings, and sets `NETWATCH_DPI_REMOTE=1` plus `NETWATCH_CAPTURE_INTERFACE`.
It leaves the API key, config file, host identity and service capabilities alone.
It uses the native Fedora libpcap linked by the local release build. The service
must already grant CAP_NET_RAW, as Fedora's current service does.

Verification requires a new invocation to log both `dpi uplink connected` and
`snapshot sent`; a merely running service is not success. If verification fails,
the installer prints the backup and rollback command. Rollback restores the
previous binary and environment and restarts the service.

After installation, reconnect Fedora's Capture panel and press Start capture.
Generate controlled HTTP/DNS/TLS traffic and check packets arrive. Then stop and
confirm delivery stops. Fedora live capture was confirmed working by the operator on 26 October 2026
after installing the restored agent. Unit/mock-relay tests alone do not establish
production packet delivery on another host; verify it after installation.

Agent fixes in this checkout:

- Failed workers release their session so capture can be retried.
- Filter edits while stopped do not start capture.
- Replacing/stopping a session drops queued frames from the previous worker.
- Nonblocking pcap reads allow stop/duration checks even on quiet interfaces.
- Packet and DNS-name batches stay within the relay's 512 KiB frame limit.
- Flow/name tracking is bounded; IP fragments are not treated as TCP/UDP headers.
- Unsupported link types and capture errors produce explicit status messages.

The Cloud requested/confirmed capture distinction was corrected and deployed in
Cloud revision 681bb1f on 27 October 2026. See the crate README for protocol coverage.
