NetWatch Agent v0.6.0 includes the live metadata-capture client used by NetWatch Cloud.

- Restores the missing DPI library as an in-repository crate, so source builds no longer depend on an unpublished sibling checkout.
- Supports TLS SNI/ALPN/JA4, HTTP method/Host/status, DNS names/address answers and SSH identification. HTTP paths, credentials and application bodies are excluded from capture output; metadata can still be sensitive.
- Adds source-side redaction, bounded parsing, frame-size limits and regression tests for malformed inputs and payload exclusion.
- Fixes failed-capture retries, filter changes while stopped, stale queued frames and quiet-interface shutdown.
- Uses netwatch-sdk 0.4.1, including the process elapsed-time overflow fix.
- Fedora live capture was confirmed working after installation of this restoration.

Capture is **off by default**. Set `NETWATCH_DPI_REMOTE=1` in the service environment, optionally select the physical interface with `NETWATCH_CAPTURE_INTERFACE`, and restart the agent. Cloud capture authorization and CAP_NET_RAW are still required. This is separate from the local `packet_capture.enabled` detector setting.

Linux x86_64 and aarch64 binaries include libpcap statically and require glibc 2.35 or newer. Verify downloads against `SHA256SUMS`. Source builds continue to use system libpcap. Alpine/musl requires a separate build.

Upgrade: `sudo netwatch-agent update`. Upgrading preserves existing configuration; it does not enable capture automatically.

Coverage limits: no TCP/IP reassembly, QUIC/HTTP3 decoding or application payload inspection. Ethernet and BSD loopback are supported; Linux cooked (`any`) and VLAN frames are not. The Cloud relay can still show capture requested after an agent-side failure; inspect the displayed status message.
