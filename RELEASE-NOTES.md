NetWatch Agent v0.6.1 reports collector availability without fabricating network loss.

- Adds timestamped latest collector-attempt evidence for NetWatch Cloud.
- Removes unconditional healthy collector reporting. Collectors with hidden failure outcomes remain explicitly unknown.
- Separates ICMP probe execution/parsing failures from observed packet loss; failures now leave RTT/loss unavailable.
- Bounds each gateway/resolver probe to eight seconds and preserves probe timestamps between health cycles.
- Keeps the v0.6.0 capture restoration and SDK 0.4.1 fixes.

Collector reports describe latest attempts, not historical quality or complete resource coverage. Connections, TCP states, disk and process bandwidth still have unknown collection outcomes. Resolver probing is ICMP, not DNS query latency. Native macOS behavior has not been verified for this change.

Linux x86_64 and aarch64 binaries include libpcap statically and require glibc 2.35 or newer. Verify downloads against `SHA256SUMS`. Source builds use system libpcap; Alpine/musl needs a separate build.

Upgrade: `sudo netwatch-agent update`. Configuration is preserved; capture remains off unless previously enabled. New Cloud collector evidence requires this agent update. Older servers ignore the optional report and continue accepting metrics.
