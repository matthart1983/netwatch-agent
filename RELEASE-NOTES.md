NetWatch Agent v0.6.2 distinguishes measured zero traffic from incomplete rate evidence.

- Interface first samples, counter resets and reappearances no longer report fabricated zero rates. Failed collection clears the baseline; a gap over 24 hours re-establishes it.
- Each snapshot includes directional baseline, missing-counter and reset counts, disappearance counts, elapsed intervals and process-list truncation.
- Process rates use observed established-socket counter deltas, with protocol/endpoints/owner keys. Unknown socket visibility and PID/tuple reuse remain limitations; this is not complete per-process traffic accounting.
- Buffered snapshots retain their own evidence. Cloud and standalone dashboard readers show incomplete rates as unavailable while keeping genuine zeroes.
- Retains v0.6.1 collector failure reporting and v0.6.0 capture fixes.

Deploy the matching Cloud API/UI before upgrading agents. Legacy servers accept the additive wire fields but cannot interpret process coverage and may display placeholder zeroes. Legacy integer interface histories are omitted because they cannot represent gaps; Cloud charts use stored observations.

Linux x86_64 and aarch64 binaries include libpcap statically and require glibc 2.35 or newer. Verify downloads against SHA256SUMS. Source builds use system libpcap; Alpine/musl needs a separate build. Native macOS behavior was not verified in this change.

Upgrade: `sudo netwatch-agent update`. Existing configuration and capture settings are preserved.
