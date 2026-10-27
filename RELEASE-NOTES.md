NetWatch Agent v0.6.3 fixes self-update on a running Linux executable.

- Stages the replacement beside the installed executable and atomically renames it, avoiding Linux `Text file busy` (ETXTBSY).
- Uses a private download directory and verifies the release SHA256SUMS before running or installing the download.
- Checks the downloaded version command and reports service restart failures accurately.
- Restores the SELinux executable label where restorecon is installed.
- Retains v0.6.2 rate coverage/baseline metadata and the earlier capture fixes.

Older installed updaters cannot apply this fix themselves. Use the repository's `scripts/install-update.sh` once with sudo; it downloads this pinned release, checks its checksum, atomically replaces `/usr/local/bin/netwatch-agent`, restores its SELinux label and restarts the service. Subsequent updates can use `sudo netwatch-agent update`.

Linux x86_64 and aarch64 binaries include libpcap statically and require glibc 2.35 or newer. Configuration and capture settings are preserved.
