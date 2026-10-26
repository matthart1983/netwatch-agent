#!/usr/bin/env bash
# Build against a pinned static libpcap to avoid Debian/Fedora SONAME differences.
set -euo pipefail
PCAP_REV=a999701dca5c873779281938baee6bc185a8d4dc # libpcap 1.10.6
BUILD_DIR=$(mktemp -d)
trap 'rm -rf "$BUILD_DIR"' EXIT
curl --fail --location --retry 3 "https://github.com/the-tcpdump-group/libpcap/archive/$PCAP_REV.tar.gz" -o "$BUILD_DIR/pcap.tar.gz"
tar -xzf "$BUILD_DIR/pcap.tar.gz" -C "$BUILD_DIR"
cmake -S "$BUILD_DIR/libpcap-$PCAP_REV" -B "$BUILD_DIR/build" \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$BUILD_DIR/install" \
  -DCMAKE_INSTALL_LIBDIR=lib -DBUILD_SHARED_LIBS=OFF -DENABLE_REMOTE=OFF \
  -DBUILD_WITH_LIBNL=OFF -DDISABLE_DBUS=ON -DDISABLE_RDMA=ON \
  -DDISABLE_BLUETOOTH=ON -DDISABLE_LINUX_USBMON=ON -DDISABLE_NETMAP=ON \
  -DDISABLE_DAG=ON -DDISABLE_SEPTEL=ON -DDISABLE_SNF=ON -DDISABLE_TC=ON
cmake --build "$BUILD_DIR/build" --parallel 4
cmake --install "$BUILD_DIR/build"
export PKG_CONFIG_PATH="$BUILD_DIR/install/lib/pkgconfig"
export LIBPCAP_STATIC=1
cargo test --workspace --locked
cargo build --release --locked
if ldd target/release/netwatch-agent | grep -E 'libpcap|not found'; then
  echo 'Release must not require a shared libpcap or missing libraries.' >&2
  exit 1
fi
target/release/netwatch-agent --version
mkdir -p dist
cp target/release/netwatch-agent "dist/netwatch-agent-linux-$(uname -m)"
cp "$BUILD_DIR/libpcap-$PCAP_REV/LICENSE" dist/LICENSE-libpcap
