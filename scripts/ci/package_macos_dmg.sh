#!/usr/bin/env bash
set -euo pipefail

arch="${1:?usage: package_macos_dmg.sh <amd64|arm64>}"
case "$arch" in
  amd64|arm64) ;;
  *) echo "unsupported macOS arch: $arch" >&2; exit 1 ;;
esac

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

dist_dir="$root/dist"
tmp_base="${TMPDIR:-/tmp}"
tmp_base="${tmp_base%/}"
stage_dir="$(mktemp -d "${tmp_base}/xconnect-one-dmg.XXXXXX")"
trap 'rm -rf "$stage_dir"' EXIT

mkdir -p "$dist_dir"

raw_bin="$dist_dir/xconnect-macos-${arch}"
CGO_ENABLED=0 GOOS=darwin GOARCH="$arch" go build \
  -trimpath \
  -ldflags="-s -w" \
  -o "$raw_bin" \
  ./cmd/xconnect

dmg_root="$stage_dir/XConnect-One"
mkdir -p "$dmg_root"
cp "$raw_bin" "$dmg_root/xconnect-one"
cp "$raw_bin" "$dmg_root/xconnect"
chmod 0755 "$dmg_root/xconnect-one" "$dmg_root/xconnect"
cp "$root/scripts/setup-xconnect-one-macos.sh" "$dmg_root/setup-xconnect-one-macos.sh"
chmod 0755 "$dmg_root/setup-xconnect-one-macos.sh"

cat > "$dmg_root/README.txt" <<'EOF'
XConnect-One (macOS Standalone CLI)
===================================

1. Install the standalone zero-dependency binary:
   sudo install -m 0755 ./xconnect-one /usr/local/bin/xconnect-one

2. Login, join gateway, and start tunnel:
   xconnect-one login
   xconnect-one join --gateway https://ph-xconnect-gateway-01.svc.plus
   sudo xconnect-one up

3. Optional LaunchDaemon autostart:
   sudo env XCONNECT_ONE_BINARY=/usr/local/bin/xconnect-one bash ./setup-xconnect-one-macos.sh
EOF

dmg_path="$dist_dir/xconnect-one-macos-${arch}.dmg"
rm -f "$dmg_path"
hdiutil create \
  -volname "XConnect-One" \
  -srcfolder "$dmg_root" \
  -ov \
  -format UDZO \
  "$dmg_path"

echo "Built macOS DMG: $dmg_path"
