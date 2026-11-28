#!/usr/bin/env bash
set -euo pipefail

arch="${1:-amd64}"
case "$arch" in
  amd64|arm64) ;;
  *) echo "unsupported Windows arch: $arch" >&2; exit 1 ;;
esac

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

dist_dir="$root/dist"
tmp_base="${TMPDIR:-/tmp}"
tmp_base="${tmp_base%/}"
work_dir="$(mktemp -d "${tmp_base}/xconnect-one-win.XXXXXX")"
trap 'rm -rf "$work_dir"' EXIT

mkdir -p "$dist_dir"

source "$root/scripts/ci/version_ldflags.sh"
ldflags="$(resolve_xconnect_ldflags "")"

raw_exe="$dist_dir/xconnect-windows-${arch}.exe"
one_exe="$dist_dir/xconnect-one-windows-${arch}.exe"
CGO_ENABLED=0 GOOS=windows GOARCH="$arch" go build \
  -trimpath \
  -ldflags="$ldflags" \
  -o "$raw_exe" \
  ./cmd/xconnect
cp "$raw_exe" "$one_exe"

wintun_version="0.14.1"
wintun_sha256="07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
wintun_zip="$work_dir/wintun-${wintun_version}.zip"
curl -fsSL "https://www.wintun.net/builds/wintun-${wintun_version}.zip" -o "$wintun_zip"
if command -v sha256sum >/dev/null 2>&1; then
  printf '%s  %s\n' "$wintun_sha256" "$wintun_zip" | sha256sum -c -
else
  printf '%s  %s\n' "$wintun_sha256" "$wintun_zip" | shasum -a 256 -c -
fi
unzip -q "$wintun_zip" -d "$work_dir/wintun"

bundle_dir="$work_dir/xconnect-one-windows-${arch}"
mkdir -p "$bundle_dir"
cp "$one_exe" "$bundle_dir/xconnect-one.exe"
cp "$raw_exe" "$bundle_dir/xconnect.exe"
cp "$work_dir/wintun/wintun/bin/${arch}/wintun.dll" "$bundle_dir/wintun.dll"
cp "$root/scripts/install-xconnect-one.ps1" "$bundle_dir/install-xconnect-one.ps1"

cat > "$bundle_dir/README.txt" <<'EOF'
XConnect-One (Windows Standalone Portable Bundle)
=================================================

Zero-dependency portable bundle (includes xconnect-one.exe + wintun.dll).
Run from an Administrator PowerShell in this directory:

  .\xconnect-one.exe login
  .\xconnect-one.exe join --gateway https://ph-xconnect-gateway-01.svc.plus
  .\xconnect-one.exe up
EOF

zip_path="$dist_dir/xconnect-one-windows-${arch}.zip"
rm -f "$zip_path"
(
  cd "$work_dir"
  zip -qr "$zip_path" "xconnect-one-windows-${arch}"
)

echo "Built Windows artifacts: $one_exe, $raw_exe, $zip_path"
