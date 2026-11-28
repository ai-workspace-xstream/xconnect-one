#!/usr/bin/env bash
set -euo pipefail

arch="${1:?usage: package_linux.sh <amd64|arm64> [version] [release]}"
version="${2:-0.1.0}"
release_num="${3:-1}"

case "$arch" in
  amd64) rpm_arch="x86_64" ;;
  arm64) rpm_arch="aarch64" ;;
  *) echo "unsupported Linux arch: $arch" >&2; exit 1 ;;
esac

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

dist_dir="$root/dist"
tmp_base="${TMPDIR:-/tmp}"
tmp_base="${tmp_base%/}"
work_dir="$(mktemp -d "${tmp_base}/xconnect-one-linux.XXXXXX")"
trap 'rm -rf "$work_dir"' EXIT

mkdir -p "$dist_dir"

raw_bin="$dist_dir/xconnect-linux-${arch}"
one_bin="$dist_dir/xconnect-one-linux-${arch}"
lab_bin="$dist_dir/xconnect-zero-lab-linux-${arch}"

source "$root/scripts/ci/version_ldflags.sh"
ldflags="$(resolve_xconnect_ldflags "$version")"

CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build \
  -trimpath \
  -ldflags="$ldflags" \
  -o "$raw_bin" \
  ./cmd/xconnect
cp "$raw_bin" "$one_bin"
chmod 0755 "$raw_bin" "$one_bin"

CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build \
  -trimpath \
  -ldflags="-s -w" \
  -o "$lab_bin" \
  ./cmd/xconnect-zero-lab
chmod 0755 "$lab_bin"

# 1. Zero-dependency portable archives (tar.gz preserves executable permissions cleanly)
portable_name="xconnect-one-linux-${arch}"
portable_dir="$work_dir/$portable_name"
mkdir -p "$portable_dir"
cp "$one_bin" "$portable_dir/xconnect-one"
cp "$raw_bin" "$portable_dir/xconnect"
chmod 0755 "$portable_dir/xconnect-one" "$portable_dir/xconnect"
cp "$root/scripts/install-xconnect-one.sh" "$portable_dir/install-xconnect-one.sh"
chmod 0755 "$portable_dir/install-xconnect-one.sh"
cat > "$portable_dir/README.txt" <<'EOF'
XConnect-One (Linux Static Standalone Bundle)
=============================================

Static zero-runtime-dependency binary (CGO_ENABLED=0). Works on Debian,
Ubuntu, Fedora, openSUSE (GNOME/KDE), and minimal Linux containers.

Quick start:
  ./xconnect-one login
  ./xconnect-one join --gateway https://ph-xconnect-gateway-01.svc.plus
  sudo ./xconnect-one up

System-wide install:
  sudo install -m 0755 ./xconnect-one /usr/local/bin/xconnect-one
EOF

tar_path="$dist_dir/${portable_name}.tar.gz"
zip_path="$dist_dir/${portable_name}.zip"
rm -f "$tar_path" "$zip_path"
tar -C "$work_dir" -czf "$tar_path" "$portable_name"
(
  cd "$work_dir"
  zip -qr "$zip_path" "$portable_name"
)

# 2. Cross-distro .deb and .rpm via nfpm (zero runtime library dependencies)
if ! command -v nfpm >/dev/null 2>&1; then
  go install github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.43.3
  export PATH="$(go env GOPATH)/bin:$PATH"
fi

pkg_root="$work_dir/pkgroot"
mkdir -p "$pkg_root/usr/bin" "$pkg_root/etc/systemd/system"
cp "$one_bin" "$pkg_root/usr/bin/xconnect-one"
chmod 0755 "$pkg_root/usr/bin/xconnect-one"
XCONNECT_ONE_INSTALL_DIR="/usr/bin" XCONNECT_ONE_STATE_DIR="/var/lib/xconnect-one" \
  bash "$root/scripts/install-xconnect-one.sh" --print-unit > "$pkg_root/etc/systemd/system/xconnect-one-sync.service"

nfpm_cfg="$work_dir/nfpm.yaml"
cat > "$nfpm_cfg" <<EOF
name: xconnect-one
arch: ${arch}
platform: linux
version: ${version}
release: ${release_num}
section: net
priority: optional
maintainer: XConnect Team <support@svc.plus>
description: |
  Standalone XConnect Zero controlled-client CLI and embedded WireGuard/Xray runtime.
  Statically compiled with zero external shared library dependencies.
vendor: XConnect Team
homepage: https://github.com/ai-workspace-xstream/xconnect-one
license: Apache-2.0
overrides:
  deb:
    recommends:
      - iproute2
      - ca-certificates
  rpm:
    recommends:
      - "(iproute or iproute2)"
      - ca-certificates
contents:
  - src: ${pkg_root}/usr/bin/xconnect-one
    dst: /usr/bin/xconnect-one
    file_info:
      mode: 0755
  - src: /usr/bin/xconnect-one
    dst: /usr/bin/xconnect
    type: symlink
  - src: ${pkg_root}/etc/systemd/system/xconnect-one-sync.service
    dst: /etc/systemd/system/xconnect-one-sync.service
    type: config|noreplace
    file_info:
      mode: 0644
scripts:
  postinstall: ${root}/packaging/nfpm/postinstall.sh
EOF

deb_path="$dist_dir/xconnect-one_${version}_${arch}.deb"
rpm_path="$dist_dir/xconnect-one-${version}.${rpm_arch}.rpm"
nfpm pkg --packager deb --config "$nfpm_cfg" --target "$deb_path"
nfpm pkg --packager rpm --config "$nfpm_cfg" --target "$rpm_path"

echo "Built Linux artifacts: $one_bin, $tar_path, $deb_path, $rpm_path"
