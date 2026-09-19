#!/usr/bin/env bash
set -euo pipefail
umask 022

# Release installer for the standalone XConnect One controlled-client.
# The install.svc.plus endpoint may serve this file, while the release base
# can be pointed at an approved mirror for private GitHub repositories.

readonly RELEASE_REPOSITORY="ai-workspace-xstream/XConnect-One"
readonly DEFAULT_VERSION="v0.1.11"
version="${XCONNECT_ONE_VERSION:-$DEFAULT_VERSION}"
release_base="${XCONNECT_ONE_RELEASE_BASE_URL:-https://github.com/${RELEASE_REPOSITORY}/releases/download}"

die() {
  echo "xconnect-one-install: $*" >&2
  exit 1
}

os="$(uname -s)"
arch="$(uname -m)"
default_install_dir='/usr/local/bin'
if [[ "$os:$arch" == Darwin:arm64 ]]; then
  default_install_dir='/opt/homebrew/bin'
fi
install_dir="${XCONNECT_ONE_INSTALL_DIR:-$default_install_dir}"
state_dir="${XCONNECT_ONE_STATE_DIR:-/var/lib/xconnect-one}"
unit_file="${XCONNECT_ONE_UNIT_FILE:-/etc/systemd/system/xconnect-one-sync.service}"

render_systemd_unit() {
  local bin_path="${1:-${install_dir}/xconnect}"
  local s_dir="${2:-${state_dir}}"
  cat <<EOF
[Unit]
Description=XConnect One sync watch service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${bin_path} sync --watch --interval=60s --state-dir ${s_dir}
Restart=on-failure
RestartSec=10
NoNewPrivileges=true
ProtectSystem=full
ReadWritePaths=${s_dir} /run /etc/wireguard

[Install]
WantedBy=multi-user.target
EOF
}

for arg in "$@"; do
  if [[ "$arg" == "--print-unit" ]]; then
    render_systemd_unit "${install_dir}/xconnect" "$state_dir"
    exit 0
  fi
done

[[ "$version" =~ ^v[0-9A-Za-z._-]+$ ]] || die "invalid release tag: $version"
[[ "$install_dir" = /* ]] || die 'XCONNECT_ONE_INSTALL_DIR must be absolute'
command -v curl >/dev/null || die 'curl is required'

case "$os:$arch" in
  Linux:x86_64) asset='xconnect-linux-amd64' ;;
  Linux:aarch64|Linux:arm64) asset='xconnect-linux-arm64' ;;
  Darwin:x86_64) asset='xconnect-macos-amd64' ;;
  Darwin:arm64) asset='xconnect-macos-arm64' ;;
  *) die "unsupported platform: $os/$arch (Windows uses install-xconnect-one.ps1)" ;;
esac

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/xconnect-one-install.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT
archive_url="${release_base%/}/${version}/${asset}"
sums_url="${release_base%/}/${version}/SHA256SUMS"

curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  "$archive_url" -o "$tmp_dir/$asset"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  "$sums_url" -o "$tmp_dir/SHA256SUMS"

expected="$(awk -v asset="$asset" '$2 == asset || $2 == "dist/" asset { print $1; exit }' "$tmp_dir/SHA256SUMS")"
[[ "$expected" =~ ^[[:xdigit:]]{64}$ ]] || die "SHA256SUMS has no entry for $asset"
if command -v sha256sum >/dev/null; then
  printf '%s  %s\n' "$expected" "$tmp_dir/$asset" | sha256sum -c - >/dev/null
elif command -v shasum >/dev/null; then
  actual="$(shasum -a 256 "$tmp_dir/$asset" | awk '{print $1}')"
  [[ "$actual" = "$expected" ]] || die 'release checksum mismatch'
else
  die 'sha256sum or shasum is required'
fi

install_parent="$(dirname "$install_dir")"
if [[ -d "$install_dir" && -w "$install_dir" ]] ||
  [[ ! -e "$install_dir" && -d "$install_parent" && -w "$install_parent" ]]; then
  install -d -m 0755 "$install_dir"
  install -m 0755 "$tmp_dir/$asset" "$install_dir/xconnect"
else
  command -v sudo >/dev/null || die "write access to $install_dir or sudo is required"
  sudo install -d -m 0755 "$install_dir"
  sudo install -m 0755 "$tmp_dir/$asset" "$install_dir/xconnect"
fi

echo "installed XConnect One $version ($asset) at $install_dir/xconnect"

if [[ "$os" == "Linux" ]]; then
  unit_content="$(render_systemd_unit "$install_dir/xconnect" "$state_dir")"
  unit_dir="$(dirname "$unit_file")"
  if [[ -w "$unit_dir" ]]; then
    printf '%s\n' "$unit_content" > "$unit_file"
    chmod 0644 "$unit_file"
    if command -v systemctl >/dev/null 2>&1; then
      systemctl daemon-reload || true
    fi
  elif command -v sudo >/dev/null 2>&1; then
    printf '%s\n' "$unit_content" | sudo tee "$unit_file" >/dev/null
    sudo chmod 0644 "$unit_file"
    if command -v systemctl >/dev/null 2>&1; then
      sudo systemctl daemon-reload || true
    fi
  else
    echo "xconnect-one-install: warning: cannot write to $unit_file without sudo, skipping service registration" >&2
  fi
  echo ""
  echo "XConnect One systemd service commands:"
  echo "  Start and enable: sudo systemctl enable --now xconnect-one-sync.service"
  echo "  Check status:     sudo systemctl status xconnect-one-sync.service"
  echo "  Stop and disable: sudo systemctl disable --now xconnect-one-sync.service"
fi

if [[ "$os" == "Darwin" ]]; then
  echo ""
  echo "XConnect One macOS service commands (Homebrew):"
  echo "  Start and enable: sudo brew services start xconnect-one"
  echo "  Check status:     sudo brew services info xconnect-one"
  echo "  Stop and disable: sudo brew services stop xconnect-one"
fi
