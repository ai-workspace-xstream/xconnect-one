# XConnect-One

**XConnect-One** is the single-binary, cross-platform endpoint client for **XConnect Zero** — a self-hostable Zero Trust WireGuard overlay carried over VLESS/XHTTP TLS (`443`).

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

- **Online Demo**: <https://console.svc.plus/panel/xconnect-zero>
- **Gateway Repository**: <https://github.com/ai-workspace-xstream/xconnect-gateway>
- **License**: Apache 2.0 — 100% open source and self-host friendly.

---

## Key Features

- **Single-Binary Embedded Runtime (`--runtime=embedded`, default)**: Bundles minimal `xray-core` (`dokodemo-door` + `vless/xhttp/tls`, excluding ~29 MB geo assets by default) and `wireguard-go` (in-process UAPI) with native TUN/route configurators — zero external `wg-quick`, `wg`, or `xray` binaries required.
- **Coexists with AI Proxy Acceleration**: Runs WireGuard over HTTPS (`443`, VLESS/XHTTP + TLS) without hijacking your default route, allowing seamless interconnection of Linux VPS, Grok Bot containers, and home macOS/Windows machines alongside existing AI proxy tools.
- **Cross-Platform & Container Native**: Supports **macOS**, **Linux (systemd & non-systemd Docker containers)**, and **Windows (Wintun)**. TUN handles are fd-scoped and automatically cleaned up on exit.
- **Zero-Trust Security & Resilience**: Ed25519-signed configurations, automatic network-change / sleep-wake recovery with millisecond Level-1 transport hot-restart, and optional fallback to `--runtime=external`.

---

## Quick Start

### 1. macOS (Apple Silicon / Intel)

```bash
# One-shell build & install from source
rm -rf /tmp/xconnect-one && \
  git clone --depth 1 https://github.com/ai-workspace-xstream/xconnect-one.git /tmp/xconnect-one && \
  (cd /tmp/xconnect-one && CGO_ENABLED=0 GOTOOLCHAIN=auto go build -trimpath -ldflags='-s -w' -o /tmp/xconnect-one/xconnect-one ./cmd/xconnect) && \
  install -m 0755 /tmp/xconnect-one/xconnect-one /opt/homebrew/bin/xconnect-one && \
  rm -rf /tmp/xconnect-one

# Login, join gateway, and start (add -D/--daemon for background daemon mode)
xconnect-one login
xconnect-one join --gateway https://ph-xconnect-gateway-01.svc.plus
sudo xconnect-one up -D
```

Configure root LaunchDaemon autostart:

```bash
sudo env XCONNECT_ONE_STATE_DIR="$HOME/.xconnect-one-user" \
  XCONNECT_ONE_BINARY=/opt/homebrew/bin/xconnect-one \
  bash scripts/setup-xconnect-one-macos.sh
```

### 2. Linux (Debian / Ubuntu / Fedora)

```bash
# One-shell install (uses distro repo packages; GOTOOLCHAIN=auto handles Go version)
set -euo pipefail
SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"
if ! command -v git >/dev/null 2>&1 || ! command -v go >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    $SUDO apt-get update && $SUDO apt-get install -y --no-install-recommends git ca-certificates golang
  elif command -v dnf >/dev/null 2>&1; then
    $SUDO dnf install -y git ca-certificates golang
  fi
fi
rm -rf /tmp/xconnect-one
git clone --depth 1 https://github.com/ai-workspace-xstream/xconnect-one.git /tmp/xconnect-one
(cd /tmp/xconnect-one && CGO_ENABLED=0 GOTOOLCHAIN=auto go build -trimpath -ldflags='-s -w' -o /tmp/xconnect-one/xconnect-one ./cmd/xconnect)
$SUDO install -m 0755 /tmp/xconnect-one/xconnect-one /usr/local/bin/xconnect-one
rm -rf /tmp/xconnect-one
xconnect-one --version

# Login, join gateway, and start (add -D/--daemon for background daemon mode)
xconnect-one login
xconnect-one join --gateway https://ph-xconnect-gateway-01.svc.plus
$SUDO xconnect-one up -D
```

### 3. Docker / Non-systemd Containers (e.g. Grok Bot)

Run the single `linux/amd64` or `linux/arm64` binary inside any minimal container with TUN capability:

```bash
docker run --cap-add=NET_ADMIN --device=/dev/net/tun ... \
  xconnect-one up --state-dir /var/lib/xconnect-one
```

### 4. Windows (Windows 10 / 11 / Server)

1. Place `xconnect-one.exe` (`GOOS=windows GOARCH=amd64 CGO_ENABLED=0`) and `amd64` [`wintun.dll`](https://www.wintun.net/) in the same directory.
2. Run in an **Administrator** PowerShell:

```powershell
.\xconnect-one.exe login
.\xconnect-one.exe join --gateway https://ph-xconnect-gateway-01.svc.plus
.\xconnect-one.exe up
# Or run detached in the background:
.\xconnect-one.exe up -D
```

> Invite-based enrollment also works on all platforms:
> `xconnect-one join "xconnect://join/<token>?controller=https%3A%2F%2Faccounts.svc.plus"`

---

## Common Commands

| Command | Description |
| :--- | :--- |
| `xconnect-one login` | Authenticate with `accounts.svc.plus` |
| `xconnect-one join [--gateway <url>] [--regenerate-device-id]` | Enroll device (persisting unique `xconnect-<os>-<host>-<8hex>` ID to `/etc/xconnect-one/device-id`) and fetch signed config |
| `xconnect-one up [-D\|--daemon] [--log-file <path>] [--runtime=embedded\|external]` | Start overlay tunnel and supervision loop (foreground by default, or background daemon with `-D` / `--daemon`; default log `<state-dir>/runtime/xconnect-one.log`) |
| `xconnect-one down` | Stop tunnel/background daemon and clean up interface/routes |
| `xconnect-one status` / `diagnose` | Inspect tunnel status and runtime health |

---

## Documentation

| Document | Topic |
| :--- | :--- |
| [docs/xconnect-zero-cloud-tldr.md](docs/xconnect-zero-cloud-tldr.md) | Quick TL;DR operational guide (client onboarding, global `/etc/xconnect-one/device-id`, gateway setup) |
| [docs/cross-platform-install-and-deployment.md](docs/cross-platform-install-and-deployment.md) | Full installation & deployment guide (macOS, Linux, Docker, Windows, Gateway) |
| [docs/cli-user-guide.zh-CN.md](docs/cli-user-guide.zh-CN.md) | Chinese CLI user guide |
| [docs/macos-runtime-setup.md](docs/macos-runtime-setup.md) | macOS LaunchDaemon autostart & recovery |
| [docs/windows-runtime.md](docs/windows-runtime.md) | Windows runtime & Wintun notes |
| [docs/self-hosted-install-and-validation.md](docs/self-hosted-install-and-validation.md) | Self-hosted deployment & validation |
| [docs/self-registration.md](docs/self-registration.md) | Device self-registration workflow |
| [docs/zero-lab.md](docs/zero-lab.md) | Local Zero lab testing |

---

## License

Licensed under the [Apache License 2.0](LICENSE).
