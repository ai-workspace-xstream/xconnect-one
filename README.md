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

### 1. macOS (Homebrew + LaunchDaemon Autostart)

Install to the standard Homebrew prefix (`/opt/homebrew/bin` on Apple Silicon, `/usr/local/bin` on Intel):

```bash
# Option A: Install via Homebrew formula (or build from source into Homebrew bin)
brew install --formula ./Formula/xconnect-one.rb

# Option B: Build latest main directly into Homebrew prefix
rm -rf /tmp/xconnect-one && \
  git clone --depth 1 https://github.com/ai-workspace-xstream/xconnect-one.git /tmp/xconnect-one && \
  (cd /tmp/xconnect-one && CGO_ENABLED=0 GOTOOLCHAIN=auto go build -trimpath -ldflags='-s -w' -o /tmp/xconnect-one/xconnect-one ./cmd/xconnect) && \
  install -m 0755 /tmp/xconnect-one/xconnect-one "$(brew --prefix)/bin/xconnect-one" && \
  ln -sf "$(brew --prefix)/bin/xconnect-one" "$(brew --prefix)/bin/xconnect" && \
  rm -rf /tmp/xconnect-one

# Login & enroll
xconnect-one login
xconnect-one join --gateway https://ph-xconnect-gateway-01.svc.plus
```

Register and start the standard **LaunchDaemon** (`/Library/LaunchDaemons/com.xconnect.one.plist`) for boot autostart:

```bash
sudo env XCONNECT_ONE_STATE_DIR="$HOME/.xconnect-one-user" \
  XCONNECT_ONE_BINARY="$(brew --prefix)/bin/xconnect-one" \
  bash scripts/setup-xconnect-one-macos.sh
sudo launchctl bootstrap system /Library/LaunchDaemons/com.xconnect.one.plist

# Or run manually without LaunchDaemon:
sudo xconnect-one up -D
```

### 2. Linux (Standard Directories + systemd Autostart)

Install via `.deb` / `.rpm` release package (installs `/usr/bin/xconnect-one` and `/etc/systemd/system/xconnect-one-sync.service`) or via the installer script (`/usr/local/bin/xconnect` + `/var/lib/xconnect-one`):

```bash
# Option A: Install release package (Debian/Ubuntu .deb or Fedora/RHEL .rpm)
# sudo dpkg -i xconnect-one_<version>_amd64.deb   # Debian / Ubuntu
# sudo rpm -Uvh xconnect-one-<version>.x86_64.rpm # Fedora / RHEL

# Option B: Build from source into standard /usr/local/bin
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
$SUDO ln -sf /usr/local/bin/xconnect-one /usr/local/bin/xconnect
rm -rf /tmp/xconnect-one
```

Enroll and enable the default **systemd** service (`xconnect-one-sync.service`) for boot autostart:

```bash
sudo xconnect-one login --state-dir /var/lib/xconnect-one
sudo xconnect-one join --gateway https://ph-xconnect-gateway-01.svc.plus --state-dir /var/lib/xconnect-one
sudo systemctl enable --now xconnect-one-sync.service
sudo systemctl status xconnect-one-sync.service
```

### 3. Non-systemd / Special Environments (e.g. Docker, Grok Bot)

In containers or minimal Linux environments without `systemd`, run the single `linux/amd64` or `linux/arm64` binary with `NET_ADMIN` + `/dev/net/tun` using either **foreground mode** (`up`) or **built-in background daemon mode** (`up -D`):

```bash
# Foreground mode (recommended for container PID 1 / supervisord)
docker run --cap-add=NET_ADMIN --device=/dev/net/tun ... \
  xconnect-one up --state-dir /var/lib/xconnect-one

# Built-in self-daemonizing background mode (writes PID & logs under <state-dir>/runtime/)
xconnect-one up -D --state-dir /var/lib/xconnect-one
```

### 4. Windows (Standard Program Files + Task Scheduler Autostart)

1. Install into `C:\Program Files\XConnect\` (place `xconnect-one.exe` and matching `amd64` [`wintun.dll`](https://www.wintun.net/) in the same directory) with standard state directory `C:\ProgramData\XConnect`:
2. Run in an **Administrator** PowerShell to enroll and register boot autostart via **Windows Task Scheduler** (`SYSTEM` at startup):

```powershell
$InstallDir = "$env:ProgramFiles\XConnect"
$StateDir   = "$env:ProgramData\XConnect"
$ExePath    = Join-Path $InstallDir "xconnect-one.exe"

# Login & enroll into standard system state directory
& $ExePath login --state-dir $StateDir
& $ExePath join --gateway https://ph-xconnect-gateway-01.svc.plus --state-dir $StateDir

# Register standard SYSTEM startup task (or use scripts/install-xconnect-one.ps1)
schtasks /create /tn XConnectOneSync `
  /tr "`"$ExePath`" sync --watch --interval=60s --state-dir `"$StateDir`"" `
  /sc onstart /ru "SYSTEM" /rl HIGHEST /f
schtasks /run /tn XConnectOneSync

# Or run manually in foreground / background daemon mode:
# & $ExePath up --state-dir $StateDir
# & $ExePath up -D --state-dir $StateDir
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
| `xconnect-one status` | Inspect tunnel status, local overlay IP/CIDR, TUN interface, and gateway endpoint/overlay IP |
| `xconnect-one diagnose` | Run structured health checks across state, credentials, and embedded runtime |
| `xconnect-one debug [--prompt\|--json] [--tail N]` | Generate a secret-redacted diagnostic report and copy-pasteable AI Agent debug prompt |

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
