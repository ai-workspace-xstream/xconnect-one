# XConnect-One & XConnect-Gateway 跨平台安装与部署指南

`XConnect-One`（`v0.1.21+`）内置精简版 `xray-core` 与 `wireguard-go`（默认 `--runtime=embedded`，保留 `--runtime=external` 切换开关），在 **macOS / Linux / Windows / Docker 无 systemd 容器** 下均以单二进制运行，无需额外安装 `wg-quick`、`wireguard-tools` 或外部 `xray`。

---

## 1. 客户端：`XConnect-One`

### 1.1 macOS（Apple Silicon / Intel + LaunchDaemon 开机自启）

1. **安装或构建单二进制**（安装到标准 Homebrew 前缀：Apple Silicon 为 `/opt/homebrew/bin`，Intel 为 `/usr/local/bin`）：
   - **方式 A（Release DMG / Homebrew Formula）**：
     从 [GitHub Releases](https://github.com/ai-workspace-xstream/xconnect-one/releases) 下载 `xconnect-one-macos-arm64.dmg`（或 `amd64.dmg`），或通过仓库内 Formula 安装：
     ```bash
     brew install --formula ./Formula/xconnect-one.rb
     ```
   - **方式 B（从最新 `main` 源码直接构建到 Homebrew 前缀）**：
     ```bash
     rm -rf /tmp/xconnect-one && \
       git clone --depth 1 https://github.com/ai-workspace-xstream/xconnect-one.git /tmp/xconnect-one && \
       (cd /tmp/xconnect-one && CGO_ENABLED=0 GOTOOLCHAIN=auto go build -trimpath -ldflags='-s -w' -o /tmp/xconnect-one/xconnect-one ./cmd/xconnect) && \
       install -m 0755 /tmp/xconnect-one/xconnect-one "$(brew --prefix)/bin/xconnect-one" && \
       ln -sf "$(brew --prefix)/bin/xconnect-one" "$(brew --prefix)/bin/xconnect" && \
       rm -rf /tmp/xconnect-one
     ```
2. **登录与入网**：
   ```bash
   xconnect-one login
   xconnect-one join --gateway https://ph-xconnect-gateway-01.svc.plus
   ```
3. **注册标准 LaunchDaemon 开机自启（`/Library/LaunchDaemons/com.xconnect.one.plist`）或手动启停**：
   ```bash
   sudo env XCONNECT_ONE_STATE_DIR="$HOME/.xconnect-one-user" \
     XCONNECT_ONE_BINARY="$(brew --prefix)/bin/xconnect-one" \
     bash scripts/setup-xconnect-one-macos.sh
   sudo launchctl bootstrap system /Library/LaunchDaemons/com.xconnect.one.plist

   # 或不使用 LaunchDaemon，手动前台 / 后台守护运行：
   # sudo xconnect-one up
   # sudo xconnect-one up -D
   ```

---

### 1.2 Linux（标准目录 + systemd 开机自启）

1. **安装单二进制**（无需外部 `wg-quick`、`wireguard-tools` 或 `xray`）：
   - **方式 A（`.deb` / `.rpm` 原生安装包）**：
     安装 `/usr/bin/xconnect-one` 并自动注册 `/etc/systemd/system/xconnect-one-sync.service`：
     ```bash
     # Debian / Ubuntu
     sudo dpkg -i xconnect-one_<version>_amd64.deb

     # Fedora / RHEL / Rocky
     sudo rpm -Uvh xconnect-one-<version>.x86_64.rpm
     ```
   - **方式 B（从源码一键构建到 `/usr/local/bin`）**：
     ```bash
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
2. **入网并启用默认 `systemd` 服务（`xconnect-one-sync.service`）**：
   ```bash
   sudo xconnect-one login --state-dir /var/lib/xconnect-one
   sudo xconnect-one join --gateway https://ph-xconnect-gateway-01.svc.plus --state-dir /var/lib/xconnect-one
   sudo systemctl enable --now xconnect-one-sync.service
   sudo systemctl status xconnect-one-sync.service
   ```

---

### 1.3 非 systemd / 容器环境（Docker、Grok Bot 等）

在没有 `systemd` 的容器或精简 Linux 环境中，使用具备 `NET_ADMIN` 权限与 `/dev/net/tun` 设备的单个 `linux/amd64` 或 `linux/arm64` 二进制即可运行；TUN 句柄由文件描述符（fd）托管，进程退出时内核自动回收网卡与路由，无僵尸网卡残留：

- **前台模式（推荐用于容器 PID 1 或 `supervisord`）**：
  ```bash
  docker run --cap-add=NET_ADMIN --device=/dev/net/tun ... \
    xconnect-one up --state-dir /var/lib/xconnect-one
  ```
- **内置自守护后台模式（将 PID 与日志写入 `<state-dir>/runtime/`）**：
  ```bash
  xconnect-one up -D --state-dir /var/lib/xconnect-one
  ```

---

### 1.4 Windows（标准 `Program Files` + Task Scheduler 开机自启）

1. **准备单二进制与 `wintun.dll`**：
   - 从 [GitHub Releases](https://github.com/ai-workspace-xstream/xconnect-one/releases) 下载 `xconnect-one-windows-amd64.zip`（或单独编译：`CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o xconnect-one.exe ./cmd/xconnect`）。
   - 将 `xconnect-one.exe` 与对应 `amd64` 架构的 [`wintun.dll`](https://www.wintun.net/) 放入标准安装目录 `C:\Program Files\XConnect\`，标准状态目录为 `C:\ProgramData\XConnect`。
2. **以管理员身份（Administrator）打开 PowerShell 入网并注册 Task Scheduler（`SYSTEM` 开机启动）**：
   ```powershell
   $InstallDir = "$env:ProgramFiles\XConnect"
   $StateDir   = "$env:ProgramData\XConnect"
   $ExePath    = Join-Path $InstallDir "xconnect-one.exe"

   # 登录并入网至标准系统状态目录
   & $ExePath login --state-dir $StateDir
   & $ExePath join --gateway https://ph-xconnect-gateway-01.svc.plus --state-dir $StateDir

   # 注册标准 SYSTEM 开机任务（也可使用 scripts/install-xconnect-one.ps1）
   schtasks /create /tn XConnectOneSync `
     /tr "`"$ExePath`" sync --watch --interval=60s --state-dir `"$StateDir`"" `
     /sc onstart /ru "SYSTEM" /rl HIGHEST /f
   schtasks /run /tn XConnectOneSync

   # 或手动在前台 / 内置后台守护模式运行：
   # & $ExePath up --state-dir $StateDir
   # & $ExePath up -D --state-dir $StateDir
   ```

---

### 1.5 一次性邀请链接入网（全平台通用）

以上所有平台除通过 `login` + `join --gateway` 账号入网外，均支持直接消费控制台签发的一次性邀请链接：

```bash
xconnect-one join "xconnect://join/<token>?controller=https%3A%2F%2Faccounts.svc.plus"
sudo xconnect-one up -D
```

---

## 2. 网关端：`XConnect-Gateway`（Linux VPS）

1. **从 GitHub Release 下载二进制**（以 `v0.1.14` 为例，ARM64 替换为 `xconnect-gateway-linux-arm64`）：
   ```bash
   curl -fsSL https://github.com/ai-workspace-xstream/xconnect-gateway/releases/download/v0.1.14/xconnect-gateway-linux-amd64 -o /usr/local/bin/xconnect-gateway
   chmod 0755 /usr/local/bin/xconnect-gateway
   ```
2. **校验宿主依赖并加入/应用策略**（宿主需具备 `wg`、`wg-quick`、`xray`、`iptables`、`iptables-restore`）：
   ```bash
   xconnect-gateway diagnose
   xconnect-gateway join --gateway-id <gateway_id> "<invite_uri>"
   xconnect-gateway apply
   ```
3. **常用运维命令**：
   - 查看状态与当前生效策略版本：`xconnect-gateway status`
   - 停止网关并自动清理 `XCONNECT_ZERO_FWD` 链：`xconnect-gateway down`
