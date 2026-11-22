# XConnect-One & XConnect-Gateway 跨平台安装与部署指南

`XConnect-One`（`v0.1.21+`）内置精简版 `xray-core` 与 `wireguard-go`（默认 `--runtime=embedded`，保留 `--runtime=external` 切换开关），在 **macOS / Linux / Windows / Docker 无 systemd 容器** 下均以单二进制运行，无需额外安装 `wg-quick`、`wireguard-tools` 或外部 `xray`。

---

## 1. 客户端：`XConnect-One`

### 1.1 macOS（Apple Silicon / Intel）

1. **安装或构建单二进制**
   ```bash
   git clone https://github.com/ai-workspace-xstream/xconnect-one.git && cd xconnect-one
   CGO_ENABLED=0 go build -trimpath -o /opt/homebrew/bin/xconnect-one ./cmd/xconnect
   ```
2. **登录、入网与启动**
   ```bash
   xconnect-one login
   xconnect-one join --gateway https://ph-xconnect-gateway-01.svc.plus
   sudo xconnect-one up
   ```
3. **开机自启（LaunchDaemon）**
   ```bash
   sudo env XCONNECT_ONE_STATE_DIR="$HOME/.xconnect-one-user" \
     XCONNECT_ONE_BINARY=/opt/homebrew/bin/xconnect-one \
     bash scripts/setup-xconnect-one-macos.sh
   ```

---

### 1.2 Linux（VPS / 桌面 / Grok Bot 等无 systemd 容器）

1. **安装单二进制**（无需 `wg-quick` / `xray`）
   ```bash
   git clone https://github.com/ai-workspace-xstream/xconnect-one.git && cd xconnect-one
   CGO_ENABLED=0 go build -trimpath -o /usr/local/bin/xconnect-one ./cmd/xconnect
   ```
2. **登录、入网与启动**
   ```bash
   xconnect-one login
   xconnect-one join --gateway https://ph-xconnect-gateway-01.svc.plus
   sudo xconnect-one up
   ```
   - 若通过控制台邀请链接入网：
     ```bash
     xconnect-one join "xconnect://join/<token>?controller=https%3A%2F%2Faccounts.svc.plus"
     sudo xconnect-one up
     ```
3. **Docker / 无 systemd 容器运行**
   - 容器需具备网络权限与 TUN 设备：
     ```bash
     docker run --cap-add=NET_ADMIN --device=/dev/net/tun ...
     ```
   - 直接前台运行 `xconnect-one up`；进程退出时内核自动回收 `xconone0` 网卡与路由，无僵尸网卡残留。

---

### 1.3 Windows（Windows 10 / 11 / Server）

1. **准备单二进制与 `wintun.dll`**
   - 构建或下载 `xconnect-one-windows-amd64.exe`（可从 macOS/Linux 交叉编译：`CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -o xconnect-one.exe ./cmd/xconnect`）。
   - 从 [wintun.net](https://www.wintun.net/) 下载对应架构（`amd64`）的 **`wintun.dll`**，放在与 `xconnect-one.exe` **同一目录**（或 `C:\Windows\System32\`）。
2. **以管理员身份（Administrator）打开 PowerShell 运行**
   ```powershell
   # 方式 A：账号登录入网
   .\xconnect-one.exe login
   .\xconnect-one.exe join --gateway https://ph-xconnect-gateway-01.svc.plus
   .\xconnect-one.exe up

   # 方式 B：邀请链接入网
   .\xconnect-one.exe join "xconnect://join/<token>?controller=https%3A%2F%2Faccounts.svc.plus"
   .\xconnect-one.exe up
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
