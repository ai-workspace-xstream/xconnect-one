# XConnect Zero Cloud TL;DR

这份文档只说明自建节点的最短操作路径。Zero/Accounts 是唯一配置与策略来源；
Gateway 与 One 是数据面运行时。短期邀请、设备凭据、WireGuard 私钥、TLS 私钥和
Vault 值均不得写进 Git、终端历史或流水线参数。

## 最短接入流程

用户只需要准备一个 Gateway，然后在 Zero Portal 生成一次性邀请，最后在受控
设备上执行 One shell。Gateway 只支持 Linux Server；One 支持 Linux、macOS 和
Windows。

### 第 1 步：准备 Gateway 域名解析

准备一个指向 Gateway 公网 IP 的 DNS-only A 记录，例如：

```text
tw-xconnect.svc.plus → Gateway 公网 IPv4
```

确认解析生效：

```bash
ping -c 1 tw-xconnect.svc.plus
```

Gateway 公网只需要开放 TCP `443`。WireGuard `51820/UDP` 只在 Gateway 本机
回环/内部转发使用，不加入公网安全组。

### 第 2 步：Gateway 执行一键初始化

SSH 登录 Linux Gateway，安装 Gateway CLI：

```bash
curl -fsSL https://install.svc.plus/xconnect-gateway | \
  sudo env XCONNECT_GATEWAY_VERSION=v0.1.6 bash
```

执行 `one shell` 初始化 Gateway 身份；只需要修改 Gateway ID 和域名：

```bash
curl -fsSL \
  https://raw.githubusercontent.com/ai-workspace-xstream/XConnect-One/main/scripts/one.sh \
  -o /tmp/xconnect-one.sh
chmod 0755 /tmp/xconnect-one.sh

sudo /tmp/xconnect-one.sh gateway-init \
  --controller https://accounts-uat.onwalk.net \
  --gateway-id gw-uat-tw-xconnect \
  --state-dir /var/lib/xconnect-gateway
```

`gateway-init` 只生成 Gateway 本机身份和受保护的 `state.json`，不会打印或
上传私钥，也不会替代后续 Zero Gateway 邀请、`join` 和 `up`。

### 第 3 步：Zero Portal 签发 One 邀请

打开当前 UAT 控制面：

[XConnect Zero Portal](https://console-serverless-uat.onwalk.net/panel/xconnect-zero)

选择：

1. 角色：`One`
2. 网络：目标 UAT/PROD 网络
3. 设备平台：`Linux`、`macOS` 或 `Windows`
4. 设备 ID：使用默认主机名或自定义稳定 ID
5. 有效期：建议 `15` 分钟

点击“签发设备邀请”，然后使用页面提供的 **Copy/Run** 命令。邀请是一次性
敏感信息，不要粘贴到 Git、工单、聊天记录或公共日志。

### 第 4 步：One 一键加入 Gateway

在 macOS/Linux 上，One shell 会自动识别主机名，并完成：

```text
join → signed config → sync → Xray/WireGuard → ACK → status/diagnose
```

macOS 从剪贴板接入：

```bash
curl -fsSL \
  https://raw.githubusercontent.com/ai-workspace-xstream/XConnect-One/main/scripts/one.sh \
  -o /tmp/xconnect-one.sh
chmod 0755 /tmp/xconnect-one.sh

pbpaste | bash /tmp/xconnect-one.sh join \
  --gateway-id gw-uat-tw-xconnect \
  --handoff /path/to/xconnect-desktop-handoff-uat.json \
  --state-dir /var/lib/xconnect-one \
  --invite-stdin
```

Linux 使用同一个脚本；把 `pbpaste` 换成系统剪贴板命令，或把 Portal 的 Copy/Run
输出安全地通过 stdin 传入：

```bash
cat /path/to/one-invite.txt | bash /tmp/xconnect-one.sh join \
  --gateway-id gw-uat-tw-xconnect \
  --handoff /path/to/xconnect-desktop-handoff-uat.json \
  --state-dir /var/lib/xconnect-one \
  --invite-stdin
```

Windows 在管理员 PowerShell 中执行：

```powershell
irm https://raw.githubusercontent.com/ai-workspace-xstream/XConnect-One/main/scripts/one.ps1 `
  -OutFile "$env:TEMP\xconnect-one.ps1"

Get-Clipboard | & "$env:TEMP\xconnect-one.ps1" join `
  -GatewayId gw-uat-tw-xconnect `
  -Handoff "$env:TEMP\xconnect-desktop-handoff-uat.json" `
  -InviteStdin
```

成功时终端会显示：

```text
PASS: XConnect One enrolled and local runtime applied.
```

### 第 5 步：验证状态

```bash
bash /tmp/xconnect-one.sh verify \
  --handoff /path/to/xconnect-desktop-handoff-uat.json
```

验证通过需要看到：

```text
joined=true
handshake=OK
PASS: XConnect One verification completed.
```

如果当前 handoff 没有 run-scoped 私网 HTTP 探针，脚本不会伪造 ping/HTTP 成功；
私网 ping/HTTP 应使用对应 UAT Cloud Lab 的验收结果。

## 一键安装入口与安全边界

以下安装入口只下载、校验并安装 CLI 二进制：

```sh
# Gateway（Linux，当前 UAT release）
curl -fsSL https://install.svc.plus/xconnect-gateway | \
  sudo env XCONNECT_GATEWAY_VERSION=v0.1.6 bash

# One（Linux）
curl -fsSL https://install.svc.plus/xconnect-one | \
  sudo env XCONNECT_ONE_VERSION=v0.1.13 bash

# One（macOS；也可使用 Homebrew）
curl -fsSL https://install.svc.plus/xconnect-one | \
  sudo env XCONNECT_ONE_VERSION=v0.1.13 bash
```

Windows 使用管理员 PowerShell：

```powershell
$env:XCONNECT_ONE_VERSION = 'v0.1.13'
irm https://install.svc.plus/xconnect-one.ps1 | iex
```

安装器只负责安装经过校验的 CLI，不会执行 `init`、`join`、`sync`、`up` 或 `down`，也不会安装或启动
Xray、WireGuard、`wireguard-go`。这些运行时必须由节点管理员从受信任来源
单独安装。

### Gateway 一键安装后初始化

安装器完成后，在 Gateway 节点显式执行初始化。`init` 只生成本机受保护的
WireGuard 身份和 `state.json`，不会自动加入网络：

```sh
sudo xconnect-gateway diagnose
sudo xconnect-gateway init \
  --state-dir /var/lib/xconnect-gateway \
  --controller https://accounts-uat.onwalk.net \
  --gateway-id gw-uat-1
```

随后由 Zero Portal 为该公钥签发一次性邀请，再执行 `join` 和 `up`。不要把邀请
放入 GitHub Actions input、公开 URL、shell history 或日志。

### One 一键安装后接入

Linux、macOS 和 Windows 使用同一生命周期：先安装 CLI 与外部运行时，再用
Zero 签发的一次性邀请显式 `join`。Linux/macOS 示例：

```sh
sudo xconnect diagnose --state-dir /var/lib/xconnect-one
sudo xconnect join --bootstrap \
  --state-dir /var/lib/xconnect-one \
  'xconnect://join/SHORT_LIVED_INVITE'
sudo xconnect sync --state-dir /var/lib/xconnect-one
sudo xconnect status --state-dir /var/lib/xconnect-one
```

Windows 管理员 PowerShell：

```powershell
& "$env:ProgramFiles\XConnect\xconnect-windows-amd64.exe" diagnose `
  --state-dir "$env:ProgramData\XConnect-One"
& "$env:ProgramFiles\XConnect\xconnect-windows-amd64.exe" join --bootstrap `
  --state-dir "$env:ProgramData\XConnect-One" `
  'xconnect://join/SHORT_LIVED_INVITE'
```

`--bootstrap` 只准备节点管理员明确允许的外部 Xray/WireGuard runtime；它不会
绕过签名验证、网络绑定、邀请有效期或 ACK。macOS standalone One 不实现
host adapter / Packet Tunnel handoff。

## macOS One

Homebrew 公式合并发布后，也可安装 One CLI：

```sh
brew install --formula \
  https://raw.githubusercontent.com/ai-workspace-xstream/XConnect-One/main/Formula/xconnect-one.rb

brew install xray wireguard-tools wireguard-go
```

安装后先确认外部运行时可见：

```sh
XCONNECT_BIN="${XCONNECT_BIN:-$(brew --prefix)/bin/xconnect}"
sudo "$XCONNECT_BIN" diagnose --state-dir /var/lib/xconnect-one
```

首次加入推荐使用受控脚本；它会在受保护终端中交互读取短期邀请：

```sh
XCONNECT_BIN="$XCONNECT_BIN" \
XCONNECT_STATE_DIR=/var/lib/xconnect-one \
bash /path/to/xconnect-one-macos-join.sh /path/to/handoff.json
```

首次 `join` 的职责：

```text
生成本机 WireGuard 密钥和受保护状态
→ 完成 Zero enrollment
→ 获取并验证签名配置
→ 生成外部 Xray transport 与 WireGuard 配置
→ 启动 Xray、WireGuard/wireguard-go
→ 读取状态并向 Accounts 发送 ACK
```

后续更新与检查：

```sh
sudo "$XCONNECT_BIN" sync --state-dir /var/lib/xconnect-one
sudo "$XCONNECT_BIN" status --state-dir /var/lib/xconnect-one
sudo wg show xconone0 latest-handshakes
```

停止 One 自己拥有的运行时：

```sh
sudo "$XCONNECT_BIN" down --state-dir /var/lib/xconnect-one
```

当前 CLI 不支持以离线缓存配置重新 `up`；停止后应使用 `sync` 重新验证签名
配置并启动。

### Linux / macOS / Windows 快速接入

统一 shell 入口：

```sh
# Gateway：只初始化本机身份和 state.json
scripts/one.sh gateway-init \
  --controller https://accounts-uat.onwalk.net \
  --gateway-id gw-uat-tw-xconnect \
  --state-dir /var/lib/xconnect-gateway

# One：自动主机名 + 一次性邀请 stdin，自动 join/sync/status/diagnose
pbpaste | scripts/one.sh join \
  --gateway-id gw-uat-tw-xconnect \
  --handoff /path/to/xconnect-desktop-handoff-uat.json \
  --state-dir /var/lib/xconnect-one \
  --invite-stdin
```

Windows 使用 `scripts/one.ps1` 和管理员 PowerShell；它保持相同的 One
生命周期，但不提供 Gateway 初始化，因为 Gateway 当前只支持 Linux Server。

`gateway-init` 与 `join` 只是薄封装：Gateway/One 的签名配置、运行时启动、
WireGuard/Xray 和 ACK 仍由对应原生 CLI 完成。不要把 Vault token、私钥或邀请
URI 固化到 shell 文件。

One 可以显式完成受管运行时准备并加入 Gateway，无需手工编写
Xray/WireGuard 配置：

```sh
sudo /usr/local/bin/xconnect join --bootstrap \
  --state-dir /var/lib/xconnect-one \
  'xconnect://join/SHORT_LIVED_INVITE'
```

该路径固定并校验 Xray 归档，使用平台受支持的包管理器安装缺失的 WireGuard
工具，并只管理 One 自己状态目录下的运行时。Windows 在管理员 PowerShell 中
使用同样的 `join --bootstrap`；macOS 使用 `sudo` 执行。

```powershell
& "$env:ProgramFiles\XConnect\xconnect-windows-amd64.exe" join --bootstrap `
  --state-dir "$env:ProgramData\XConnect-One" `
  'xconnect://join/SHORT_LIVED_INVITE'
```

## Gateway

先由 Vault 以受保护方式注入：

```text
/etc/xconnect-gateway/tls.crt
/etc/xconnect-gateway/tls.key
```

然后在 Linux Gateway 主机运行：

```sh
sudo /usr/local/bin/xconnect-gateway diagnose
sudo /usr/local/bin/xconnect-gateway init \
  --state-dir /var/lib/xconnect-gateway \
  --controller https://accounts-uat.example \
  --gateway-id gw-uat-1

# 在 Zero 确认 Gateway 公钥后，以短期邀请加入。
sudo /usr/local/bin/xconnect-gateway join \
  --state-dir /var/lib/xconnect-gateway \
  --gateway-id gw-uat-1 \
  'xconnect://join/SHORT_LIVED_INVITE'

sudo /usr/local/bin/xconnect-gateway up \
  --state-dir /var/lib/xconnect-gateway \
  --tls-cert /etc/xconnect-gateway/tls.crt \
  --tls-key /etc/xconnect-gateway/tls.key
```

Gateway 的 `up` 会同步并验证签名配置，启动外部 Xray/WireGuard，并发送 ACK。

## 验证闭环

```text
One WireGuard
  → One 本机 Xray transport
  → VLESS/XHTTP TLS TCP 443
  → Gateway Xray
  → Gateway 本机 UDP 127.0.0.1:51820
  → Gateway WireGuard
  → 授权私网资源
```

数据面通过必须同时满足：

```sh
# One
sudo "$XCONNECT_BIN" status --state-dir /var/lib/xconnect-one
sudo wg show xconone0 latest-handshakes
ping -c 3 10.77.0.1
curl --fail --max-time 10 http://10.77.0.1:8080/uat/run

# Gateway
sudo /usr/local/bin/xconnect-gateway status --state-dir /var/lib/xconnect-gateway
sudo wg show xconnect0 latest-handshakes
sudo systemctl is-active xconnect-gateway-xray.service
sudo ss -lntp | grep ':443'
```

Portal/Accounts 的 ACK 只说明已确认某一代配置，不能单独证明 handshake、ping 或
HTTP 已打通。
