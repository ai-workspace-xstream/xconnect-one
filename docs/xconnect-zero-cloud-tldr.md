# XConnect Zero Cloud TL;DR

这份文档只说明自建节点与客户端的最短操作路径。Zero/Accounts 是唯一配置与策略来源；
Gateway 与 One 是数据面运行时。短期邀请、设备凭据、WireGuard 私钥、TLS 私钥和
Vault 值均不得写进 Git、终端历史或流水线参数。

---

## 一、XConnect-One 客户端极速上手（`v0.1.22+`）

`xconnect-one` 默认启用**单二进制内嵌运行时（`--runtime=embedded`）**，内置精简版 `xray-core` 与 `wireguard-go`，无需额外安装外部 `xray` 或 `wg-quick`。

### 1.1 一键安装（Release 安装包 / 二进制）

从 [GitHub Releases (`v0.1.22`)](https://github.com/ai-workspace-xstream/xconnect-one/releases/tag/v0.1.22) 下载对应平台产物，或使用安装脚本：

```bash
# Linux / macOS 一键安装脚本
curl -fsSL https://install.svc.plus/xconnect-one | \
  sudo env XCONNECT_ONE_VERSION=v0.1.22 bash
```

也支持原生包安装：
- **macOS**：下载 `xconnect-one-macos-arm64.dmg`（或 `amd64.dmg`）
- **Debian / Ubuntu**：`sudo dpkg -i xconnect-one_0.1.22_amd64.deb`（或 `arm64.deb`）
- **RHEL / Fedora / Rocky**：`sudo rpm -Uvh xconnect-one-0.1.22.x86_64.rpm`（或 `aarch64.rpm`）
- **Windows（管理员 PowerShell）**：下载 `xconnect-one-windows-amd64.zip`（内含 `xconnect-one.exe` 与 `wintun.dll`）或执行：
  ```powershell
  $env:XCONNECT_ONE_VERSION = 'v0.1.22'
  irm https://install.svc.plus/xconnect-one.ps1 | iex
  ```

### 1.2 三步入网与后台守护启动（`login` → `join` → `up -D`）

```bash
# 1. 登录控制面（支持邮箱密码 + MFA TOTP，或 --web 浏览器 OAuth）
xconnect-one login

# 2. 绑定网关并完成设备注册（若账号尚未授权网关，会自动引导打开 Console 授权并等待完成）
xconnect-one join --gateway https://ph-xconnect-gateway-01.svc.plus

# 3. 后台守护模式启动隧道（默认日志位于 <state-dir>/runtime/xconnect-one.log）
sudo xconnect-one up -D

# 查看状态 / 停止守护进程
sudo xconnect-one status
sudo xconnect-one down
```

### 1.3 全局唯一 Device ID 与冲突自愈机制（`/etc/xconnect-one/device-id`）

为彻底避免多台同名主机（如 `ubuntu`、`localhost`）或克隆虚拟机在 `join` 时触发控制面 **HTTP 409 Conflict**：

1. **首次运行自动派生唯一 ID**：
   - 客户端自动读取 **系统 Machine ID**（`/etc/machine-id`、`/var/lib/dbus/machine-id`、`/etc/hostid`） + **首个物理网卡 MAC 地址**（自动过滤虚拟网卡） + **本地 WireGuard 公钥**，计算 8 位 Hex 指纹。
   - 生成格式：`xconnect-<os>-<short-hostname>-<8hex>`（例如 `xconnect-linux-ubuntu-8f3a1c9d`）。
2. **全局持久化**：
   - 生成后立即持久化写入 **`/etc/xconnect-one/device-id`**（非特权模式同步保存于 `<state-dir>/device-id`）。
   - 后续 `login`、`join`、`up` 均复用该全局 ID，保证设备标识与分配的 Overlay 内网 IP 稳定不变。
3. **重新生成全新 Device ID（注册为全新设备）**：
   - `/etc/xconnect-one/device-id` 是全局权威标识，支持随时重新生成；**重新生成即代表在控制面注册全新的 `device_id` 并自动轮换本地 WireGuard 密钥对**：
   ```bash
   # 方式 A：通过参数一键重新生成并入网
   sudo xconnect-one join --regenerate-device-id --gateway https://ph-xconnect-gateway-01.svc.plus

   # 方式 B：删除全局 device-id 文件后重新 join
   sudo rm -f /etc/xconnect-one/device-id
   sudo xconnect-one join --gateway https://ph-xconnect-gateway-01.svc.plus
   ```

---

## 二、自建 Gateway 与邀请码接入最短流程

用户只需要准备一个 Gateway，然后在 Zero Portal 绑定或生成一次性邀请，最后在受控
设备上执行 `xconnect-one`。Gateway 只支持 Linux Server；One 支持 Linux、macOS 和
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

### 第 3 步：Zero Portal 授权账号或签发 One 邀请

打开控制面（生产环境 `https://console.svc.plus/panel/xconnect-zero` 或 UAT [XConnect Zero Portal](https://console-serverless-uat.onwalk.net/panel/xconnect-zero)）：

- **方式 A（推荐：账号登录直接入网）**：
  在控制台将网关网络授权给当前账号，随后在终端直接运行 `xconnect-one login` 与 `xconnect-one join`。
- **方式 B（无账号自动化 / 一次性邀请码入网）**：
  1. 角色：`One`
  2. 网络：目标 UAT/PROD 网络
  3. 设备平台：`Linux`、`macOS` 或 `Windows`
  4. 设备 ID：留空（由客户端使用 `/etc/xconnect-one/device-id` 唯一 ID）或指定自定义稳定 ID
  5. 有效期：建议 `15` 分钟

点击“签发设备邀请”，然后使用页面提供的 **Copy/Run** 命令。邀请是一次性
敏感信息，不要粘贴到 Git、工单、聊天记录或公共日志。

### 第 4 步：One 使用邀请码一键加入 Gateway

在 macOS/Linux 上，One shell 会自动读取或生成全局唯一 `device-id`，并完成：

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

---

## 三、安装器与外部运行时（`--runtime=external`）说明

以下安装入口只下载、校验并安装 CLI 二进制：

```sh
# Gateway（Linux，当前 UAT release）
curl -fsSL https://install.svc.plus/xconnect-gateway | \
  sudo env XCONNECT_GATEWAY_VERSION=v0.1.6 bash

# One（Linux）
curl -fsSL https://install.svc.plus/xconnect-one | \
  sudo env XCONNECT_ONE_VERSION=v0.1.22 bash

# One（macOS；也可使用 DMG 或 Homebrew）
curl -fsSL https://install.svc.plus/xconnect-one | \
  sudo env XCONNECT_ONE_VERSION=v0.1.22 bash
```

Windows 使用管理员 PowerShell：

```powershell
$env:XCONNECT_ONE_VERSION = 'v0.1.22'
irm https://install.svc.plus/xconnect-one.ps1 | iex
```

- `xconnect-one` 默认使用内置 `--runtime=embedded`，开箱即用。
- 若需回退至系统外部 `xray` 与 `wireguard-go`/`wg` 二进制（`--runtime=external`），可通过 `--bootstrap` 准备受管外部运行时。

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

### Gateway 启动

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

---

## 四、验证闭环

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
sudo xconnect-one status
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
