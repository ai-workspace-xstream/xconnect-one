# XConnect-One DNS 缓存自查与清理脚本

本目录提供面向客户端（macOS / Linux / Windows）的 DNS 缓存自查诊断与一键清理脚本，用于排查并解决因本地系统负缓存（Negative Cache）、DNS 劫持、分流异常或配置更新延迟导致的客户端连接故障。

## 脚本清单

| 脚本文件 | 适用平台 | 说明 |
| :--- | :--- | :--- |
| `dns-check.sh` | macOS / Linux | 全面自查系统底层解析（`getaddrinfo`）与公共/权威 DNS 差异，智能识别负缓存 |
| `dns-flush.sh` | macOS / Linux | 一键清理并重置系统级 DNS 缓存守护进程（支持自动自查验证） |
| `dns-cache.ps1` | Windows (PowerShell) | Windows 平台专用的 DNS Client 缓存检查与一键清理脚本 |

---

## 快速使用

### XConnect One shell 入口

`one.sh` 是对已安装 CLI 的最小封装。它不读取 Vault、不保存 Portal 会话，
也不生成长期凭据；Gateway 与 One 仍使用各自的 CLI 和 state 目录。

Gateway 只初始化本机身份和 `state.json`：

```bash
scripts/one.sh gateway-init \
  --controller https://accounts-uat.onwalk.net \
  --gateway-id gw-uat-tw-xconnect \
  --state-dir /var/lib/xconnect-gateway
```

macOS/Linux One 使用 Zero 签发的一次性邀请：

```bash
pbpaste | scripts/one.sh join \
  --gateway-id gw-uat-tw-xconnect \
  --handoff /path/to/xconnect-desktop-handoff-uat.json \
  --state-dir /var/lib/xconnect-one \
  --invite-stdin
```

Windows 使用管理员 PowerShell，邀请同样只从 stdin 读取：

```powershell
Get-Clipboard | .\scripts\one.ps1 join `
  -GatewayId gw-uat-tw-xconnect `
  -Handoff .\xconnect-desktop-handoff-uat.json `
  -InviteStdin
```

`join` 自动识别主机名，并依次执行 `join → sync → status → diagnose`。邀请
不写入文件或命令行参数；sudo/UAC 仍由本机管理员确认。Gateway 的 `join/up`、
One 的签名验证、runtime 启动和 ACK 仍由原生 CLI 负责。

面向终端用户的推荐顺序是：

```text
域名解析 → Gateway gateway-init → Zero Portal 签发短期邀请 → One join
```

不要使用 `curl ... | bash` 同时承载脚本和邀请 stdin；脚本内容与邀请会争用
同一个输入流。推荐先把脚本下载到 `/tmp`，再使用 `pbpaste | bash /tmp/one.sh`。

### 1. macOS / Linux

#### 诊断自查 (无需 root 权限)
```bash
# 诊断默认接入域名 (jp-xconnect.svc.plus / agent-proxy-selfhost-prod-jp.svc.plus / accounts.svc.plus)
./scripts/dns-check.sh

# 诊断指定域名
./scripts/dns-check.sh my-custom-endpoint.svc.plus

# 指定对比的公共 DNS 服务器 (默认 8.8.8.8)
./scripts/dns-check.sh -s 1.1.1.1 jp-xconnect.svc.plus
```

#### 缓存清理 (需要 sudo 权限)
```bash
# 清理系统 DNS 缓存并自动自查
sudo ./scripts/dns-flush.sh

# 清理后跳过自动自查
sudo ./scripts/dns-flush.sh --no-verify
```

---

### 2. Windows (PowerShell)

以管理员身份启动 PowerShell：

```powershell
# 仅执行自查
.\scripts\dns-cache.ps1 -Action Check

# 仅执行清理 (Clear-DnsClientCache & ipconfig /flushdns)
.\scripts\dns-cache.ps1 -Action Flush

# 先清理后自查
.\scripts\dns-cache.ps1 -Action Both
```

---

## 典型故障场景说明

* **现象**：终端 `ssh` 或客户端报 `Could not resolve hostname: nodename nor servname provided, or not known`，但 `dig` 却能查出 IP。
* **根因**：系统在域名生效前发起过查询，操作系统的 DNS 守护进程（如 macOS `mDNSResponder`）将失败结果写入了内存中的**负缓存 (Negative Cache)**。
* **处置**：直接执行 `sudo ./scripts/dns-flush.sh`，脚本重置守护进程后即刻恢复正常解析。
