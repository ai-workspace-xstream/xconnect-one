# XConnect One CLI 使用手册

`xconnect-one` 将认证登录、网关发现、设备入网、签名配置验证及隧道编排统一封装进 **`login`**、**`up`**、**`down`** 三个核心命令中，满足桌面端交互式与脚本化非交互式接入需求。

---

## 一、核心三命令

| 命令 | 职责 | 常用用法 |
|---|---|---|
| `xconnect-one login` | 登录账号（支持邮箱密码 + MFA TOTP、OAuth `--web`），可选直接绑定网关 | `xconnect-one login` |
| `xconnect-one up` | 自动完成网关选择/入网、拉取签名配置、启动 Xray + WireGuard 隧道 | `xconnect-one up` |
| `xconnect-one down` | 断开隧道并清理网卡，保留登录会话与网关选择以便下次一键恢复 | `xconnect-one down` |

此外，可通过 `xconnect-one -v` 或 `xconnect-one version` 查看当前客户端版本。

---

## 二、网关四级选择优先级

在执行 `xconnect-one up`（或 `login --gateway`）时，客户端按以下优先级自动决定接入网关，无需手动执行额外的子命令：

1. **显式指定（最高优先级）**
   通过 `--gateway` 传入 **Gateway ID** 或 **入口域名**，支持随时切换网关：
   ```bash
   # 按入口域名指定
   xconnect-one up --gateway ph-xconnect-gateway-01.svc.plus

   # 按 Gateway ID 指定
   xconnect-one up --gateway ph-xconnect-gateway-01

   # 登录时一并指定
   xconnect-one login --gateway ph-xconnect-gateway-01.svc.plus
   ```

2. **记忆上次选择（已入网设备日常重连）**
   若本地 `state.json` 与设备凭据已存在，且未传入新的 `--gateway`，`xconnect-one up` 直接沿用上次选定的网关向控制面同步最新签名配置并拉起隧道，**零额外交互**。

3. **单网关自动选择**
   首次入网且未传 `--gateway` 时，客户端请求 `GET /api/overlay/v1/gateways`；若账号下只有一个可用网关，**自动选中并入网启动**。

4. **多网关交互 / 显式提示**
   首次入网且账号下存在多个网关、未传 `--gateway` 时：
   - **交互式终端（TTY）**：打印网关列表提示输入序号选择（回车默认第一个健康网关）：
     ```text
     Available gateways:
       [1] ph-xconnect-gateway-01 (ph-xconnect-gateway-01.svc.plus, net-ph-xconnect)
       [2] tw-xconnect-gateway-01 (tw-xconnect-gateway-01.svc.plus, net-tw-xconnect)
     Select gateway [1]:
     ```
   - **非交互模式**：报错并列出所有可用网关 ID 与域名，提示通过 `--gateway` 显式指定。

---

## 三、常见使用场景

### 3.1 交互式首次接入（推荐）
```bash
# 1. 交互式输入邮箱、密码及 MFA 动态口令
xconnect-one login

# 2. 一键接入（单网关自动选，多网关按提示选择）
xconnect-one up
```

### 3.2 非交互式 / CI 脚本接入
```bash
# 使用标准输入密码与 TOTP 动态口令登录并直接选定网关
printf "%s" "<password>" | xconnect-one login \
  --email user@example.com \
  --password-stdin \
  --totp 123456 \
  --server https://accounts.svc.plus \
  --gateway ph-xconnect-gateway-01.svc.plus

# 拉起隧道
xconnect-one up
```

> **macOS 说明**：在无桌面 Keychain 解锁的终端或自动化环境中，可加 `XCONNECT_CREDENTIAL_BACKEND=file` 使用受保护文件存储凭据（`/Users/<user>/.xconnect-one/protected/`），`up` 与 `down` 需要 `root` 权限创建 `utun` 虚拟网卡。

### 3.3 浏览器 OAuth 登录
```bash
xconnect-one login --web --provider google
xconnect-one up
```

### 3.4 日常启停与彻底登出
```bash
# 断开隧道（保留登录会话与当前网关，下次 up 直接恢复）
xconnect-one down

# 断开隧道并清除本地登录会话
xconnect-one down --logout

# 查看登录状态或隧道状态
xconnect-one login --status
xconnect-one status
```

---

## 四、WireGuard over VLESS 验证

成功执行 `xconnect-one up` 后，数据面流量按如下路径封装传输：
- **本机**：`wireguard-go`（macOS `utun*`）→ 本地 Xray → VLESS over XHTTP/TLS（`TCP 443`，路径 `/xconnect`）
- **网关**：入口代理（`:443 /xconnect`）→ Gateway Xray → 本地回环 `127.0.0.1:51820` → 内核 WireGuard（`xconzero0`）

本机验证命令：
```bash
# 查看虚拟网卡 IP（如 10.66.0.2）
ifconfig | grep -A 2 "10.66.0"

# 测试网关 Overlay 连通性
ping -c 3 10.66.0.1
```

---

## 五、参数速查

### `login` 参数
- `--server`：控制面地址（默认 `https://accounts.svc.plus`；交互式终端未指定时默认提示并支持回车确认或手动输入）
- `--email`：登录邮箱（交互模式下可省略）
- `--password-stdin`：从标准输入读取密码
- `--show-password`：在终端明文回显密码输入（默认使用 `golang.org/x/term` 隐藏输入）
- `--totp`：6 位 MFA 动态口令
- `--web` / `--provider`：通过浏览器 OAuth 登录
- `--gateway`：登录后立即入网指定网关（支持 ID、域名或 URL 如 `https://ph-xconnect-gateway-01.svc.plus`；交互模式下未指定时支持列表/默认网关选择或跳过）
- `--status`：查看当前登录会话状态
- `--state-dir`：状态目录（默认 `~/.xconnect-one`；若目录被 `root` 占用或无写权限，默认安全回退到 `~/.xconnect-one-user`，显式传参时校验权限并给出具体修复提示）

### `up` 参数
- `--gateway`：指定或切换目标网关（支持 Gateway ID、域名或 URL 如 `https://ph-xconnect-gateway-01.svc.plus`）
- `--bootstrap`：启动前自动检查/安装受管 Xray 运行时

### Linux 运行时与非 systemd 主机

`up` 在 Linux 上仅当系统 systemd 管理器真实在线时使用 `systemd-run`（依据 `/run/systemd/system`、`/run/systemd/private` 以及 PID 1 的 `comm` 是否为 `systemd`，而不是看有没有 `systemd-run` 二进制）。在 tini 等非 systemd 环境中，CLI 会以独立会话托管 Xray（及 path manager）：记录 PID 与 start-token 身份、在 `~/.xconnect-one/runtime/logs`（或指定 `--state-dir` 下的 `runtime/logs`）写入权限为 0600 的 stderr 日志，并在 `down`/失败回滚时 SIGTERM/SIGKILL 回收，避免残留孤儿进程。不会安装或伪装 systemd。

若控制面下发的 WireGuard `AllowedIPs` 包含默认路由（`0.0.0.0/0` 或 `::/0`），客户端不会把它安装成主机默认路由，而改为叠加层网段（网络 CIDR、网关 CIDR、本机地址、mesh overlay）。若无法得出叠加层意图，则拒绝启动，以免劫持主机出口。

当前源码版本号为 v0.1.20 build 25，属于未发布的开发构建，不是官方 Release 包。
- `--watch` / `--interval`：持续运行并按周期向控制面同步配置（默认 `1m`）
- `--device-id` / `--name`：自定义设备 ID 与显示名称
- `--state-dir`：状态目录（默认 `~/.xconnect-one`，无权限时自动回退到用户级目录）

### `down` 参数
- `--logout`：断开隧道后同时清除本地登录会话
- `--state-dir`：状态目录
