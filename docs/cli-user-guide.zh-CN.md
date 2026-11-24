# XConnect One CLI 使用手册

`xconnect-one` 将认证登录、网关发现、设备入网、签名配置验证、隧道编排与诊断排障封装进一组简洁命令中，满足桌面端交互式与脚本化非交互式接入需求。

---

## 一、核心与常用命令

| 命令 | 职责 | 常用用法 |
|---|---|---|
| `xconnect-one login` | 登录 `accounts.svc.plus` 账号（支持邮箱密码 + MFA TOTP、OAuth `--web`），可选直接绑定网关 | `xconnect-one login` |
| `xconnect-one join [--gateway <url>] [--regenerate-device-id]` | 注册设备（将唯一 `xconnect-<os>-<host>-<8hex>` ID 持久化至 `/etc/xconnect-one/device-id`）并拉取签名配置 | `xconnect-one join --gateway https://ph-xconnect-gateway-01.svc.plus` |
| `xconnect-one up [-D\|--daemon] [--log-file <path>] [--runtime=embedded\|external]` | 启动 Overlay 隧道与守护循环（默认前台运行，`-D` / `--daemon` 为后台守护模式，默认日志 `<state-dir>/runtime/xconnect-one.log`） | `sudo xconnect-one up -D` |
| `xconnect-one down [--logout]` | 停止隧道 / 后台守护进程并清理网卡与路由；可选 `--logout` 清除登录会话 | `sudo xconnect-one down` |
| `xconnect-one status` | 查看隧道状态、本机 Overlay IP/CIDR、TUN 网卡与当前网关入口 / Overlay IP | `sudo xconnect-one status` |
| `xconnect-one diagnose` | 围绕状态文件、凭据与内嵌运行时执行结构化健康检查 | `sudo xconnect-one diagnose` |
| `xconnect-one debug [--prompt\|--json] [--tail N]` | 生成自动脱敏的诊断报告，以及可直接粘贴给 AI Agent 的排障提示词 | `sudo xconnect-one debug --prompt` |
| `xconnect-one version` / `-v` | 查看当前客户端版本、构建号与架构信息 | `xconnect-one -v` |

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
- `-D` / `--daemon`：后台守护模式启动隧道（默认日志写入 `<state-dir>/runtime/xconnect-one.log`）
- `--log-file`：后台守护模式自定义日志文件路径
- `--runtime`：运行时模式，默认 `embedded`（单二进制内嵌 `xray-core` + `wireguard-go`），可选 `external` 回退至外部二进制
- `--gateway`：指定或切换目标网关（支持 Gateway ID、域名或 URL 如 `https://ph-xconnect-gateway-01.svc.plus`）
- `--bootstrap`：启动前自动检查/安装受管 Xray 运行时
- `--watch` / `--interval`：持续运行并按周期向控制面同步配置（默认 `1m`）
- `--device-id` / `--name`：自定义设备 ID 与显示名称（未显式指定时默认读取或首次生成 `xconnect-<os>-<hostname>-<8hex>` 并全局持久化至 `/etc/xconnect-one/device-id`）
- `--state-dir`：状态目录（默认 `~/.xconnect-one`，无权限时自动回退到用户级目录）

### `join` 参数
- `--gateway`：绑定目标网关（支持 Gateway ID、域名或 URL）
- `--device-id`：显式指定设备 ID 并更新 `/etc/xconnect-one/device-id`
- `--regenerate-device-id`：重新生成全新的全局 `device_id`（写入 `/etc/xconnect-one/device-id`）并自动轮换本地 WireGuard 密钥对，在控制面作为全新设备注册
- `--state-dir`：状态目录

### `down` 参数
- `--logout`：断开隧道后同时清除本地登录会话
- `--state-dir`：状态目录

### `status` 与 `diagnose` 参数
- `--state-dir`：指定要检查的本地状态目录；`status` 输出隧道状态、Overlay IP/CIDR、TUN 网卡与网关信息，`diagnose` 输出状态/凭据/运行时的结构化健康检查结果

### `debug` 参数
- `--format`：输出格式，支持 `markdown`（默认）、`prompt`、`json`
- `--prompt`：仅输出可直接粘贴给 AI Agent 的脱敏排障提示词（等价于 `--format=prompt`）
- `--json`：以 JSON 格式输出脱敏诊断报告（等价于 `--format=json`）
- `--tail`：附加的后台守护日志行数（默认 `20`）
- `--state-dir`：状态目录
