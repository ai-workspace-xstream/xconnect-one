# One 多设备自适应数据面

## 仓库边界

- `xconnect-edge-agent`：Gateway / One 注册、向 Zero 上报，未来统一管理 GPG 证书、UUID、用户 Auth。只读运行状态，不控制 UDP 路径、不持有新的数据面私钥副本。
- `XConnect-Gateway`：核心 relay，认证会话并按 Zero 签名的 peer 授权转发密文。
- `XConnect-One`：边缘 WireGuard 和逐 peer 路径管理。
- Zero / Accounts：既有授权控制面，签发成员、公钥、overlay 地址和到期时间。LAN 地址是候选信息，不是授权依据。

```text
应用 → overlay / WireGuard → 每个 peer 的稳定 loopback UDP → One 路径管理器
                                                        ├─ LAN UDP → 对端路径管理器 → WireGuard → 应用
                                                        └─ Xray VLESS / XHTTP / TLS → Gateway relay → 对端
```

## 最小接入方式

保留外部 WireGuard、原 Gateway peer 和原 UDP transport。仅对有授权的 One peer 添加更精确的 /32 或 /128 AllowedIPs，Endpoint 指向各自独立的动态 loopback UDP socket。WireGuard 会话与地址不随 LAN / relay 切换变化。

One 经既有 Xray 通道建立独立 TCP relay 会话。Gateway 新增 loopback TCP 51821 的固定协议入口，原 UDP 51820 保持原职责。One 本地监听端口、LAN 地址、设备 ID、peer 数量均从签名配置和运行环境取得；不存在 A / B / C 设备特例。

## 自动发现与自适应

1. Zero 签名配置提供授权成员、公钥、overlay 单地址。One 通过认证的 relay 交换 peer 签名的 LAN 候选。
2. 每秒刷新物理网卡地址和掩码，仅探测本机 on-link 的私有 IPv4；排除 loopback、overlay、utun / tun / wg 等虚拟网卡。
3. 每个 peer 独立维护候选、nonce、ACK、RTT 和探测健康。连续 3 次有效 ACK 切直连；4 秒无 ACK 回 relay。保留健康选中的 NIC，避免细微 RTT 差异引发抖动。
4. 两条路径一直可以接收，但每个数据包只选择一条发送路径。网卡候选撤销立即取消对应 LAN 状态；睡眠恢复、地址变化和 UDP 暂时错误由后续探测自愈。
5. 每个设备对依据签名设备 ID 的排序确定一个空闲 WireGuard keepalive 发起方，避免多节点同时启动时双方空闲握手冲突；双方仍可发起应用流量。数据面序号和 epoch 逐 peer 独立，其他设备的大量探测不能耗尽当前 peer 的重排窗口。
6. 签名成员变更保留未变 peer 的 socket、路径状态与运行进程，通过 `wg syncconf` 更新 peer；身份、传输或基础 WireGuard 配置变化仍走既有完整事务。

不依赖固定设备名单、广播域标签或公网 IP 相同。当前候选交换需要 Gateway 可达；已建立的 LAN 路径可在 Gateway 暂时中断时继续运行至签名配置过期。没有实现 mDNS、跨公网 NAT 穿透、STUN / ICE，IPv6 LAN 直连留待后续。

## 授权与兼容

签名配置可选 `mesh` 字段；关闭功能时既有签名规范和数据面不变。外部 WireGuard 当前没有跨平台解密后端口 ACL 接口，因此仅在 Zero 策略的完整规则显式标记 `whole_device: true`、且允许双向互通时签发 mesh。该标记明确授权所有 IP 协议的设备流量；仅 TCP/UDP 全端口和 ICMP 规则不会自动变成整设备授权。端口受限、单向、存在 deny 或默认无授权的设备对继续使用原 Gateway 路径，绝不扩大原策略。

本轮支持桌面 Linux / macOS / Windows runtime；移动端继续原模式。单节点上限为 256 个授权 peer，LAN 候选上限 32；这些是资源边界，不是硬编码拓扑。MTU 最高 1280，LAN 二进制封装在标准 1500 MTU 下无需 IP 分片。

LAN 信封使用 WireGuard X25519 密钥派生的域隔离 HMAC；Gateway 会话另用 relay 域，challenge 防重放。peer 层有 session epoch 和 64 包重排窗口；WireGuard 再独立验证端到端密文。Gateway 不解密应用流量。配置过期关闭数据面 socket，撤销依赖已签配置下发 / 轮询，未及时拿到撤销的离线节点最多保留旧授权到其 TTL。

## 开启与观测

在 Accounts 显式配置 `XCONNECT_OVERLAY_MESH_NETWORKS=<network-id,...>`，先部署兼容 Gateway / One，再开启网络。无需给每台 One 配对端 LAN 地址。

One 自动管理内部 `xconnect path-manager` 子进程；它读取受保护的既有 WireGuard 配置中的私钥。状态文件：`<state-dir>/runtime/overlay-status.json`，以及 revision 目录内的 `paths.json`。edge-agent 的 `agent.overlayStatusPath` 配置指向状态文件，Agent 的 NodeID / NetworkID / Role 必须与文件一致。报告仅包含能力、健康、路径、原因、RTT、计数和时间，不输出密钥。

## 本地验证

独立仓库测试覆盖签名兼容、授权限制、重放 / 篡改、真实 relay 认证、运行生命周期和动态成员更新。Gateway `tests/mesh/run.sh ONE_CHECKOUT ACCOUNTS_CHECKOUT` 使用临时 Go module 和临时测试密钥，运行 3 个真实 WireGuard-go netstack，验证 HTTP、LAN 提升、逐 peer 回退与恢复、同一 TCP 连接连续传输、反向发起、撤销、未受影响 peer，以及 Gateway relay 停止后已建立 LAN 仍能传输 HTTP。第二条测试使用实际 One / Gateway renderer 产出的 Xray VLESS / XHTTP / TLS 链路。

netstack 测试使用可控 loopback 候选模拟故障，不修改宿主路由；不能替代真实多设备、多网卡、休眠及 UAT 验收。发布和部署需另行执行并验证。
