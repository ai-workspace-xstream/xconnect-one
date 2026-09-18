# One：常驻同步与 ACK 契约修复（One 仓库的任务卡）

> **Status**: ⬜ 未开始（迭代 I-3 到 I-6）
> **Date**: 2026-09-18
> **Related PRs**: 待填
> **完整跨仓规划**: `xconnect-edge-agent/docs/tasks/2026-09-18-xconnect-edge-convergence-plan.md`（规则、交付循环和验收以那份文档为准）

## 为什么要改

- One 没有周期同步，只在手动执行 `xconnect sync` 后的 5 分钟内显示为绿。
- 每有新设备加入，网络的 generation 就加 1，旧 ACK 随即失效。
- 旧的 ACK 路径请求 `/api/overlay/v1/config/ack`，accounts 没有这个路由，会返回 404（`overlay/controlplane/client.go:107`、`overlay/usecase/join.go:313`）。

## 迭代（每一轮：PR → 合并 main → 打标签发版 → UAT 部署 → 验证 Goal）

UAT 部署默认走整体发版入口：
```bash
gh workflow run daily-main-snapshot.yaml -R ai-workspace-infra/platform-ops-toolkit \
  -f deploy_env=uat -f xconnect_one_release_tag=<新标签> -f enable_migration=false
```
不要填 `repositories`，填了会跳过 UAT 部署。只想单独验证 One 时，可以用 `xconnect-one-uat.yaml`，传 `cli_release_tag=<新标签>`，先 dry-run 再 apply。详见总规划 2.3.1。

| 迭代 | 任务 | 版本 | Goal |
|---|---|---|---|
| I-3 | A3：删除 `AckConfig` 和 join 里的旧分支，加路由契约测试（`testdata/accounts_overlay_v1_routes.json` 来自 accounts A4） | `v0.1.15` | UAT One 执行 apply 后，一次完整 sync 期间 accounts 日志里没有 `/api/overlay` 的 404 |
| I-4 | T0-2：`7417a57` 按决策处理；T0-3：提交 `NOTICE`（先确认 `.gitignore` 的改动） | `v0.1.16` | `net_uat` 上 dry-run 和 apply 都成功；`git ls-files NOTICE` 有输出 |
| I-5 | A2a：新增 `overlay/usecase/sync_loop.go`，`runSync` 加 `--watch` 和 `--interval`（默认 60s，范围 15–100s）；fake clock 测试覆盖总规划 A2 列出的 6 条行为 | `v0.1.17` | 不带 `--watch` 时行为不变，UAT apply 和一次性 ACK 都成功 |
| I-6 | A2b：Linux systemd `xconnect-one-sync.service`、macOS `brew services`、Windows 计划任务 | `v0.1.18` | UAT One 以常驻服务运行，30 分钟常绿；重启后自动恢复；断网 3 分钟后，恢复网络 2 分钟内回绿，期间隧道不拆 |

## 不要做

- 不要调用 `/api/overlay/v1/config/ack` 或 `/api/overlay/v1/devices/{id}/ack`。
- 网络失败时不要拆隧道。
- 融合期间只接受修复，不加新功能。
