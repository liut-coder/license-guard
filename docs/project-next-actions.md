# 项目下一步待办

更新时间：2026-06-08

## 1. 当前 Long-task

```text
License Guard 完整闭环
```

目标：

```text
按计划推进项目完整闭环
```

## 2. Issue 队列

已完成：

1. 闭合风险事件复核与审计链路
   - objective: 风险事件不仅能生成和展示，还能由管理员标记已处理并写入审计日志。
   - file boundaries: `internal/licensecore/server.go`, `internal/licensecore/server_test.go`, `web/admin/index.html`, `scripts/smoke.sh`, `README.md`。
   - verification: `go test ./...` 通过；`bash scripts/smoke.sh` 通过。
2. 闭合管理员退出会话链路
   - objective: 后台退出需要让服务端 session 失效，并保留 `admin.logout` 审计记录。
   - file boundaries: `internal/licensecore/server.go`, `internal/licensecore/server_test.go`, `web/admin/index.html`, `scripts/smoke.sh`, `README.md`。
   - verification: `go test ./...` 通过；`bash scripts/smoke.sh` 通过。
3. 闭合管理后台设置链路
   - objective: 支持 `GET/PATCH /admin/settings`，管理台可保存默认授权策略、安全开关和审计保留配置，并让默认设备数、授权期限、token TTL、offline grace 真实参与业务。
   - file boundaries: `internal/licensecore/types.go`, `internal/licensecore/server.go`, `internal/licensecore/postgres_store.go`, `internal/licensecore/server_test.go`, `migrations/004_system_settings.sql`, `web/admin/index.html`, `scripts/smoke.sh`, `README.md`。
   - verification: `go test ./...` 通过；`bash scripts/smoke.sh` 通过。
4. 闭合 SDK Key 轮换链路
   - objective: 支持 `POST /admin/apps/:id/sdk-keys/rotate`，新 secret 只返回一次，服务端仅持久化 hash/prefix，应用详情和 SDK 页面展示 key 状态，轮换写入审计日志。
   - file boundaries: `internal/licensecore/types.go`, `internal/licensecore/server.go`, `internal/licensecore/postgres_store.go`, `internal/licensecore/server_test.go`, `migrations/005_sdk_keys.sql`, `web/admin/index.html`, `scripts/smoke.sh`, `README.md`。
   - verification: `go test ./...` 通过；`bash scripts/smoke.sh` 通过。
5. 补齐生产化清单和可验证部署检查
   - objective: 将上线前必须人工确认的事项和可自动验证的部署不变量沉淀为文档与脚本，完成前能用命令证明当前 MVP 已具备可部署检查闭环。
   - file boundaries: `docs/04-production-readiness-checklist.md`, `scripts/production-check.sh`, `README.md`, `docs/project-next-actions.md`, `docs/current-project-context.md`, `docs/agent-memory-long-task.md`, `data/state.sqlite`。
   - verification: `go test ./...` 通过；`bash scripts/smoke.sh` 通过；`bash scripts/production-check.sh` 通过。
   - documentation updates: README 增加生产检查入口；`docs/04-production-readiness-checklist.md` 增加人工上线门禁；项目上下文和长任务记忆记录该闭环。
   - commit / push expectations: 当前目录不是 Git 仓库，不能 commit / push；以文件内容、SQLite 状态和验证命令作为本轮证据。
   - unrelated dirty files to leave untouched: 不回滚历史截图、`data/store.json`、`data/signing-key.json` 等既有运行态文件。

待推进：

无。

## 3. 执行约定

每个 issue 必须明确：

```text
objective
file boundaries
verification commands
documentation updates
commit / push expectations
unrelated dirty files to leave untouched
```

任务结束：

```text
1. 运行相关验证。
2. 更新本文件和相关进度文档。
3. 更新 data/state.sqlite，如果存在。
4. 只暂存当前 issue 文件。
5. 按仓库规则 fetch / commit / push。
6. 汇报 commit、push、验证和未触碰 dirty 文件。
```

## 4. 暂缓事项

- 文档 API 范围大于当前 MVP，完成声明必须逐项用文件、测试和运行结果证明
- 当前目录不是 Git 仓库，没有 commit / push checkpoint；以文件内容和验证命令结果作为本轮证据。
