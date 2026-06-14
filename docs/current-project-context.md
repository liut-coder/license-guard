# 当前项目上下文

更新时间：2026-06-08

## 1. Long-task

```text
project_key: license-guard
title: License Guard 完整闭环
objective: 按计划推进项目完整闭环
state: data/state.sqlite
```

## 2. 当前 Git Checkpoint

```text
branch: unknown
head: unknown
upstream: unknown
remote: unknown
```

最近提交：

```text
not captured
```

当前工作树：

```text
not captured
```

## 3. 恢复方式

如果 `project-memory-loop` 和 `codex-long-task` 命令不可用，使用 file-based fallback：

```text
docs/agent-memory-long-task.md
docs/current-project-context.md
docs/project-next-actions.md
docs/agent-state-schema.sql
data/state.sqlite
```

## 4. 必读项目文档

- docs/01-development-implementation-plan.md (exists)
- docs/02-product-specification.md (exists)
- docs/03-windows-go-integration-guide.md (exists)

## 5. 当前完成范围

- go test ./... 通过
- scripts/smoke.sh 通过
- scripts/production-check.sh 通过
- 风险事件复核闭环：`POST /admin/risk-events/:id/resolve` 会设置 `resolved_at`，管理台可处理，审计日志记录 `risk.resolve`。
- 管理员退出闭环：`POST /admin/logout` 会让服务端 session 失效，管理台退出调用该接口，审计日志记录 `admin.logout`。
- 管理后台设置闭环：`GET/PATCH /admin/settings` 已实现，管理台可保存默认授权策略、安全开关和审计保留配置，默认设备数/授权期限/token TTL/offline grace 已参与业务。
- SDK Key 轮换闭环：`POST /admin/apps/:id/sdk-keys/rotate` 已实现，新 secret 只返回一次，服务端仅保存 hash/prefix，管理台 SDK 页可轮换并展示 key 状态，审计日志记录 `sdk_key.rotate`。
- 生产化检查闭环：`docs/04-production-readiness-checklist.md` 记录上线前人工门禁，`scripts/production-check.sh` 自动验证 Go 单测、构建、烟测、迁移顺序、部署文档、Admin UI JS 解析和 SDK Key 泄露防线。

## 6. 当前约束与风险

约束：

- 首期聚焦 Windows Go 授权、设备绑定、短期 token、完整性上报、后台管理闭环
- 当前目录不是 Git 仓库，不能依赖 Git 状态作为进度来源

风险：

- 文档 API 范围大于当前 MVP，完成声明必须逐项用文件、测试和运行结果证明

## 7. 成功标准

- 风险事件不仅能生成和展示，还能由管理员标记已处理并写入审计日志（已完成）
- 管理员退出不仅清理浏览器 token，还会让服务端 session 失效并写入审计日志（已完成）
- 系统设置不仅能保存，还会影响授权签发和客户端 token/offline 策略（已完成）
- SDK Key 不仅能生成，还能轮换、只显示一次 secret、避免 API 泄露 secret_hash 并写入审计日志（已完成）
- 生产化清单和部署检查不仅存在文档，还能通过 `bash scripts/production-check.sh` 自动证明关键不变量（已完成）
- 每个可交付切片都更新 docs/project-next-actions.md 和 data/state.sqlite（已完成）
