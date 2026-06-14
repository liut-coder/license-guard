# Agent 记忆、长任务与执行编排

更新时间：2026-06-08

## 1. 恢复入口

短口令：

```text
恢复项目
继续项目
续任务
LT恢复
long-task恢复
```

恢复流程：

```text
1. 读取仓库指令，例如 AGENTS.md。
2. project-memory-loop 检索记忆，如果工具可用。
3. codex-long-task resume/status/issue-next，如果工具可用。
4. 工具不可用时，读取本文、当前上下文和下一步待办。
5. 先核对 Git checkpoint，再相信历史上下文。
6. 只执行当前 bounded issue。
```

## 2. Git-backed 进度优先

恢复时优先按已提交代码和远端状态推定进度，不要只按计划文档推断。

当前 bootstrap checkpoint：

```text
branch: unknown
head: unknown
upstream: unknown
remote: unknown
```

恢复时建议重新执行：

```text
git fetch origin main --prune
git status --short --branch
git log --oneline --decorate -n 10
```

未提交文件只作为现场痕迹，不自动视为已完成进度，也不要无关暂存。

## 3. 项目记忆

约束：

- 首期聚焦 Windows Go 授权、设备绑定、短期 token、完整性上报、后台管理闭环
- 当前目录不是 Git 仓库，不能依赖 Git 状态作为进度来源

已完成 checkpoint：

- go test ./... 通过
- scripts/smoke.sh 通过
- scripts/production-check.sh 通过
- 风险事件复核闭环已完成：API、管理台操作、持久化 `resolved_at`、`risk.resolve` 审计日志和烟测覆盖。
- 管理员退出会话闭环已完成：服务端 session 失效、管理台调用、`admin.logout` 审计日志和烟测覆盖。
- 管理后台设置闭环已完成：`GET/PATCH /admin/settings`、JSON/PostgreSQL 持久化、管理台设置页、默认授权策略、token TTL、offline grace、`settings.update` 审计日志和烟测覆盖。
- SDK Key 轮换闭环已完成：`POST /admin/apps/:id/sdk-keys/rotate`、JSON/PostgreSQL 持久化、管理台 SDK 页轮换、一次性 secret、hash-only 持久化、`sdk_key.rotate` 审计日志和烟测覆盖。
- 生产化检查闭环已完成：`docs/04-production-readiness-checklist.md` 提供人工上线门禁，`scripts/production-check.sh` 自动执行单测、构建、烟测、迁移顺序、部署文档、Admin UI JS 解析和 SDK Key 泄露防线检查。

风险 / 易错点：

- 文档 API 范围大于当前 MVP，完成声明必须逐项用文件、测试和运行结果证明

## 4. 工具与状态

```text
docs/agent-state-schema.sql
data/state.sqlite
```

`data/state.sqlite` 是本地运行态，不提交。

## 5. 写回规则

写回项目记忆：

```text
项目级约束。
重复踩坑。
稳定架构决策。
跨任务可复用模式。
用户纠正过的误导项。
```

不写回：

```text
一次性命令输出。
临时状态。
真实地址、短链、用户名、token、设备私有连接信息。
未验证猜测。
```
