# Production Readiness Checklist

更新时间：2026-06-08

本文用于把 License Guard MVP 从“功能闭环”推进到“上线前可验证”。自动检查负责证明代码、迁移、烟测和关键安全不变量仍然成立；人工检查负责确认环境、运维和租户安全配置已经到位。

## 1. 自动检查

从项目根目录运行：

```bash
bash scripts/production-check.sh
```

该脚本会执行并校验：

- `go test ./...`
- `go build -buildvcs=false ./cmd/licenseguard-server ./cmd/licenseguard-migrate`
- `bash scripts/smoke.sh`
- `migrations/001_initial_schema.sql` 到 `migrations/007_capability_policies.sql` 文件顺序和 `schema_migrations` 记录
- Admin UI 内联 JavaScript 可解析
- README 和部署文档包含 PostgreSQL、迁移、`-key-dir`、备份、HTTPS、demo seed 限制和多副本迁移约束
- SDK Key API 使用 `SDKKeyView`，管理台不引用 `secret_hash`，单测和烟测覆盖 `secret_hash` 不泄露

上线前必须保留本次脚本输出摘要、执行人、日期和目标版本。任何失败项都应先修复，再重新执行完整脚本。

## 2. PostgreSQL 与迁移

- 生产运行使用 `-store postgres` 和 `DATABASE_URL`。
- `DATABASE_URL` 使用 TLS，例如 `sslmode=require`，并通过部署平台 secret 注入。
- 多副本生产环境先由发布流水线运行 `licenseguard-migrate`，再启动或滚动 API 实例。
- `-auto-migrate` 只用于小型单节点或临时环境，不作为多副本生产默认方案。
- `licenseguard-migrate -seed-demo` 仅用于本地或演示数据库，生产租户不得执行 demo seed。
- 数据库备份必须覆盖恢复演练，不只检查备份任务是否存在。

## 3. 签名密钥

- `-key-dir` 必须挂载到持久化磁盘或受控 secret volume。
- `signing-key.json` 需要备份、访问控制和恢复流程。
- 多实例部署必须共享同一份签名私钥；否则客户端 token 验签会不稳定。
- 公钥可以发布给 SDK；私钥不得进入客户端、日志、截图或工单。

## 4. 网络与后台安全

- API 和 Admin UI 对外只通过 HTTPS 暴露。
- `LG_CORS_ALLOWED_ORIGINS` / `-cors-allowed-origins` 必须配置为具体 HTTPS Origin；生产不得使用 `*`。
- 后台入口配置 IP 白名单、MFA 或等效访问控制。
- 首次生产启动后立即替换 demo 管理员凭据，确认默认密码不可登录。
- 敏感操作确认、审计保留天数、token TTL、offline grace、默认设备数和默认授权天数按租户策略配置。
- 日志不得记录 `DATABASE_URL` 明文密码、license key 全量、SDK secret、私钥或 `secret_hash`。

## 5. 发布与 SDK 接入

- 每个生产版本登记主程序 hash、签名指纹、包 hash、下载地址和 rollout 策略。
- 强制升级、最低支持版本、版本封禁、设备封禁、授权暂停/恢复/吊销都需要在 smoke 或演练租户验证。
- SDK secret 只在创建或轮换时显示一次，生产环境按密钥管理流程保存。
- 客户端本地缓存 token 必须使用 `/v1/public-key` 发布的 Ed25519 公钥验签。

## 6. 运行边界

- JSON store 只用于本地开发。
- 当前 MVP 已提供 PostgreSQL 主业务存储；Redis、Object Storage、导出报表等仍是后续生产化增强项。
- 完成上线前检查不代表跳过监控、告警、备份恢复演练或安全评审。
