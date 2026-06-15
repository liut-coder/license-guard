# License Guard Backup and Restore Runbook

更新时间：2026-06-16

本文定义 License Guard 生产环境的最小备份、恢复和演练流程。目标是保证 PostgreSQL 主业务数据、Ed25519 签名密钥和部署配置能恢复到同一时间点，避免恢复后出现 token 验签失败、公钥变化、授权状态丢失或审计链断裂。

## 1. 备份对象

| 对象 | 默认位置 | 必须备份 | 恢复影响 |
|---|---|---:|---|
| PostgreSQL 数据库 | `DATABASE_URL` 指向的库 | 是 | App、Release、License、Device、Activation、Policy、审计和风险事件 |
| 签名密钥目录 | `-key-dir`，Docker 为 `licenseguard_keys`，systemd 为 `/var/lib/licenseguard/keys` | 是 | `signing-key.json` 决定 license token 和 SDK 本地缓存验签 |
| 部署环境配置 | `deploy/.env` 或 `/etc/licenseguard/licenseguard.env` | 是 | 数据库连接、CORS、生产模式、bootstrap admin |
| 反代 TLS 配置 | nginx / LB / 平台证书配置 | 是 | HTTPS 入口和 Admin/API 访问 |
| 应用版本和迁移文件 | 发布包、Docker image tag、`migrations/` | 是 | 恢复后必须使用匹配 schema 的服务端版本 |

不备份对象：

- `LG_BOOTSTRAP_ADMIN_PASSWORD` 应在首次登录并改密后移除，不作为长期恢复凭据。
- SDK secret 原文只在创建或轮换时显示一次；服务端只保存 `secret_hash`，不能从备份中恢复原文。

## 2. 备份策略

最低要求：

- PostgreSQL 每日全量备份，生产高频写入时增加 WAL/PITR 或更短间隔的增量备份。
- `-key-dir` 在首次生成、每次密钥轮换、每次环境迁移前后立即备份。
- PostgreSQL dump、`signing-key.json` 和部署配置必须打上同一个恢复点标签，例如 `licenseguard-prod-20260616-010000`.
- 备份文件进入受控存储，启用加密、访问审计和最小权限。
- 至少保留最近 7 天每日备份、最近 4 周每周备份和最近 3 个月月度备份；更长周期按租户合规要求配置。

示例命令：

```bash
BACKUP_ID=licenseguard-prod-$(date -u +%Y%m%d-%H%M%S)
mkdir -p "/secure-backups/${BACKUP_ID}"

pg_dump "$DATABASE_URL" \
  --format=custom \
  --file="/secure-backups/${BACKUP_ID}/license_guard.pgcustom"

tar -C /var/lib/licenseguard \
  -czf "/secure-backups/${BACKUP_ID}/licenseguard-keys.tgz" \
  keys

cp /etc/licenseguard/licenseguard.env \
  "/secure-backups/${BACKUP_ID}/licenseguard.env"

sha256sum "/secure-backups/${BACKUP_ID}/"* \
  > "/secure-backups/${BACKUP_ID}/SHA256SUMS"
```

Docker 部署中，`licenseguard_keys` 是 volume，不要只备份容器文件系统。应从宿主机 volume 路径或一次性维护容器中导出 `keys/signing-key.json`。

## 3. 恢复顺序

恢复必须先停写，再恢复数据库和签名密钥，最后启动 API。

1. 停止 `licenseguard-server` 或把流量从该实例摘除。
2. 确认目标环境不会同时运行旧实例，避免恢复期间产生新写入。
3. 恢复 PostgreSQL：

```bash
createdb license_guard_restore
pg_restore \
  --clean \
  --if-exists \
  --dbname "$RESTORE_DATABASE_URL" \
  "/secure-backups/${BACKUP_ID}/license_guard.pgcustom"
```

4. 恢复签名密钥目录：

```bash
mkdir -p /var/lib/licenseguard
tar -C /var/lib/licenseguard \
  -xzf "/secure-backups/${BACKUP_ID}/licenseguard-keys.tgz"
chown -R licenseguard:licenseguard /var/lib/licenseguard/keys
chmod 700 /var/lib/licenseguard/keys
chmod 600 /var/lib/licenseguard/keys/signing-key.json
```

5. 恢复并检查环境配置，确保 `DATABASE_URL` 指向恢复库，`LG_PRODUCTION=true`，`-key-dir` 指向恢复后的 key 目录。
6. 运行迁移命令。恢复到旧版本时使用同版本迁移；升级恢复时先确认迁移兼容，再运行：

```bash
licenseguard-migrate \
  -database-url "$RESTORE_DATABASE_URL" \
  -migrations-dir /opt/licenseguard/migrations \
  -production=true
```

7. 启动 `licenseguard-server`，确认 `/health` 返回正常。

## 4. 恢复后验证

必须验证：

- `/v1/public-key` 返回值和恢复前记录的 public key 一致。
- Admin 可登录，且默认 demo 密码不可登录生产环境。
- 已存在 License、Device、Activation、Release、Capability Policy 可查询。
- 使用恢复前签发的有效 token 执行一次 SDK 本地验签或在线 verify。
- 使用一条演练 license 完成 activate / verify / heartbeat。
- 风险事件、审计日志和最近完整性报告可查询。
- 生产 CORS、HTTPS 入口和反代配置仍匹配目标域名。

建议命令：

```bash
curl -fsS https://licenseguard.example.com/health
curl -fsS https://licenseguard.example.com/v1/public-key
```

恢复验证通过后，记录：

- 恢复人、审批人、恢复时间、恢复点 ID。
- PostgreSQL dump sha256、`licenseguard-keys.tgz` sha256。
- 恢复前后 public key 指纹。
- 验证命令输出摘要和异常处理记录。

## 5. 演练频率

- 每月至少做一次非生产恢复演练。
- 每次变更 `-key-dir`、签名密钥、迁移链、PostgreSQL 主版本或部署平台后必须补做一次演练。
- 演练环境不得使用生产 `DATABASE_URL` 写入；恢复验证只能指向隔离库和隔离域名。

## 6. 失败边界

- 只恢复 PostgreSQL、不恢复原 `signing-key.json`：历史 token 和客户端本地缓存会验签失败，必须重新激活或发版更新公钥。
- 只恢复 `signing-key.json`、不恢复 PostgreSQL：授权、设备、Release 和审计状态会缺失，不能作为完整恢复。
- 恢复到旧数据库但使用新迁移代码：可能触发 schema 不兼容，必须先确认版本和迁移顺序。
- 丢失 `signing-key.json`：不能从 public key、license token 或 SDK cache 反推出私钥，只能进入密钥丢失事故流程。
