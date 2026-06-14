# License Guard 开发落地方案

## 1. 项目目标

License Guard 是一套面向多应用、多平台的软件授权与完整性验证平台。首期优先支持 Windows Go 客户端接入，后续扩展 Android、更多 Windows 技术栈和企业级授权模型。

核心目标：

- 支持多个应用统一接入授权、防破解和风险管控。
- 服务端负责最终授权判断，客户端只保存短期授权结果。
- 首期跑通 Windows Go App 的授权激活、设备绑定、完整性上报、短期 token、后台管理。
- 后续支持 Android Play Integrity、企业席位、并发授权、风控规则和审计追踪。

非目标：

- 不承诺“绝对防破解”。
- 不把授权判断完全放在客户端。
- 不在客户端内置服务端私钥或固定万能密钥。

## 2. 系统组成

```text
Admin Console
  React + Vite + TypeScript + Kumo UI style
        |
        v
Admin API / Open API
  Auth / RBAC / App Registry / License / Device / Integrity / Risk / Audit
        |
        v
PostgreSQL + Redis + Object Storage
        |
        v
Windows Go SDK / Windows Go App
```

首期建议模块：

- 管理后台：登录、总览、应用管理、授权管理、设备管理、风险事件、SDK 接入、系统设置。
- 服务端 API：管理 API、客户端验证 API、审计日志、风险事件写入。
- Windows Go SDK：初始化、challenge、activate、verify、heartbeat、DPAPI 本地缓存、完整性采集。
- 发布工具：应用版本、签名证书指纹、核心文件 hash 注册。

## 3. 推荐技术栈

前端：

- React
- Vite
- TypeScript
- Tailwind CSS
- `@cloudflare/kumo` 作为组件基础或设计语义参考

后端：

- Node.js Fastify 或 Go
- 首期如果追求和 Windows Go SDK 一致，可以后端也用 Go；如果追求后台 CRUD 效率，Fastify 更快。
- API 文档：OpenAPI 3.1

数据库：

- PostgreSQL：主业务数据
- Redis：nonce、rate limit、短期风控缓存、token 黑名单
- Object Storage：SDK 包、发布文件 hash 清单、导出报表

当前落地状态：

- 本地开发默认使用 JSON Store，便于快速启动和调试。
- 已提供 PostgreSQL schema、迁移命令和 PostgreSQL Store，可在不改变客户端 API 的情况下切换主业务存储。
- 管理员账号已进入持久化数据模型，密码使用 bcrypt hash 保存。
- Redis 和 Object Storage 仍属于后续生产化阶段。

安全：

- 管理员密码：Argon2id 或 bcrypt
- 客户端短期 token：Ed25519 或 ES256 非对称签名
- API 通信：HTTPS
- SDK Secret：只在服务端和后台受控显示，不放进客户端

## 4. 首期页面范围

```text
/login
/dashboard
/apps
/apps/:id
/licenses
/devices
/risk-events
/sdk
/settings
```

页面职责：

- `/login`：管理员登录。
- `/dashboard`：应用数、活跃授权、今日验证、高风险设备、验证趋势、实时风险事件。
- `/apps`：多应用列表、平台筛选、风险筛选、新增应用。
- `/apps/:id`：应用概览、完整性配置、授权策略、SDK 密钥。
- `/licenses`：授权签发、吊销、续期、设备数量。
- `/devices`：设备绑定、解绑、封禁、风险分。
- `/risk-events`：篡改、调试、Hook、重放、离线异常。
- `/sdk`：Windows Go 接入参数、示例代码、测试验证。
- `/settings`：默认授权策略、安全设置、审计配置。

## 5. 数据模型

### 5.1 核心表

```text
admins
roles
permissions
admin_sessions

apps
app_platforms
app_releases
app_integrity_profiles
sdk_keys

license_plans
licenses
license_entitlements

devices
activations
verify_sessions
integrity_reports

risk_events
risk_rules
revocations
audit_logs
```

### 5.2 关键字段建议

`apps`

```text
id
app_key              唯一业务标识，例如 app_nax_desktop_prod
name
description
owner_team
status              active / disabled
created_at
updated_at
```

`app_platforms`

```text
id
app_id
platform            windows / android
package_name        Android 使用
windows_product_id  Windows 使用
current_version
status
```

`app_releases`

```text
id
app_id
platform
version
channel             production / staging / beta
signer_thumbprint
main_binary_hash
resource_manifest_hash
allowed_from
blocked_from
created_at
```

`sdk_keys`

```text
id
app_id
public_key
secret_hash
key_prefix
status
last_used_at
created_at
rotated_at
```

`licenses`

```text
id
license_key_hash
license_key_prefix
app_id
plan_id
owner_type          user / organization / offline
owner_ref
max_devices
expires_at
status              active / suspended / revoked / expired
created_at
updated_at
```

`devices`

```text
id
device_fingerprint_hash
install_id_hash
platform
os_version
machine_name_hash
risk_score
status              active / blocked / pending_review
first_seen_at
last_seen_at
```

`activations`

```text
id
license_id
device_id
app_id
activation_status   active / deactivated / blocked
activated_at
last_verified_at
deactivated_at
```

`integrity_reports`

```text
id
app_id
device_id
release_id
verify_session_id
platform
app_version
signer_thumbprint
main_binary_hash
debugger_detected
hook_indicators
vm_indicators
report_json
created_at
```

`risk_events`

```text
id
app_id
device_id
license_id
event_type
severity            low / medium / high / critical
action              allow / challenge / deny / revoke / review
summary
metadata_json
created_at
```

`audit_logs`

```text
id
admin_id
action
target_type
target_id
ip
user_agent
metadata_json
created_at
```

## 6. API 设计

### 6.1 管理后台 API

```text
POST   /admin/login
POST   /admin/logout
GET    /admin/me

GET    /admin/dashboard

GET    /admin/apps
POST   /admin/apps
GET    /admin/apps/:id
PATCH  /admin/apps/:id
POST   /admin/apps/:id/releases
POST   /admin/apps/:id/sdk-keys/rotate

GET    /admin/licenses
POST   /admin/licenses
PATCH  /admin/licenses/:id
POST   /admin/licenses/:id/revoke

GET    /admin/devices
POST   /admin/devices/:id/block
POST   /admin/devices/:id/unblock
POST   /admin/devices/:id/unbind
POST   /admin/devices/:id/reverify

GET    /admin/risk-events
POST   /admin/risk-events/:id/resolve

GET    /admin/audit-logs
GET    /admin/settings
PATCH  /admin/settings
```

### 6.2 客户端验证 API

```text
GET  /v1/public-key
POST /v1/challenge
POST /v1/activate
POST /v1/verify
POST /v1/heartbeat
POST /v1/deactivate
POST /v1/integrity/report
```

首期 Windows Go App 必须接：

- `/v1/challenge`
- `/v1/activate`
- `/v1/verify`
- `/v1/heartbeat`

## 7. Windows Go 首期验证流程

```text
1. App 启动
2. SDK 读取本地缓存 token
3. 如果 token 有效，先允许进入基础功能
4. SDK 请求 /v1/challenge
5. SDK 采集完整性信息
6. SDK 提交 license_key、device_info、integrity_report 到 /v1/verify
7. 服务端验证授权、设备绑定、版本、签名、hash、风险规则
8. 服务端返回短期 license token
9. SDK 使用 Windows DPAPI 加密缓存 token
10. App 根据 token entitlements 控制功能入口
11. SDK 定期 heartbeat
```

首次激活使用 `/v1/activate`，后续常规启动使用 `/v1/verify`。

## 8. Windows Go SDK 能力

首期 SDK 包建议命名：

```text
github.com/your-org/license-guard-go
```

核心接口：

```go
type Client struct {}

func NewClient(options Options) (*Client, error)
func (c *Client) Activate(ctx context.Context, licenseKey string) (*VerifyResult, error)
func (c *Client) Verify(ctx context.Context) (*VerifyResult, error)
func (c *Client) Heartbeat(ctx context.Context) error
func (c *Client) Deactivate(ctx context.Context) error
func (c *Client) CurrentEntitlements() []string
func (c *Client) IsAllowed(feature string) bool
```

采集项：

- `app_id`
- `app_version`
- `install_id`
- `device_fingerprint`
- `os_version`
- `machine_name_hash`
- `main_binary_hash`
- `signer_thumbprint`
- `debugger_detected`
- `suspicious_modules`
- `vm_indicators`

本地缓存：

- Windows 使用 DPAPI。
- 缓存短期 token，不缓存长期 license key 明文。
- token 过期后必须重新请求服务端。

## 9. 风控策略

首期风险事件：

```text
signature_mismatch
binary_hash_mismatch
debugger_detected
suspicious_module_loaded
device_limit_exceeded
token_replay
offline_grace_exceeded
rapid_device_switch
```

建议默认动作：

```text
low       allow + log
medium    allow + shorten token ttl + log
high      deny token + create risk event
critical  revoke session + require admin review
```

注意：调试器、虚拟机、可疑模块等单个信号不建议直接永久封禁，应由服务端综合评分。

## 10. 里程碑

### M1：产品原型与数据模型，3-5 天

- 确认页面信息架构。
- 确认数据库表。
- 确认客户端验证协议。
- 输出 OpenAPI 草案。

交付物：

- UI 原型
- 产品说明书
- 开发落地方案
- Windows Go 接入指南

### M2：后端 MVP，1-2 周

- 管理员登录。
- 应用管理。
- 授权签发与吊销。
- 设备绑定。
- `/v1/challenge`、`/v1/activate`、`/v1/verify`。
- 审计日志。

验收：

- 后台可创建应用。
- 后台可签发 license。
- Windows Go Demo 可激活并获得 token。

当前实现补充：

- JSON Store 已跑通完整闭环。
- PostgreSQL 迁移文件位于 `migrations/`。
- `cmd/licenseguard-migrate` 用于执行数据库迁移。
- `cmd/licenseguard-server -store postgres` 用于以 PostgreSQL 作为运行时存储。
- 版本更新已支持下载地址、包 SHA256、强制更新、最低支持版本、灰度比例和 release 状态 PATCH。

### M3：前端管理台，1-2 周

- 登录页。
- Dashboard。
- 应用列表和详情。
- 授权管理。
- 设备管理。
- 风险事件。
- SDK 接入页。
- 版本页支持发布版本、查看更新策略、切换 active/deprecated/blocked、切换强制/推荐更新。

验收：

- 与 API 联调完成。
- 页面能完成应用创建、授权签发、查看设备、查看事件。

### M4：Windows Go SDK，1-2 周

- SDK 初始化。
- 激活、验证、心跳。
- 本地 DPAPI 缓存。
- EXE hash 采集。
- 基础 debugger 检测。
- Demo App。

验收：

- Go App 能接入 SDK。
- 断网短期可用。
- token 过期后重新验证。
- 后台可看到设备和验证日志。

### M5：完整性与风控增强，2-4 周

- Authenticode 签名验证。
- 发布版本 hash 管理。
- 风险评分。
- 封禁、复核、吊销。
- token replay 防护。

验收：

- 篡改后的二进制触发风险事件。
- 超设备数激活被拒绝。
- 被封禁设备无法获取新 token。

## 11. 部署方案

开发环境：

```text
Docker Compose
- admin-web
- api
- postgres
- redis
```

生产环境：

```text
Nginx / Cloudflare
Admin Web
API Service
PostgreSQL
Redis
Object Storage
Backup Job
Log Export Job
```

PostgreSQL 初始化：

```bash
DATABASE_URL='postgres://user:pass@host:5432/license_guard?sslmode=require' \
go run ./cmd/licenseguard-migrate -migrations-dir ./migrations
```

本地 demo 数据可选：

```bash
DATABASE_URL='postgres://user:pass@127.0.0.1:5432/license_guard?sslmode=disable' \
go run ./cmd/licenseguard-migrate -migrations-dir ./migrations -seed-demo
```

API 使用 PostgreSQL：

```bash
DATABASE_URL='postgres://user:pass@host:5432/license_guard?sslmode=require' \
go run ./cmd/licenseguard-server \
  -store postgres \
  -key-dir ./data \
  -admin-dir ./web/admin
```

小型单节点部署可临时使用 `-auto-migrate`，多副本生产环境建议由发布流水线先运行 `licenseguard-migrate`，避免多个 API 实例同时改 schema。

必须配置：

- HTTPS
- 数据库每日备份
- `-key-dir` 中的 `signing-key.json` 持久化、备份和访问控制
- Redis 持久化或可重建策略
- 后台 IP 白名单或 MFA
- 审计日志保留策略

## 12. 风险与取舍

主要风险：

- 客户端永远可被逆向，不能把核心授权逻辑放客户端。
- Windows 环境复杂，设备指纹容易因重装或硬件变化产生误判。
- 过强反调试可能误伤企业客户、开发环境和安全软件。
- 离线授权越长，破解窗口越大。

建议取舍：

- 首期优先保证商业闭环：授权、设备绑定、服务端 token。
- 完整性和反调试逐步增强，不作为第一版上线阻塞项。
- 默认 token TTL 12 小时，离线宽限期 3-7 天。
- 企业客户可放宽设备迁移和人工复核策略。

## 13. 官方参考

- Microsoft SignTool: https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool
- Microsoft WinVerifyTrust: https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust
- Microsoft DPAPI CryptProtectData: https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata
- Go Windows package: https://pkg.go.dev/golang.org/x/sys/windows
