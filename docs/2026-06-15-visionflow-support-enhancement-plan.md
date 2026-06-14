# License Guard 支撑 VisionFlow 接入增强实施与验收清单

> 文档状态：当前版本草稿
> 当前版本基线日期：2026-06-15
> 主要信息来源：License Guard 当前代码结构、VisionFlow 接入需求、用户最新对齐结论
> 适用目录：`E:\AI\Game\license-guard`

## 0. 当前版本基线

- 当前阶段：License Guard 已具备服务端、Admin UI、PostgreSQL 迁移、Windows Go SDK、demo 和 smoke，但还需要为 VisionFlow 接入补齐 SDK 稳定性、部署自动化、发布注册和生产安全增强。
- 当前目标：降低 VisionFlow 接入和部署成本，让授权、版本发布、更新提示、设备绑定、完整性校验和后台运维形成可验收闭环。
- 分支策略：用户确认 `license-guard` 使用 `main`。
- 接入约束：不追求完全零配置；客户端至少需要可信的 Endpoint、App ID、Public Key 和 license 激活入口。
- 已确认不做：不把 SDK secret、服务端私钥、admin token 或生产 license key 放进客户端集成包。
- 待确认：License Guard 正式部署目标环境、安装包托管地址、代码签名证书、是否需要多租户隔离。

## 1. 增强目标

| 目标 | 判断方式 | 优先级 |
|---|---|---|
| SDK Windows 缓存稳定 | `go test ./...` 在 Windows 通过 | P0 |
| VisionFlow 可本地依赖 SDK | VisionFlow 能用 `replace` 编译接入 | P0 |
| VisionFlow 专用 App 初始化 | 后台存在 App、Release、License、Public Key | P0 |
| Release 自动登记 | 发布后不用人工复制 hash | P1 |
| 接入包生成 | 后台可下载 VisionFlow 接入配置包 | P1 |
| 部署模板 | 服务端部署从文档手工配置收敛为模板 | P1 |
| 生产安全基线 | HTTPS、PostgreSQL、密钥持久化、默认凭据处理 | P1 |
| 防共享和低成本破解 | 设备绑定、短 token、hash 校验、吊销生效 | P1 |
| 高阶完整性/风控 | WinVerifyTrust、调试器/模块/VM 信号 | P3 |

## 2. 实施清单

### P0：VisionFlow 接入前置

- [ ] 修复 Windows DPAPI 缓存 bug。

当前风险：`sdk/go/licenseguard/cache_windows.go` 中 `dpapiProtect` / `dpapiUnprotect` 返回 `unsafe.Slice(out.pbData, out.cbData)` 后再 `LocalFree`，调用方可能拿到已释放内存。

修复方式：

```go
outBytes := append([]byte(nil), unsafe.Slice(out.pbData, out.cbData)...)
return outBytes, nil
```

- [ ] 跑通 License Guard 全量测试：

```text
go test ./...
```

- [ ] 保持短期 module 兼容。

当前 module：

```text
module license-guard
```

VisionFlow 首版用本地 `replace` 接入；License Guard 本阶段不强制改 module path，避免扩大迁移影响。

- [ ] 在 Admin UI 或初始化脚本中准备 VisionFlow 专用 App。

建议默认值：

```text
AppKey: app_visionflow_windows_prod
Platform: windows
Version: 0.1.0
Entitlements:
  visionflow.automation
  visionflow.asset_mapping
  visionflow.advanced
```

- [ ] 创建首个 VisionFlow License，并验证设备数限制。
- [ ] 确认 `/v1/public-key` 返回值可用于客户端本地验签。

### P1：部署与发布自动化

- [x] 提供服务端部署模板。

建议新增：

```text
deploy/docker-compose.yml
deploy/.env.example
deploy/systemd/licenseguard.service
deploy/nginx/licenseguard.conf
```

覆盖：

```text
PostgreSQL
licenseguard-migrate
licenseguard-server
persistent -key-dir
HTTPS 反代
health check
backup path
```

已落地：

- `deploy/Dockerfile`
- `deploy/docker-compose.yml`
- `deploy/.env.example`
- `deploy/systemd/licenseguard.service`
- `deploy/systemd/licenseguard-migrate.service`
- `deploy/systemd/licenseguard.env.example`
- `deploy/nginx/licenseguard.conf`
- `deploy/README.md`

- [x] 增加 VisionFlow 接入包生成能力。

License Guard 后台生成：

```text
visionflow-license-bundle.zip
  licenseguard.config.json
  .env.example
  public_key.txt
  app_id.txt
  endpoint.txt
  integration-checklist.md
```

要求：

- 不包含 SDK secret。
- 不包含服务端私钥。
- 不包含 admin token。
- 默认不包含生产 license key。

已落地：现有 Admin UI 集成包下载接口会生成 secret-free zip，并包含 `.env.example`、`licenseguard.config.json`、`app_id.txt`、`endpoint.txt`、`public_key.txt`、`integration-checklist.md` 和 Go 接入骨架。

- [x] 增加 Release 发布 CLI 或脚本。

建议命令：

```text
licenseguardctl release publish
```

输入：

```text
app_id
platform
version
build_number
main_binary_hash
signer_thumbprint
package_sha256
download_url
release_notes
mandatory
min_supported_version
rollout_percent
```

已落地：`cmd/licenseguardctl release publish` 支持从签名后 EXE 和安装包自动计算 `main_binary_hash`、`package_sha256`，再调用 Admin API 创建 Release。

- [ ] 支持 VisionFlow 发布后自动登记 Release。

发布顺序：

```text
build VisionFlow
代码签名
计算签名后 EXE SHA-256
打安装包
计算安装包 SHA-256
上传安装包
注册 License Guard Release
```

- [ ] Admin UI 增加 VisionFlow 接入总览。

显示：

```text
App ID
Public Key 指纹
最新 Release
最新设备
最近 heartbeat
最近风险事件
接入包下载入口
```

### P1：生产安全基线

- [ ] 生产默认使用 PostgreSQL，不使用 JSON store。
- [ ] 多实例部署共享同一份 `signing-key.json` 或持久化 `-key-dir`。
- [ ] 明确备份和恢复流程，覆盖数据库和签名密钥。
- [ ] 生产必须使用 HTTPS。
- [ ] 收紧生产 CORS，避免 Admin UI/API 长期使用 `Access-Control-Allow-Origin: *`。
- [ ] 处理 demo admin：生产首次启动强制改密或生产模式禁用 demo seed。
- [ ] Admin 登录、challenge、activate、verify 增加限流或失败延迟。
- [ ] 周期清理过期 challenge，避免内存 map 长期增长。
- [ ] 日志和审计脱敏：

```text
license key 全量
SDK secret
signing private key
DATABASE_URL 密码
admin token
license token 明文
```

### P2：版本更新与客户交付优化

- [ ] 支持客户/租户授权包。

可包含：

```text
customer_name
license_key
max_devices
expires_at
entitlements
config bundle
```

说明：公共安装包不内置生产 license key；私有交付包可按客户策略预置激活信息。

- [ ] Release API 校验字段完整性。

关键字段缺失时提示：

```text
main_binary_hash
signer_thumbprint
package_sha256
download_url
```

- [ ] Admin UI 支持强制更新、最低支持版本、灰度比例的操作确认。
- [ ] 增加 update 行为 smoke：普通更新、强制更新、版本封禁、最低版本。
- [ ] 提供接入包导入说明，面向 VisionFlow 客户部署。

### P3：防破解与风控增强

- [ ] SDK 固定 public key 策略文档化：生产客户端不应每次启动动态信任 `/v1/public-key`。
- [ ] Windows SDK 增加 Authenticode / WinVerifyTrust 校验。
- [ ] 自动采集 signer thumbprint。
- [ ] 增加 debugger 基础检测。
- [ ] 增加可疑模块和 VM 指标采集。
- [ ] 风险信号只参与评分，不单点永久封禁。
- [ ] 高价值功能可缩短 token TTL。
- [ ] 增加异常系统时间风险事件。
- [ ] 将 SDK 拆成稳定版本或子模块，发布 tag，避免客户端长期依赖服务端仓库主分支。

## 3. 防破解能力边界

### 当前方案能有效防

- 普通用户共享 license。
- 复制 token 到其他设备。
- 修改本地授权缓存。
- 被吊销后长期继续使用。
- 超设备数激活。
- 使用被封禁设备。
- 使用被停用旧版本。
- 使用 hash 不匹配的篡改包。
- 长期完全离线绕过授权。

### 当前方案不能绝对防

- 专业逆向 patch 掉客户端授权检查。
- Hook 本地验签结果。
- 修改二进制后绕过客户端逻辑。
- 模拟服务端响应，尤其是客户端未固定 public key 或 HTTPS 校验不严格时。

定位：适合商业授权、防共享、防低成本破解、防内部滥用；对专业逆向是提高成本，不是绝对防护。

## 4. 验收清单

### P0 验收

- [ ] `go test ./...` 通过。
- [ ] Windows SDK `TestCachedAuthorizationAllowsSignedOfflineGrace` 通过。
- [ ] `Activate` 成功后 token 可保存并重新读取。
- [ ] 本地 token 被篡改后验签失败。
- [ ] VisionFlow 能通过本地 `replace` import SDK 并编译。
- [ ] License Guard 后台存在 VisionFlow App、Release、License。
- [ ] VisionFlow 使用有效 license 激活后，后台出现 Device 和 Activation。

### P1 验收

- [ ] 使用部署模板可启动 PostgreSQL、迁移和 License Guard API。
- [ ] `-key-dir` 持久化，重启服务后 public key 不变化。
- [ ] Admin UI 可下载 VisionFlow 接入包。
- [ ] 接入包不包含 SDK secret、私钥、admin token、生产 license key。
- [ ] Release 发布脚本能登记签名后 EXE hash 和安装包 hash。
- [ ] 客户端 verify 返回 `update.available` 时字段完整。
- [ ] `mandatory=true` 时客户端收到 `update.required=true`。
- [ ] Admin 登录、activate、verify 的限流或失败延迟生效。
- [ ] 过期 challenge 会被清理。
- [ ] 生产 CORS/HTTPS 配置有文档和模板。

### P2 验收

- [ ] 客户授权包可生成并包含 license、entitlements、设备数、过期时间。
- [ ] Release 字段缺失时 Admin/API 给出明确错误。
- [ ] `min_supported_version` 能强制旧版本升级。
- [ ] `rollout_percent` 对同一设备结果稳定。
- [ ] 版本 blocked 后客户端 verify 返回拒绝。

### P3 验收

- [ ] Windows SDK 可读取并上报 signer thumbprint。
- [ ] WinVerifyTrust 校验失败能形成风险事件。
- [ ] debugger / suspicious modules / VM indicators 能进入 integrity report。
- [ ] 高风险设备可触发短 token TTL 或 deny。
- [ ] SDK 有明确版本 tag 或子模块发布方案。

## 5. 非目标

- 不提供破解不可行的承诺。
- 不把服务端私钥或 SDK secret 下发到客户端。
- 不默认把生产 license key 打进公共安装包。
- 不把 JSON store 作为生产推荐部署。
- 不在本阶段实现 Redis、对象存储或复杂多租户计费。

## 6. 待确认问题

- License Guard 正式部署是单机、Docker Compose、还是云平台托管。
- VisionFlow 安装包下载地址由谁维护。
- 是否已有代码签名证书。
- 是否需要给不同客户生成私有接入包。
- 是否需要多环境：dev、staging、production。
