# License Guard 支撑 VisionFlow 授权产品化实施与验收清单

> 文档状态：当前版本草稿
> 当前版本基线日期：2026-06-15
> 主要信息来源：License Guard 当前代码结构、VisionFlow 接入需求、用户最新对齐结论
> 适用目录：`E:\AI\Game\license-guard`

## 0. 当前版本基线

- 当前阶段：License Guard 已具备服务端、Admin UI、PostgreSQL 迁移、Windows Go SDK、demo、smoke、部署模板、集成包、Release 发布 CLI 和 VisionFlow 业务完整性摘要上报；VisionFlow 授权链路已能本地联调，但试用配置和授权拦截体验仍偏工程化。
- 当前目标：将 License Guard 从“授权 API + SDK”升级为 VisionFlow 的授权产品化控制中心，覆盖一键试用、能力策略、可视化配置、Release 自动化、授权诊断和生产安全基线。
- 分支策略：用户确认 `license-guard` 使用 `main`。
- 接入约束：不追求完全零配置；客户端至少需要可信的 Endpoint、App ID、Public Key 和 license 激活入口。
- 已确认不做：不把 SDK secret、服务端私钥、admin token 或生产 license key 放进客户端集成包。
- 已确认新方向：能力定义和强制边界由 VisionFlow 内置；拦截策略、套餐、客户差异和可视化配置由 License Guard 管理；客户端配置只能收紧体验，不能绕过 license entitlement。
- 已确认新增风险：VisionFlow 核心业务定义大量落在本地 SQLite、图片资源和 workflow 文件中；License Guard 不直接保护这些文件，但需要接收 VisionFlow 的完整性上报并参与授权拒绝、风险事件和版本基线管理。
- 已确认本地加密边界：VisionFlow 可使用 SQLCipher、强随机密钥、Windows DPAPI 或 Credential Manager 保护本地 SQLite；License Guard 不生成、不保存、不恢复客户端本地 DB 密钥。
- 待确认：License Guard 正式部署目标环境、安装包托管地址、代码签名证书、套餐/客户模型是否进入首期可视化。

## 1. 最终形态与配置归属

License Guard 最终承担 VisionFlow 授权策略中心角色：

```text
License Guard Admin UI
  - App / Release / License
  - Entitlement / Plan / Customer
  - Capability Policy
  - VisionFlow bootstrap / integration bundle
        ↓ signed policy + license token
VisionFlow License Provider
  - 拉取 license 状态
  - 拉取 signed policy
  - 本地缓存和诊断
        ↓
VisionFlow Capability Gate
  - 前端体验拦截
  - 后端强制拦截
  - 任务启动/恢复/批量/导出统一校验
```

| 配置 | 归属 | 是否可视化 | 约束 |
|---|---|---:|---|
| capability 名称和安全等级 | VisionFlow 代码内置，License Guard 同步展示 | 只读 | 不能由客户删除或改成不受控 |
| capability -> entitlement 映射 | VisionFlow 内置默认值，License Guard 保存 App 级策略 | 是 | License Guard 不能授予 license 未包含的 entitlement |
| 拦截体验策略 | License Guard | 是 | 支持 block、hide、readonly、degrade、watermark、warn |
| 套餐/客户/license 差异 | License Guard | 是 | 按默认策略、套餐、客户、license 层级合并 |
| Release 元数据 | CI / `licenseguardctl` 写入 License Guard | 是 | 不应人工逐项填写 hash 和包摘要 |
| 私有化部署覆盖 | 部署配置 | 可选 | 只能收紧或改提示，不能放宽授权 |
| VisionFlow 本地业务 manifest hash | VisionFlow 构建/CI 写入 License Guard Release | 是 | 用于比对受保护 DB 表、assets、workflow 是否匹配官方发布基线 |
| VisionFlow 本地 DB 加密密钥 | VisionFlow 客户端系统安全区 | 否 | License Guard 不接触密钥，避免服务端变成客户本地数据恢复依赖 |

策略合并原则：

```text
VisionFlow 内置安全基线
  ∩ License entitlements
  ∩ License Guard signed policy
  ∩ 私有化收紧策略
  = 最终可执行能力
```

## 2. 增强目标

| 目标 | 判断方式 | 优先级 |
|---|---|---|
| SDK Windows 缓存稳定 | `go test ./...` 在 Windows 通过 | P0 |
| VisionFlow 可本地依赖 SDK | VisionFlow 能用 `replace` 编译接入 | P0 |
| VisionFlow 专用一键试用 | 一条 bootstrap 命令创建 App、Release、License 并输出 VisionFlow 可用配置 | P0 |
| Capability Policy 模型 | 服务端能保存并下发 VisionFlow 能力策略 | P0 |
| 策略安全边界 | 策略不能放宽 license 未包含的 entitlement | P0 |
| 授权诊断支撑 | API 能解释 license、device、release、policy 和最近拒绝原因 | P0 |
| VisionFlow 业务完整性上报 | verify/heartbeat 能记录业务 manifest、DB 定义、assets、workflow hash | P0 |
| Release 自动登记 | 发布后不用人工复制 hash | P1 |
| 接入包生成 | 后台可下载 VisionFlow 接入配置包 | P1 |
| 能力策略可视化 | Admin UI 可配置 capability 拦截方式和提示文案 | P1 |
| 套餐/客户策略 | 不同 plan/customer/license 可覆盖默认策略 | P1 |
| 部署模板 | 服务端部署从文档手工配置收敛为模板 | P1 |
| 生产安全基线 | HTTPS、PostgreSQL、密钥持久化、默认凭据处理 | P1 |
| 防共享和低成本破解 | 设备绑定、短 token、hash 校验、吊销生效 | P1 |
| 高阶完整性/风控 | WinVerifyTrust、调试器/模块/VM 信号 | P3 |

## 3. 实施清单

### P0：VisionFlow 授权产品化入口

- [x] 增加 VisionFlow 一键 bootstrap 命令：

```text
licenseguardctl visionflow bootstrap
```

默认行为：

```text
创建或复用 App: app_visionflow_windows_prod
创建 dev Release: windows / 0.1.0 / dev hash / dev signer
创建测试 License: 至少包含 visionflow.automation
读取 /v1/public-key
输出 VisionFlow 可直接使用的 env 和 license key
```

建议输出：

```text
LICENSE_GUARD_ENDPOINT=http://127.0.0.1:8090/v1
LICENSE_GUARD_APP_ID=app_visionflow_windows_prod
LICENSE_GUARD_PUBLIC_KEY=...
LICENSE_GUARD_APP_VERSION=0.1.0
LICENSE_GUARD_BINARY_HASH=dev-visionflow-main-binary-sha256
LICENSE_GUARD_SIGNER_THUMBPRINT=dev-visionflow-signer-thumbprint
VISIONFLOW_LICENSE_KEY=...
```

已落地：

- `cmd/licenseguardctl visionflow bootstrap`
- 支持创建或复用 `app_visionflow_windows_prod`
- 支持 PATCH 初始 Release，补齐 `main_binary_hash`、`signer_thumbprint`、`package_sha256`、`download_url`
- 支持签发 VisionFlow 开发 license
- 支持读取 `/v1/public-key`
- 支持输出 env 或写入 `-write-env`
- 验证：`go test ./cmd/licenseguardctl`

- [ ] 增加 VisionFlow 默认产品模板。

默认 entitlement：

```text
visionflow.automation
visionflow.batch
visionflow.export
visionflow.plugin
visionflow.update
```

默认 capability policy：

| Capability | Entitlement | 默认模式 | 说明 |
|---|---|---|---|
| `automation.run` | `visionflow.automation` | block | 自动化任务启动 |
| `automation.resume` | `visionflow.automation` | block | 任务恢复 |
| `automation.batch` | `visionflow.batch` | block | 批量任务 |
| `script.execute` | `visionflow.automation` | block | 脚本/动作执行 |
| `export.video` | `visionflow.export` | watermark | 导出能力 |
| `plugin.install` | `visionflow.plugin` | block | 插件安装 |
| `update.skipMandatory` | `visionflow.update` | block | 跳过强制更新 |

- [ ] 增加 Capability Policy 服务端模型和 API。

首期字段：

```text
app_id
capability
required_entitlement
mode
message
limits_json
updated_at
```

安全要求：

- 未知 capability 默认拒绝或标记为需要 VisionFlow 确认。
- `mode=allow` 不能绕过 `required_entitlement`。
- 下发给客户端的 policy 必须有签名或绑定在签名 license 响应中。
- policy 允许降级、隐藏、只读和提示，但不能授予 license 没有的权益。

- [ ] 增加授权诊断支撑 API。

诊断至少能解释：

```text
license 状态
license entitlements
device 状态
release 状态
policy 命中结果
最近一次 verify / heartbeat
最近一次 capability deny 原因
```

- [x] 扩展 VisionFlow integrity report 字段。

License Guard 不读取客户端本地 SQLite，也不直接校验图片文件；它只接收 VisionFlow 上报的摘要并和 Release 基线比对。

建议字段：

```text
business_manifest_sha256
business_manifest_signature_valid
protected_db_schema_hash
protected_db_tables_hash
assets_manifest_sha256
workflow_manifest_sha256
business_integrity_status
business_integrity_errors
```

拒绝规则：

- `business_manifest_signature_valid=false`：拒绝受控能力，记录 high risk。
- Release 要求的 `business_manifest_sha256` 与客户端上报不一致：拒绝受控能力，记录 `business_manifest_mismatch`。
- `business_integrity_status=failed|invalid|tampered`：拒绝受控能力，记录 `business_integrity_failed`。
- `protected_db_tables_hash` 不匹配：Release 增加独立 DB 基线字段后拒绝受控能力，记录 `protected_db_definition_mismatch`。
- `assets_manifest_sha256` 不匹配：Release 增加独立 assets 基线字段后按策略拒绝或降级，记录 `asset_manifest_mismatch`。
- 用户运行数据 hash 不进入拒绝依据，避免把正常配置、记录、evidence 清理误判为破解。

已落地：

- `/v1/activate` 和 `/v1/verify` 可接收并保存上述业务完整性字段。
- `/v1/heartbeat` 支持可选 `integrity` 对象；未传 `integrity` 的旧心跳只更新时间，不触发业务完整性误判。
- PostgreSQL `integrity_reports` 已增加业务 manifest、受保护 DB、assets、workflow 和业务完整性错误字段。
- 当前 P0 先复用 Release 的 `resource_manifest_hash` 作为 `business_manifest_sha256` 发布基线，避免一次性扩大 Release schema。
- 当前已强判 `business_manifest_signature_valid=false`、`business_manifest_mismatch`、`business_integrity_status=failed|invalid|tampered`。
- 验证：`go test ./internal/licensecore`。

客户端本地 SQLite 加密边界：

- SQLCipher 密钥由 VisionFlow 在本机生成并保存到 Windows DPAPI 或 Credential Manager。
- License Guard 不保存 SQLCipher 密钥、不参与 DB 解密、不提供本地 DB 恢复。
- License Guard 只接收加密 DB 打开后的完整性摘要，例如 protected table hash 和 business manifest hash。
- DB 加密失败、密钥丢失、密钥不可读属于 VisionFlow 本地诊断/恢复问题，不应被 License Guard 误判为 license 有效。

### P0：VisionFlow 接入前置

- [x] 修复 Windows DPAPI 缓存 bug。

当前风险：`sdk/go/licenseguard/cache_windows.go` 中 `dpapiProtect` / `dpapiUnprotect` 返回 `unsafe.Slice(out.pbData, out.cbData)` 后再 `LocalFree`，调用方可能拿到已释放内存。

修复方式：

```go
outBytes := append([]byte(nil), unsafe.Slice(out.pbData, out.cbData)...)
return outBytes, nil
```

- [x] 跑通 License Guard 全量测试：

```text
go test ./...
```

- [x] 保持短期 module 兼容。

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
- [x] 确认 `/v1/public-key` 返回值可用于客户端本地验签。

### P1：能力策略可视化

- [ ] Admin UI 增加 Capability Policy 页面。

页面能力：

```text
查看 VisionFlow capability 列表
查看 required entitlement
选择拦截模式 block / hide / readonly / degrade / watermark / warn
编辑用户提示文案
编辑 limits_json，如 maxConcurrent、maxExports、watermarkText
查看策略来源：默认 / 套餐 / 客户 / license / 部署收紧
```

- [ ] Admin UI 增加 License 签发向导。

向导能力：

```text
选择 VisionFlow App
选择套餐或 entitlement 集合
设置过期时间和设备数
预览该 license 在 VisionFlow 中可用/不可用能力
生成 license key
```

- [ ] Admin UI 增加策略预览。

输入：

```text
license
device_id
app_version
capability
```

输出：

```text
allowed / denied / degraded
deny reason
命中的 entitlement
命中的 policy 层级
用户可见文案
```

### P1：部署与发布自动化

已完成的本地验证：

- `go test ./...`
- `docker-compose --env-file deploy/.env.example -f deploy/docker-compose.yml config`
- `go run ./cmd/licenseguardctl release publish -dry-run ...`
- `bash scripts/smoke.sh`（通过 Git Bash）
- `bash scripts/production-check.sh`（通过 Git Bash）

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
business_manifest_sha256
protected_db_schema_hash
protected_db_tables_hash
assets_manifest_sha256
workflow_manifest_sha256
download_url
```

- [ ] Admin UI 支持强制更新、最低支持版本、灰度比例的操作确认。
- [ ] 增加 update 行为 smoke：普通更新、强制更新、版本封禁、最低版本。
- [ ] 提供接入包导入说明，面向 VisionFlow 客户部署。

### P2：Release 与 CI 自动化补强

- [ ] 扩展 `licenseguardctl release publish --from-artifact`。

自动生成或读取：

```text
version
build_number
main_binary_hash
signer_thumbprint
package_sha256
business_manifest_sha256
protected_db_schema_hash
protected_db_tables_hash
assets_manifest_sha256
workflow_manifest_sha256
download_url
release_notes
mandatory
min_supported_version
rollout_percent
```

- [ ] 提供 VisionFlow CI 示例。

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

- [ ] Admin UI 对 Release 风险字段加确认。

需要确认：

```text
mandatory=true
min_supported_version 提高
rollout_percent 降低
blocked release
download_url 为空
hash 字段缺失
```

### P3：防破解与风控增强

- [ ] SDK 固定 public key 策略文档化：生产客户端不应每次启动动态信任 `/v1/public-key`。
- [ ] Windows SDK 增加 Authenticode / WinVerifyTrust 校验。
- [ ] 自动采集 signer thumbprint。
- [ ] 增加 debugger 基础检测。
- [ ] 增加可疑模块和 VM 指标采集。
- [ ] 增加 VisionFlow 业务定义完整性风险事件。
- [ ] 风险信号只参与评分，不单点永久封禁。
- [ ] 高价值功能可缩短 token TTL。
- [ ] 增加异常系统时间风险事件。
- [ ] 将 SDK 拆成稳定版本或子模块，发布 tag，避免客户端长期依赖服务端仓库主分支。

## 4. 防破解能力边界

### 当前方案能有效防

- 普通用户共享 license。
- 复制 token 到其他设备。
- 修改本地授权缓存。
- 被吊销后长期继续使用。
- 超设备数激活。
- 使用被封禁设备。
- 使用被停用旧版本。
- 使用 hash 不匹配的篡改包。
- 使用业务定义 manifest 不匹配的 VisionFlow 本地包。
- 使用受保护 DB 定义、图片资源或 workflow 被篡改的本地环境。
- 长期完全离线绕过授权。

### 当前方案不能绝对防

- 专业逆向 patch 掉客户端授权检查。
- Hook 本地验签结果。
- 修改二进制后绕过客户端逻辑。
- 模拟服务端响应，尤其是客户端未固定 public key 或 HTTPS 校验不严格时。
- 用户读取或复制本地 SQLite、图片资源、workflow 文件。
- 用户修改运行记录、evidence、用户配置等非受保护数据。

定位：适合商业授权、防共享、防低成本破解、防内部滥用；对专业逆向是提高成本，不是绝对防护。

## 5. 验收清单

### P0 验收

- [ ] `go test ./...` 通过。
- [ ] Windows SDK `TestCachedAuthorizationAllowsSignedOfflineGrace` 通过。
- [ ] `Activate` 成功后 token 可保存并重新读取。
- [ ] 本地 token 被篡改后验签失败。
- [ ] VisionFlow 能通过本地 `replace` import SDK 并编译。
- [ ] License Guard 后台存在 VisionFlow App、Release、License。
- [ ] VisionFlow 使用有效 license 激活后，后台出现 Device 和 Activation。
- [x] `licenseguardctl visionflow bootstrap` 一条命令能生成 VisionFlow 可用本地试用配置。
- [ ] 默认 VisionFlow capability policy 存在，且未知 capability 不会被默认放行。
- [ ] license 缺少 entitlement 时，即使 policy 配置为宽松模式也不能放行。
- [ ] 诊断 API 能解释一次 capability deny 的具体原因。
- [x] verify/heartbeat 能接收并保存 VisionFlow 业务完整性字段。
- [x] 业务 manifest 签名无效或 hash 不匹配时返回拒绝或风险事件。

### P1 验收

- [ ] 使用部署模板可启动 PostgreSQL、迁移和 License Guard API。
- [ ] `-key-dir` 持久化，重启服务后 public key 不变化。
- [ ] Admin UI 可下载 VisionFlow 接入包。
- [ ] 接入包不包含 SDK secret、私钥、admin token、生产 license key。
- [ ] Admin UI 可查看和编辑 VisionFlow capability policy。
- [ ] Admin UI 可预览某个 license 对某个 capability 的最终结果。
- [ ] Release 发布脚本能登记签名后 EXE hash 和安装包 hash。
- [ ] Release 能登记 VisionFlow `business_manifest_sha256`、受保护 DB hash、assets hash、workflow hash。
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
- [ ] VisionFlow `business_manifest_mismatch`、`protected_db_definition_mismatch`、`asset_manifest_mismatch` 能形成风险事件。
- [ ] VisionFlow 上报 DB 加密或密钥读取失败时能形成独立诊断事件，不和 license 过期、吊销混淆。
- [ ] 高风险设备可触发短 token TTL 或 deny。
- [ ] SDK 有明确版本 tag 或子模块发布方案。

## 6. 非目标

- 不提供破解不可行的承诺。
- 不把服务端私钥或 SDK secret 下发到客户端。
- 不默认把生产 license key 打进公共安装包。
- 不把 JSON store 作为生产推荐部署。
- 不在本阶段实现 Redis、对象存储或复杂多租户计费。
- 不允许通过前端配置、部署配置或策略覆盖放宽 license entitlement。
- 不把 VisionFlow 的安全基线交给客户可编辑配置维护。
- 不直接读取或修复 VisionFlow 客户端本地 SQLite、图片资源和 workflow 文件；License Guard 只保存发布基线、接收完整性摘要、给出授权/风险判定。
- 不保存 VisionFlow SQLCipher 密钥，不承担客户本地 DB 数据恢复职责。
- 不把用户运行数据、evidence、普通用户配置的 hash mismatch 作为默认拒绝依据。

## 7. 待确认问题

- License Guard 正式部署是单机、Docker Compose、还是云平台托管。
- VisionFlow 安装包下载地址由谁维护。
- 是否已有代码签名证书。
- 是否需要给不同客户生成私有接入包。
- 是否需要多环境：dev、staging、production。
- 套餐/客户模型首期是否只做 VisionFlow 单 App，还是直接抽象为通用 License Guard 能力。
- Capability policy 签名是否复用 license token Ed25519 key，还是独立 policy signing key。
- VisionFlow 业务 manifest hash 是否作为 Release 必填字段，还是首期作为可选完整性增强字段。
- `assets_manifest_sha256` 不匹配时首期是直接拒绝，还是按 capability 策略只拒绝依赖该资源的任务。
- VisionFlow DB 加密失败是否需要 License Guard risk event，还是仅在 VisionFlow 本地诊断页展示。
