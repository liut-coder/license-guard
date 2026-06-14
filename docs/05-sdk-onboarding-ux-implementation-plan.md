# SDK 接入工作台落地实施文档

更新时间：2026-06-10

## 1. 背景与目标

当前 Admin UI 的 SDK 接入页已经能展示 SDK Key、Public Key、运行参数和 demo 命令，但交互形态仍偏“文档复制”。接入方需要自己判断 App 端要改哪些模块、先做什么、成功结果是什么、失败后如何定位。

目标是把 SDK 页升级为“接入工作台”：

- App 端开发者能一眼看到自己要改哪些代码层。
- 每一步都有可视化状态、输入项、自动生成配置、命令、代码片段和成功标准。
- 能从服务端数据自动判断的状态自动判断，不能自动判断的事项允许开发者手动标记。
- 管理员能看到某个 App 的接入进度和最近验证证据。

## 2. 目标用户与场景

用户：

- App 开发者：负责把现有 Windows Go App 接入 License Guard。
- License Guard 管理员：负责创建 App、签发 License、轮换 SDK Key、查看设备和风险。
- 测试人员：负责验证激活、离线、本地验签、心跳、封禁、篡改等场景。

核心场景：

- 第一次接入：从 0 到跑通 activate、local verify、online verify、heartbeat。
- 改造现有 App：知道要新增哪些模块、改启动流程哪里、功能开关如何落地。
- 联调验收：跑完命令或 App 后，后台能显示是否收到激活、心跳、完整性上报和风险事件。
- 故障定位：看到错误码后能知道 App 端应该提示什么、用户能做什么、管理员能处理什么。

## 3. 最终体验设计

### 3.1 页面结构

把现有 `SDK 接入` 页面改成 4 个 Tab：

```text
SDK 接入
├─ 接入总览
├─ App 改造指南
├─ 自动生成
└─ 联调验证
```

建议默认打开“接入总览”。

### 3.2 接入总览

可视化展示当前 App 的接入状态：

```text
┌────────────────────────────────────────────────────────────┐
│ Nax Desktop / app_nax_desktop_prod                         │
│ Endpoint: http://31.57.218.242:8090/v1                     │
│ SDK Key: active / lgsk_xxxx       Public Key: 已加载        │
├────────────────────────────────────────────────────────────┤
│ 接入进度                                                   │
│ [✓] 创建 App        [✓] 发布版本        [✓] 签发 License    │
│ [✓] SDK Key active  [●] 首次激活        [ ] 心跳在线        │
│ [ ] 完整性上报      [ ] 离线验签        [ ] 风险演练        │
├────────────────────────────────────────────────────────────┤
│ 下一步建议：运行“首次激活”命令，或在 App 中接入 Activate。  │
└────────────────────────────────────────────────────────────┘
```

状态来源：

- App 创建：`GET /admin/apps/:id`
- 发布版本：`releases.length > 0`
- License：`licenses.length > 0`
- SDK Key：`sdk_keys` 中存在 active key
- 首次激活：最近 devices / activations 中存在当前 App 记录
- 心跳在线：设备 `last_seen_at` 在近 N 分钟内
- 完整性上报：最近 integrity report 存在
- 风险演练：最近 risk event 存在

首期如果后端缺少聚合字段，可先用现有 `devices`、`risk-events`、`app detail` 推导，后续补只读聚合接口。

### 3.3 App 改造指南

用“应用架构地图”告诉开发者要改哪里：

```text
┌──────────────── App 启动流程 ────────────────┐
│ main.go                                      │
│  ├─ 初始化配置           读取 endpoint/public key/app id │
│  ├─ 本地 token 验签      允许基础功能先启动              │
│  ├─ 后台 verify          刷新授权和风险状态              │
│  └─ heartbeat 定时器     上报在线和设备状态              │
├──────────────── 授权模块 ───────────────────┤
│ internal/licenseguard/                       │
│  ├─ client.go            调 API                         │
│  ├─ device.go            生成 install_id/device id       │
│  ├─ integrity.go         采集版本/hash/签名              │
│  ├─ cache_windows.go     DPAPI 或本地安全缓存            │
│  └─ token.go             Ed25519 验签和 entitlements     │
├──────────────── 业务功能层 ─────────────────┤
│ export/batch/pro features                    │
│  └─ 调 entitlement checker 决定功能是否可用  │
└──────────────── 用户提示层 ─────────────────┘
   错误码 -> 可理解的提示 -> 重试/联系管理员/退出
```

每一项使用相同卡片结构：

```text
步骤 4：启动时本地验签
App 端要改什么：启动入口调用 licenseguard.LoadCachedToken() 和 VerifyLocal()
要保存什么：token cache、install_id
自动生成：Go 代码片段、配置结构体、测试命令
成功标准：断网启动时可进入基础功能，token 过期后提示联网刷新
```

## 4. App 端改造清单

### 4.1 准备配置

App 端要做：

- 增加 License Guard 配置读取。
- 区分 dev/staging/production endpoint。
- 把 `PUBLIC_KEY` 随应用发布，不从不可信位置动态覆盖。

配置项：

```text
LICENSE_GUARD_ENDPOINT
LICENSE_GUARD_APP_ID
LICENSE_GUARD_APP_VERSION
LICENSE_GUARD_PUBLIC_KEY
LICENSE_GUARD_BINARY_HASH
LICENSE_GUARD_SIGNER_THUMBPRINT
```

自动化：

- 后台根据当前 App、最新 Release、Public Key 自动生成 `.env`。
- 自动生成 Go `Config` 结构体初始化代码。
- 一键复制当前环境完整配置。

成功标准：

- App 启动日志能打印脱敏后的 endpoint、app_id、version。
- App 端不包含 SDK Secret、服务端私钥、管理员 token、数据库凭据。

### 4.2 新增授权模块

App 端要做：

- 新增 `internal/licenseguard/` 包。
- 把 API 调用、设备指纹、完整性采集、token cache、token 验签与业务代码隔离。

推荐目录：

```text
internal/licenseguard/
  client.go
  config.go
  device.go
  integrity.go
  cache_windows.go
  token.go
  entitlement.go
```

自动化：

- 后台生成“最小接入文件清单”。
- 复制 Go skeleton，开发者可直接放进 App。
- 后续可提供 `integration-bundle.zip`，包含模板代码和 README。

成功标准：

- 业务层只依赖 `licenseguard.Service` 或等价接口，不直接散落 HTTP 请求。

### 4.3 首次激活

App 端要做：

- 用户输入 license key。
- 调用 `/v1/challenge` 获取 nonce。
- 采集 device info 和 integrity report。
- 调用 `/v1/activate`。
- 缓存服务端返回的短期 token。

自动化：

- 根据当前 App 自动生成 activate demo 命令。
- 自动生成嵌入式 Go 示例。
- 后台展示最近一次 activation/device 证据。

成功标准：

- 成功返回 `allowed=true`。
- 后台设备列表出现新设备。
- 本地 token cache 文件存在且可验签。

### 4.4 启动时本地验签

App 端要做：

- 每次启动先读取本地 token。
- 用 Ed25519 public key 验签。
- 检查 `app_id`、`device_id`、`expires_at`、`entitlements`。
- 本地通过后允许进入基础功能，并在后台异步 verify。

自动化：

- 自动生成 `VerifyLocalOnStartup()` 示例代码。
- 自动生成断网验证命令。
- UI 展示“本地验签通过/未验证”的手动验收开关。

成功标准：

- 网络不可用但 token 未过期时，App 可进入基础功能。
- token 过期或验签失败时，App 进入受限模式。

### 4.5 在线 verify 与 heartbeat

App 端要做：

- 启动后异步调用 `/v1/verify`。
- 定时调用 `/v1/heartbeat`。
- 服务端拒绝时更新本地授权状态。

自动化：

- 自动生成 verify/heartbeat 命令。
- 后台展示最近 `last_seen_at` 和验证建议。
- 后续新增接入状态接口后，自动判断“心跳在线”。

成功标准：

- 后台设备 `last_seen_at` 持续更新。
- 服务端返回 revoke/suspend/block 时，App 能及时限制功能。

### 4.6 Entitlements 功能开关

App 端要做：

- 不能只判断授权是否有效。
- 高价值功能必须检查 entitlement。
- 功能层统一调用 `HasEntitlement("export.enabled")`。

自动化：

- 后台根据 License entitlements 自动生成 Go 常量。
- 生成业务调用示例。

成功标准：

- 移除某个 entitlement 后，对应功能不可用。
- UI 能提示“当前授权不包含该功能”。

### 4.7 完整性上报

App 端要做：

- 上报 `app_version`、`main_binary_hash`、`signer_thumbprint`。
- 后续补充 debugger、suspicious modules、VM indicators。
- 发布新版本时，后台 Release 必须登记 hash 和 signer。

自动化：

- 后台从最新 Release 自动填充 hash/signer。
- 提供“篡改 hash 演练”命令。
- 后台展示最近 risk event。

成功标准：

- 正确 hash 验证通过。
- 错误 hash 返回 `INTEGRITY_FAILED` 并生成风险事件。

### 4.8 离线宽限

App 端要做：

- 区分 token 有效、token 过期但在 offline grace、超过 offline grace。
- 超过宽限期时进入受限模式或要求联网刷新。

自动化：

- 后台展示当前 `offline_grace_days`。
- 自动生成本地判断伪代码。

成功标准：

- 离线体验可控，不会因为短暂断网直接阻断所有功能。
- 超过宽限期后不会继续开放高价值功能。

### 4.9 Deactivate / 换机

App 端要做：

- 用户退出授权、换机、卸载前调用 `/v1/deactivate`。
- 删除本地 token cache。
- 保留 install_id 的策略由产品决定；一般退出授权后可以保留，彻底卸载时删除。

自动化：

- 自动生成 deactivate 命令和 Go 示例。
- 后台展示设备解绑/禁用状态。

成功标准：

- deactivate 后旧 token 不再可用。
- 管理台设备解绑后，客户端下一次 verify 被拒绝或要求重新激活。

### 4.10 错误码与用户提示

App 端要做：

- 统一错误码映射，不把服务端原始错误直接丢给用户。
- 给出可执行动作：重试、联网、联系管理员、换授权、退出。

建议映射：

```text
LICENSE_REVOKED        授权已吊销，请联系管理员。
LICENSE_SUSPENDED      授权已暂停，请联系管理员恢复。
DEVICE_BLOCKED         当前设备已被封禁。
DEVICE_LIMIT_EXCEEDED  授权设备数已达上限，请解绑旧设备。
INTEGRITY_FAILED       应用完整性校验失败，请重新安装官方版本。
TOKEN_EXPIRED          授权状态需要联网刷新。
APP_VERSION_BLOCKED    当前版本已停用，请升级。
```

自动化：

- 后台生成错误码表和 Go map。
- 联调验证 Tab 提供每个错误场景的演练入口。

成功标准：

- 用户能理解问题。
- 测试人员能通过错误码判断是授权、设备、版本还是完整性问题。

## 5. 自动化能力设计

### 5.1 前端可先实现的自动化

不改后端即可落地：

- 自动生成 `.env`。
- 自动生成 Go `Config`。
- 自动生成 CLI demo 命令。
- 自动生成最小集成代码片段。
- 根据现有 app detail、licenses、devices、risk events 推导部分接入进度。
- 用 `localStorage` 保存“App 端已完成”手动勾选状态。
- 一键复制命令、配置、代码片段。

### 5.2 后端只读聚合接口

新增：

```text
GET /admin/apps/:id/onboarding
```

返回：

```json
{
  "app_id": "app_nax_desktop_prod",
  "has_active_sdk_key": true,
  "has_release": true,
  "has_license": true,
  "latest_release": {
    "version": "1.4.2",
    "main_binary_hash": "demo-main-binary-sha256",
    "signer_thumbprint": "demo-signer-thumbprint"
  },
  "latest_device": {
    "id": "dev_xxx",
    "status": "active",
    "last_seen_at": "2026-06-10T08:17:19Z"
  },
  "latest_risk_event": {
    "event_type": "binary_hash_mismatch",
    "severity": "high",
    "resolved_at": null
  },
  "steps": [
    {"id": "app_created", "status": "passed", "source": "server"},
    {"id": "local_verify", "status": "manual", "source": "client"}
  ]
}
```

用途：

- 前端不用到处拼状态。
- 管理员可以直接看接入进度。
- 后续可以扩展为接入验收报告。

### 5.3 集成包生成

第二阶段后新增：

```text
POST /admin/apps/:id/integration-bundle
```

产物：

```text
licenseguard-integration-app_nax_desktop_prod.zip
├─ README.md
├─ .env.example
├─ internal/licenseguard/*.go
└─ integration-checklist.md
```

注意：

- 包内不得包含 SDK Secret。
- Public Key、App ID、Endpoint、Release 信息可以包含。
- License key 默认不打包，除非用户明确选择 demo license。

## 6. 前端交互细节

### 6.1 Tab 与步骤状态

状态样式：

```text
passed   绿色勾
current  蓝色圆点
warning  黄色提示
blocked  红色阻断
manual   灰色待手动确认
```

步骤顺序：

```text
1. 创建 App
2. 发布版本
3. 签发 License
4. 配置 SDK Key
5. 改造 App 配置
6. 接入首次激活
7. 接入本地验签
8. 接入在线 verify
9. 接入 heartbeat
10. 接入 entitlements
11. 接入完整性上报
12. 演练错误场景
```

每个步骤有三个操作：

- `复制代码`
- `复制命令`
- `标记为已接入`

能由服务端判断的步骤不显示手动标记，避免人为误判。

### 6.2 参数面板

字段：

```text
Endpoint
App ID
License Key
App Version
Binary Hash
Signer Thumbprint
Install ID Path
Token Cache Path
```

默认值从当前 App 和最新 Release 自动填充。用户修改后所有命令和代码片段实时更新。

### 6.3 代码片段类型

提供 segmented control：

```text
.env | Go Config | 启动流程 | Activate | Local Verify | Verify + Heartbeat | Entitlements | Errors
```

每个片段：

- 有复制按钮。
- 有“这个片段应该放到哪里”的路径提示。
- 有成功标准。
- 有常见错误。

## 7. 文件级实施计划

### 阶段一：纯前端升级

目标：不改 API，先把 SDK 页变成可视化接入工作台。

改动文件：

```text
web/admin/index.html
README.md
docs/03-windows-go-integration-guide.md
```

实现：

- SDK section 改为 4 个 Tab。
- 增加接入进度 stepper。
- 增加参数面板。
- 增加 App 改造指南卡片。
- 增加自动生成代码片段。
- 增加 copy feedback。
- 用现有 `loadAll()` 数据推导基础状态。

验证：

```bash
node - <<'NODE'
const fs = require('fs');
const html = fs.readFileSync('web/admin/index.html', 'utf8');
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)];
if (scripts.length !== 1) throw new Error('expected one inline script');
new Function(scripts[0][1]);
NODE

bash scripts/smoke.sh
```

### 阶段二：后端接入状态接口

目标：把接入状态聚合从前端推导移到后端，便于验收。

改动文件：

```text
internal/licensecore/server.go
internal/licensecore/server_test.go
web/admin/index.html
scripts/smoke.sh
README.md
```

实现：

- `GET /admin/apps/:id/onboarding`
- 聚合 App、release、license、sdk key、device、risk event。
- 前端总览优先使用该接口。
- 单测覆盖状态判断。
- smoke 覆盖接口返回。

验证：

```bash
go test ./...
bash scripts/smoke.sh
bash scripts/production-check.sh
```

### 阶段三：集成包生成

目标：能下载或复制完整集成包，进一步降低 App 端接入成本。

改动文件：

```text
internal/licensecore/server.go
internal/licensecore/server_test.go
web/admin/index.html
sdk/go/licenseguard
examples/windows-go-demo
```

实现：

- 复用 `sdk/go/licenseguard` 生成模板。
- 后台生成 zip 或 tar。
- 包内包含 `.env.example`、Go skeleton、接入 README、验收 checklist。
- 禁止包含 SDK Secret。

验证：

```bash
go test ./...
bash scripts/smoke.sh
```

## 8. 验收标准

第一阶段完成后：

- SDK 页不再只有大段命令。
- 用户能看到 App 改造地图。
- 用户能修改参数并实时生成命令/代码。
- 每个步骤都有“App 要改什么、放在哪里、成功标准”。
- Admin UI JS 解析通过，smoke 通过。

第二阶段完成后：

- 后台能自动判断接入状态。
- 总览页能展示最近设备、心跳、风险事件。
- 接入验收不依赖用户口头反馈。

第三阶段完成后：

- App 开发者可以下载集成包或复制完整 skeleton。
- 从创建 App 到跑通 demo 的手工拼接步骤明显减少。

## 9. 不做事项

- 不把 SDK Secret 写入客户端代码。
- 不把生产 License Key 默认打进集成包。
- 不在首期实现所有平台 SDK，先聚焦 Windows Go。
- 不把 Redis/Object Storage 等后续生产化增强混入本次 SDK 页改造。

## 10. 推荐优先级

建议先做阶段一，因为它风险最低、立刻改善体验。阶段二随后补齐自动验收能力。阶段三适合在 App 端接入流程稳定后再做，避免过早固化模板。

## 11. 落地闭环记录

更新时间：2026-06-10

本轮已完成阶段一、阶段二和阶段三的首版闭环：

- `web/admin/index.html`：SDK 页已升级为 `接入总览`、`App 改造指南`、`自动生成`、`联调验证` 四个 Tab 的接入工作台。
- `web/admin/index.html`：接入总览优先读取 `GET /admin/apps/:id/onboarding`，展示 App、Release、License、SDK Key、设备、完整性上报、风险事件和离线宽限证据。
- `web/admin/index.html`：参数面板支持实时生成 `.env`、Go Config、启动流程、Activate、Local Verify、Verify + Heartbeat、Entitlements、Errors 片段。
- `web/admin/index.html`：客户端侧事项用 `localStorage` 保存手动验收状态，服务端可判断的步骤不依赖手动勾选。
- `internal/licensecore/server.go` / `types.go`：新增 `GET /admin/apps/:id/onboarding` 聚合接口。
- `internal/licensecore/server.go`：新增 `POST /admin/apps/:id/integration-bundle`，返回不含 SDK Secret 的 zip 集成包。
- `internal/licensecore/server_test.go`：覆盖 onboarding 状态聚合、最近设备/完整性/风险证据、集成包内容和 secret 泄露保护。
- `scripts/smoke.sh`：覆盖 onboarding 基础状态、客户端激活/verify/heartbeat 后状态，以及 integration bundle zip 响应。
- `README.md` 和 `docs/03-windows-go-integration-guide.md`：同步 Admin UI 工作台、新接口和集成包能力。

已执行验证：

```bash
node - <<'NODE'
const fs = require('fs');
const html = fs.readFileSync('web/admin/index.html', 'utf8');
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)];
if (scripts.length !== 1) throw new Error('expected one inline script');
new Function(scripts[0][1]);
NODE

go test ./...
bash scripts/smoke.sh
bash scripts/production-check.sh
```

验证结果：

- Admin UI inline script 解析通过。
- `go test ./...` 通过。
- `bash scripts/smoke.sh` 通过。
- `bash scripts/production-check.sh` 通过，包含 Go 测试、二进制构建、Admin UI JS 解析、SDK key `secret_hash` 暴露保护和端到端 smoke。

仍按“不做事项”约束：

- 集成包默认不包含 SDK Secret。
- 集成包默认不包含生产 License Key。
- 本次仍聚焦 Windows Go，不扩展其他平台 SDK。
- 未混入 Redis/Object Storage 等生产化增强。
