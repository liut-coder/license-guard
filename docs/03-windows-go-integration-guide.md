# License Guard 外部接入指南：Windows Go App

## 1. 适用范围

本文档用于指导 Windows Go 客户端应用接入 License Guard。首期目标是完成授权激活、设备绑定、短期 token、完整性上报和心跳验证。

适用客户端：

- Windows 桌面应用
- Go 开发
- 可访问 HTTPS API
- 支持本地文件或系统安全存储

不适用：

- 完全离线且长期不联网的软件
- 无法更新客户端代码的软件
- 要求只靠本地注册码永久验证的软件

## 2. 接入前准备

在 License Guard 后台创建应用后，开发者会获得：

```text
APP_ID
API_ENDPOINT
PUBLIC_KEY
SDK_VERSION
ENVIRONMENT
```

示例：

```text
APP_ID=app_nax_desktop_prod
API_ENDPOINT=https://api.licenseguard.example/v1
PUBLIC_KEY=lgpk_live_b71c...49ad
ENVIRONMENT=production
```

客户端不得内置：

```text
服务端私钥
SDK Secret
数据库凭据
管理员 token
万能 license key
```

后台 `SDK 接入` 页现在是接入工作台，包含 `接入总览`、`App 改造指南`、`自动生成`、`联调验证` 四个 Tab。开发者可以在工作台中查看服务端自动判断的接入进度、复制 `.env`/Go 片段/demo 命令、下载不含 SDK Secret 的集成包，并手动标记只能由客户端验证的事项。

管理员也可以直接调用只读聚合接口查看某个 App 的接入证据：

```http
GET /admin/apps/:id/onboarding
```

集成包接口：

```http
POST /admin/apps/:id/integration-bundle
```

包内包含 `.env.example`、`internal/licenseguard/` skeleton、README 和验收清单。默认不会包含 SDK Secret、服务端私钥、管理员 token、数据库凭据或生产 License Key。

## 3. 推荐接入方式

首期可以先不做完整 SDK 包，直接按 HTTP 协议接入。后续再把这些逻辑封装成 Go SDK。

推荐目录：

```text
your-app/
  internal/
    licenseguard/
      client.go
      device.go
      integrity.go
      cache_windows.go
      token.go
```

职责：

- `client.go`：API 请求。
- `device.go`：install_id、device_fingerprint。
- `integrity.go`：版本、hash、签名、调试器信号。
- `cache_windows.go`：DPAPI 加密缓存。
- `token.go`：token 解析和权限判断。

## 4. 客户端启动流程

```text
App 启动
  |
  v
读取本地缓存 token
  |
  +-- token 未过期 -> 允许进入基础功能，并异步 verify
  |
  +-- token 不存在/已过期 -> 显示授权页或限制高级功能
  |
  v
请求 /challenge
  |
  v
采集 device_info + integrity_report
  |
  v
请求 /verify 或 /activate
  |
  v
服务端返回 allowed / denied / risk
  |
  v
缓存短期 token
  |
  v
按 entitlements 控制功能
```

## 5. API 协议

所有请求使用 HTTPS，Content-Type 为 `application/json`。

建议请求头：

```text
Content-Type: application/json
X-LG-App-Id: app_nax_desktop_prod
X-LG-SDK-Version: go-windows-0.1.0
X-LG-Request-Id: uuid
```

### 5.1 获取 Challenge

上线前客户端需要内置或配置服务端 Ed25519 公钥。Demo 环境可通过接口获取：

请求：

```http
GET /v1/public-key
```

响应：

```json
{
  "alg": "EdDSA",
  "key_type": "Ed25519",
  "public_key": "base64-ed25519-public-key"
}
```

生产建议：

- 公钥随应用配置或安装包发布。
- 客户端只保存公钥，绝不保存服务端私钥。
- 本地缓存 token 必须用公钥验签后再信任 `entitlements`。

请求：

```http
POST /v1/challenge
```

请求体：

```json
{
  "app_id": "app_nax_desktop_prod",
  "platform": "windows",
  "install_id": "c9fd4f3b-3bb6-4ad8-a8db-c6cb2a5f18ef",
  "app_version": "1.4.2"
}
```

响应：

```json
{
  "challenge_id": "chg_01HV9J8W1N8N2",
  "nonce": "base64url-random-nonce",
  "expires_at": "2026-06-07T22:10:00Z",
  "server_time": "2026-06-07T22:05:00Z"
}
```

客户端要求：

- `nonce` 只能使用一次。
- challenge 过期后必须重新请求。
- 不要把旧 nonce 复用到新请求。

### 5.2 首次激活

请求：

```http
POST /v1/activate
```

请求体：

```json
{
  "app_id": "app_nax_desktop_prod",
  "platform": "windows",
  "license_key": "LG-92B8-44KD-XXXX",
  "challenge_id": "chg_01HV9J8W1N8N2",
  "nonce": "base64url-random-nonce",
  "device": {
    "install_id": "c9fd4f3b-3bb6-4ad8-a8db-c6cb2a5f18ef",
    "fingerprint": "sha256-device-fingerprint",
    "os": "windows",
    "os_version": "Windows 11 23H2",
    "machine_name_hash": "sha256-machine-name"
  },
  "integrity": {
    "app_version": "1.4.2",
    "main_binary_hash": "sha256-exe-hash",
    "signer_thumbprint": "cert-thumbprint",
    "debugger_detected": false,
    "suspicious_modules": [],
    "vm_indicators": []
  }
}
```

响应：

```json
{
  "allowed": true,
  "license_token": "eyJhbGciOiJFZERTQSJ9...",
  "expires_at": "2026-06-08T10:05:00Z",
  "offline_grace_until": "2026-06-14T10:05:00Z",
  "entitlements": ["feature.pro", "export.enabled"],
  "device_status": "active",
  "risk": {
    "level": "low",
    "score": 12,
    "actions": []
  },
  "update": {
    "available": true,
    "required": true,
    "latest_version": "1.5.0",
    "download_url": "https://download.example.com/nax-desktop/1.5.0/setup.exe",
    "package_sha256": "demo-package-v150-sha256",
    "release_notes": "Mandatory update package."
  }
}
```

拒绝响应：

```json
{
  "allowed": false,
  "code": "DEVICE_LIMIT_EXCEEDED",
  "message": "授权绑定设备数已达到上限",
  "risk": {
    "level": "medium",
    "score": 58,
    "actions": ["review"]
  }
}
```

### 5.3 常规验证

请求：

```http
POST /v1/verify
```

请求体与 `/activate` 类似，但可以不传 `license_key`，改传本地 token：

```json
{
  "app_id": "app_nax_desktop_prod",
  "platform": "windows",
  "license_token": "eyJhbGciOiJFZERTQSJ9...",
  "challenge_id": "chg_01HV9J8W1N8N2",
  "nonce": "base64url-random-nonce",
  "device": {
    "install_id": "c9fd4f3b-3bb6-4ad8-a8db-c6cb2a5f18ef",
    "fingerprint": "sha256-device-fingerprint",
    "os": "windows",
    "os_version": "Windows 11 23H2",
    "machine_name_hash": "sha256-machine-name"
  },
  "integrity": {
    "app_version": "1.4.2",
    "main_binary_hash": "sha256-exe-hash",
    "signer_thumbprint": "cert-thumbprint",
    "debugger_detected": false,
    "suspicious_modules": [],
    "vm_indicators": []
  }
}
```

响应与 `/activate` 一致。

### 5.3.1 版本更新处理

客户端在 `/activate` 和 `/verify` 成功响应中读取 `update` 字段：

```text
update 不存在             当前版本无需提示更新
update.available=true     有新版本
update.required=true      强制更新，旧版本应阻断高价值功能或进入更新流程
update.required=false     推荐更新，允许继续使用但展示升级入口
```

后台版本页登记每个 release 的下载地址、安装包 SHA256、发布说明、强制更新开关、灰度比例和最低支持版本。服务端规则：

- 最新 `active` release 的 build number 最大者作为候选更新版本。
- `mandatory=true` 时，命中客户端必须更新。
- 客户端当前版本低于 `min_supported_version` 时，即使灰度比例为 0 也必须更新。
- 非强制更新按设备 ID 做稳定灰度，同一设备在同一 release 下结果保持一致。
- 客户端下载安装包后应校验 `package_sha256`，通过后再启动安装流程。

### 5.4 心跳

请求：

```http
POST /v1/heartbeat
```

请求体：

```json
{
  "app_id": "app_nax_desktop_prod",
  "license_token": "eyJhbGciOiJFZERTQSJ9...",
  "install_id": "c9fd4f3b-3bb6-4ad8-a8db-c6cb2a5f18ef",
  "app_version": "1.4.2",
  "runtime": {
    "started_at": "2026-06-07T22:00:00Z",
    "uptime_seconds": 900
  }
}
```

建议频率：

- 普通软件：15-30 分钟一次。
- 高价值功能使用中：5-10 分钟一次。
- 离线时不要阻塞主流程，记录下次联网补报。

### 5.5 停用当前设备授权

用户退出授权或换设备前，客户端应调用：

```http
POST /v1/deactivate
```

请求体：

```json
{
  "app_id": "app_nax_desktop_prod",
  "license_token": "eyJhbGciOiJFZERTQSJ9...",
  "install_id": "c9fd4f3b-3bb6-4ad8-a8db-c6cb2a5f18ef"
}
```

响应：

```json
{
  "ok": true,
  "deactivated": true,
  "server_time": "2026-06-08T01:00:00Z"
}
```

客户端要求：

- 成功后删除本地 token 缓存。
- 旧 token 再次 verify 会返回 `TOKEN_DEACTIVATED`。
- 后续要重新使用时，应让用户重新输入 license key 激活。

## 6. Go 代码示例

### 6.1 初始化客户端

```go
package licenseguard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type Options struct {
	AppID      string
	Endpoint   string
	PublicKey  string
	AppVersion string
	HTTPClient *http.Client
}

type Client struct {
	options Options
	http    *http.Client
}

func NewClient(options Options) *Client {
	httpClient := options.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 12 * time.Second}
	}

	return &Client{
		options: options,
		http:    httpClient,
	}
}

func (c *Client) postJSON(ctx context.Context, path string, in any, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.options.Endpoint+path, bytes.NewReader(body))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-LG-App-Id", c.options.AppID)
	req.Header.Set("X-LG-SDK-Version", "go-windows-0.1.0")

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("license guard api returned %s", resp.Status)
	}

	return json.NewDecoder(resp.Body).Decode(out)
}
```

### 6.2 获取 Challenge

```go
type ChallengeRequest struct {
	AppID      string `json:"app_id"`
	Platform   string `json:"platform"`
	InstallID  string `json:"install_id"`
	AppVersion string `json:"app_version"`
}

type ChallengeResponse struct {
	ChallengeID string    `json:"challenge_id"`
	Nonce       string    `json:"nonce"`
	ExpiresAt   time.Time `json:"expires_at"`
	ServerTime  time.Time `json:"server_time"`
}

func (c *Client) Challenge(ctx context.Context, installID string) (*ChallengeResponse, error) {
	req := ChallengeRequest{
		AppID:      c.options.AppID,
		Platform:   "windows",
		InstallID:  installID,
		AppVersion: c.options.AppVersion,
	}

	var resp ChallengeResponse
	if err := c.postJSON(ctx, "/challenge", req, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}
```

### 6.3 激活授权

```go
type DeviceInfo struct {
	InstallID       string `json:"install_id"`
	Fingerprint     string `json:"fingerprint"`
	OS              string `json:"os"`
	OSVersion       string `json:"os_version"`
	MachineNameHash string `json:"machine_name_hash"`
}

type IntegrityReport struct {
	AppVersion        string   `json:"app_version"`
	MainBinaryHash    string   `json:"main_binary_hash"`
	SignerThumbprint  string   `json:"signer_thumbprint"`
	DebuggerDetected  bool     `json:"debugger_detected"`
	SuspiciousModules []string `json:"suspicious_modules"`
	VMIndicators      []string `json:"vm_indicators"`
}

type ActivateRequest struct {
	AppID       string          `json:"app_id"`
	Platform    string          `json:"platform"`
	LicenseKey  string          `json:"license_key"`
	ChallengeID string          `json:"challenge_id"`
	Nonce       string          `json:"nonce"`
	Device      DeviceInfo      `json:"device"`
	Integrity   IntegrityReport `json:"integrity"`
}

type RiskResult struct {
	Level   string   `json:"level"`
	Score   int      `json:"score"`
	Actions []string `json:"actions"`
}

type VerifyResult struct {
	Allowed           bool       `json:"allowed"`
	Code              string     `json:"code,omitempty"`
	Message           string     `json:"message,omitempty"`
	LicenseToken      string     `json:"license_token,omitempty"`
	ExpiresAt         *time.Time `json:"expires_at,omitempty"`
	OfflineGraceUntil *time.Time `json:"offline_grace_until,omitempty"`
	Entitlements      []string   `json:"entitlements,omitempty"`
	DeviceStatus      string     `json:"device_status,omitempty"`
	Risk              RiskResult `json:"risk"`
}

func (c *Client) Activate(ctx context.Context, licenseKey string) (*VerifyResult, error) {
	installID, err := LoadOrCreateInstallID()
	if err != nil {
		return nil, err
	}

	challenge, err := c.Challenge(ctx, installID)
	if err != nil {
		return nil, err
	}

	device, err := CollectDeviceInfo(installID)
	if err != nil {
		return nil, err
	}

	integrity, err := CollectIntegrity(c.options.AppVersion)
	if err != nil {
		return nil, err
	}

	req := ActivateRequest{
		AppID:       c.options.AppID,
		Platform:    "windows",
		LicenseKey:  licenseKey,
		ChallengeID: challenge.ChallengeID,
		Nonce:       challenge.Nonce,
		Device:      device,
		Integrity:   integrity,
	}

	var result VerifyResult
	if err := c.postJSON(ctx, "/activate", req, &result); err != nil {
		return nil, err
	}

	if result.Allowed && result.LicenseToken != "" {
		_ = SaveTokenDPAPI(result.LicenseToken)
	}

	return &result, nil
}
```

## 7. Install ID 与设备指纹

### 7.1 Install ID

首次运行生成 UUID，持久化到本机。

建议路径：

```text
%ProgramData%\YourCompany\YourApp\install_id
```

要求：

- 不要每次启动重新生成。
- 用户卸载后是否保留，由业务策略决定。
- 不要把 install_id 当作唯一安全凭证。

### 7.2 Device Fingerprint

设备指纹建议由多个稳定因素组合后 hash：

```text
install_id
windows machine guid
os edition
cpu architecture
可选硬件信息
```

注意：

- 不要单独依赖 MAC 地址。
- 不要采集过多敏感硬件序列号。
- 服务端应允许合理的设备变化容错。

## 8. 本地 Token 缓存

Windows 首期使用 DPAPI 加密缓存。

建议缓存：

```json
{
  "license_token": "...",
  "expires_at": "2026-06-08T10:05:00Z",
  "offline_grace_until": "2026-06-14T10:05:00Z",
  "entitlements": ["feature.pro", "export.enabled"],
  "last_verified_at": "2026-06-07T22:05:00Z"
}
```

不要缓存：

- license key 明文
- SDK Secret
- 服务端私钥

缓存策略：

- token 未过期且签名有效：可直接使用。
- token 过期但未超过签名内的 offline grace：可允许有限功能，并提示需要联网验证。
- 超过 offline grace：禁止高级功能。
- 如果配置了 `PUBLIC_KEY`，客户端必须优先信任签名 token 中的 `entitlements`，不要用可被篡改的本地 JSON 字段覆盖。
- 服务端会校验 token 中的 `device_id` 与当前设备指纹对应的设备一致；复制 token 到另一台机器会返回 `TOKEN_DEVICE_MISMATCH` 并生成风险事件。

## 9. 完整性采集

### 9.1 主程序 Hash

计算当前 EXE 的 SHA-256：

```go
package licenseguard

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
```

### 9.2 可执行文件路径

```go
package licenseguard

import "os"

func CurrentExecutableHash() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return FileSHA256(exe)
}
```

### 9.3 调试器检测

Go 可以通过 Windows API `IsDebuggerPresent` 做基础检测。该信号只能作为风险评分的一部分，不建议单独永久封禁。

### 9.4 签名证书校验

首期可以先上报 signer thumbprint，服务端与后台登记值比对。增强版可在客户端调用 Windows `WinVerifyTrust` 验证 Authenticode 签名。

要求：

- 正式发布的 EXE 必须代码签名。
- 后台登记合法证书指纹。
- 版本发布时登记主程序 hash。

## 10. 功能开关

App 不应该只在启动时校验一次。核心功能入口应检查授权结果。

示例：

```go
auth, err := client.CachedAuthorization()
if err == nil && auth.Allowed && client.IsAllowed("export.enabled") {
	// enable export
}
```

推荐控制点：

- 高级功能
- 导出功能
- 批处理功能
- 插件功能
- 云端接口
- 模型或资源下载

## 11. 授权失败处理

客户端需要对常见错误码提供明确 UI。

```text
INVALID_LICENSE          授权码无效
LICENSE_EXPIRED          授权已过期
LICENSE_REVOKED          授权已吊销
DEVICE_LIMIT_EXCEEDED    设备数超限
DEVICE_BLOCKED           设备已封禁
APP_VERSION_BLOCKED      当前版本已被阻止
INTEGRITY_FAILED         完整性验证失败
TOKEN_DEVICE_MISMATCH    授权 token 与当前设备不匹配
TOKEN_DEACTIVATED        授权 token 已停用
CHALLENGE_EXPIRED        验证请求已过期
NETWORK_ERROR            网络错误
SERVER_ERROR             服务端错误
```

建议 UI：

- 不展示内部风险细节，例如“Frida detected”。
- 展示用户能理解的处理方式。
- 支持复制错误码给客服。
- 对企业客户提供“申请换设备”入口。

## 12. 离线场景

建议默认策略：

```text
token_ttl: 12 小时
offline_grace: 7 天
heartbeat_interval: 15 分钟
```

离线行为：

- token 未过期：正常使用。
- token 已过期但在宽限期：允许有限使用，提示联网验证。
- 超过宽限期：限制高级功能。

不要做：

- 永久离线授权默认开启。
- 客户端本地自行延长授权。
- 修改系统时间后继续信任本地时间。

服务端可对系统时间异常生成风险事件。

## 13. 安全要求

必须：

- 所有 API 使用 HTTPS。
- 客户端不内置服务端私钥。
- license key 激活后不明文保存。
- 使用 challenge/nonce 防重放。
- token 短期有效。
- 敏感功能由 entitlements 控制。

建议：

- 正式发布 EXE 使用 Authenticode 代码签名。
- 发布时登记 EXE hash。
- 客户端关键字符串做基础混淆。
- 重要业务接口也做服务端鉴权。
- 风险信号只作为评分，不单点误封。

## 14. 最小接入清单

Windows Go App 首版必须完成：

- 配置 `APP_ID`、`API_ENDPOINT`、`PUBLIC_KEY`。
- 生成并保存 `install_id`。
- 实现 `/challenge`。
- 实现 `/activate`。
- 实现 `/verify`。
- 实现 `/heartbeat`。
- 采集 EXE SHA-256。
- 采集基础设备信息。
- 本地 DPAPI 加密缓存 token。
- 根据 `entitlements` 控制功能。
- 授权失败 UI。

可第二阶段完成：

- WinVerifyTrust 签名校验。
- Debugger 检测。
- 可疑模块检测。
- VM 信号采集。
- 发布 hash 清单自动上传。
- 客户端日志脱敏上报。

## 15. 联调验收

### 15.1 正常激活

```text
输入有效 license
服务端返回 allowed=true
后台出现 device 和 activation
App 解锁授权功能
```

### 15.2 超设备数

```text
同一 license 超过 max_devices
服务端返回 DEVICE_LIMIT_EXCEEDED
App 显示设备数超限
后台出现风险或操作记录
```

### 15.3 吊销授权

```text
后台吊销 license
App 下次 verify/heartbeat 失败
App 限制高级功能
```

### 15.4 篡改检测

```text
后台登记版本 hash
客户端上报 hash 不一致
服务端生成 binary_hash_mismatch
按策略拒绝 token 或进入复核
```

### 15.5 离线缓存

```text
联网激活成功
断网重启 App
token 未过期时可用
超过 offline_grace 后限制高级功能
```

## 16. 官方参考

- Microsoft SignTool: https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool
- Microsoft WinVerifyTrust: https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust
- Microsoft DPAPI CryptProtectData: https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata
- Go Windows package: https://pkg.go.dev/golang.org/x/sys/windows
