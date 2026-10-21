# CloudFront 签名 Cookie 保护私有 S3 内容

一个 Go Web 应用校验用户身份后下发 **CloudFront 签名 Cookie**。浏览器带着 Cookie 访问 `/protected/*`，
CloudFront 在边缘验签，通过后才从私有 S3 桶取文件。一次签名覆盖整个路径，不需要为每个对象生成签名 URL。

## 1. 工作原理

```
浏览器                           CloudFront                        Go 应用 (EC2)            S3（私有）
  │ 1. POST /login password=…      │                                  │                        │
  │───────────────────────────────>│ 默认行为，转发给应用 ──────────────>│                        │
  │                                │                                  │ 校验密码               │
  │                                │                                  │ 用私钥签策略           │
  │ 2. 303 + 4 个 Set-Cookie        │<──────────────────────────────────│                        │
  │<───────────────────────────────│                                  │                        │
  │ 3. GET /protected/report.txt    │                                  │                        │
  │    Cookie: CloudFront-…         │                                  │                        │
  │───────────────────────────────>│ 用 Key group 里的公钥验签          │                        │
  │                                │ 检查资源和过期时间                 │                        │
  │                                │ 通过 → 经 OAC 读取 ─────────────────────────────────────────>│
  │ 4. 200 文件内容                 │<─────────────────────────────────────────────────────────────│
  │<───────────────────────────────│ 不通过 → 403，不访问 S3             │                        │
```

### 1.1 四个 Cookie

| Cookie | 内容 |
|---|---|
| `CloudFront-Policy` | 策略 JSON，Base64 编码（CloudFront 变体：`+`→`-`，`=`→`_`，`/`→`~`） |
| `CloudFront-Signature` | 用私钥对策略 JSON 做的 RSA 签名，同样编码 |
| `CloudFront-Key-Pair-Id` | CloudFront 公钥 ID，告诉 CloudFront 用哪把公钥验签 |
| `CloudFront-Hash-Algorithm` | `SHA256`。缺少时 CloudFront 按 SHA-1 验签，SHA-256 签名会被拒绝 |

策略（自定义策略）：

```json
{
  "Statement": [{
    "Resource": "https://d111111abcdef8.cloudfront.net/protected/*",
    "Condition": { "DateLessThan": { "AWS:EpochTime": 1792544400 } }
  }]
}
```

- `Resource` 支持 `*` 通配，所以一组 Cookie 能访问 `/protected/` 下的所有文件。协议和域名必须与用户访问的完全一致。
- `DateLessThan` 是过期时间，默认签发后 1 小时。还可以加 `DateGreaterThan`（生效时间）和 `IpAddress`（来源 IP），本项目没用。

### 1.2 Cookie 属性

`Secure; HttpOnly; SameSite=Lax; Path=/protected/`，**不设置 `Domain`**。

- **不设 `Domain`**：Cookie 只发给签发它的主机。所以签发 Cookie 的应用和受保护内容必须在同一个 CloudFront 域名下，本项目把应用放在同一个分发的默认行为里。
- **`Path=/protected/`**：Cookie 只随受保护的请求发送，不会发给登录页。
- **`HttpOnly`**：页面脚本读不到，XSS 拿不走。
- 退出登录只是让浏览器删除 Cookie。被复制走的 Cookie 在过期前仍然有效，CloudFront 没有吊销机制，所以有效期要短。

### 1.3 信任链

私钥只在应用端（存 Secrets Manager），用来签名。公钥注册到 CloudFront，放进 **Key group**，再在 `/protected/*` 行为上设置
**Trusted key groups**。CloudFront 用 `CloudFront-Key-Pair-Id` 在 Key group 里找公钥。CloudFront 要求 RSA 2048。

## 2. CloudFront 配置

一个分发，两个行为：

| | 默认行为 `*` | `/protected/*` |
|---|---|---|
| 源站 | VPC origin → EC2 上的 Go 应用（HTTP 8080） | 私有 S3 桶，OAC |
| 访问控制 | 无 | **Trusted key groups**（要求签名 Cookie） |
| 允许的方法 | 全部（登录要 POST） | GET、HEAD |
| Cache policy | `CachingDisabled` | `CachingOptimized` |
| Origin request policy | `AllViewer`（转发 `Host`，见下） | 无 |
| Viewer protocol | HTTP 重定向到 HTTPS | 仅 HTTPS |

要点：

- **S3 桶完全私有。** 开启 Block Public Access，桶策略只允许 `cloudfront.amazonaws.com` 且 `AWS:SourceArn` 等于这个分发的 ARN。直连 S3 返回 403。
- **受保护行为可以放心缓存。** CloudFront 先验签再查缓存，缓存键不需要包含 Cookie。
- **默认行为必须转发 `Host`。** 应用的跨站请求防护比较 `Origin` 和 `Host`。用 `AllViewerExceptHostHeader` 时 Host 被改成源站内网域名，浏览器提交的登录表单会被当成跨站请求拒绝。
- **签名失败的表现**：没有 Cookie 返回 403 和 `MissingKey`；签名被篡改、缺少 Hash 算法 Cookie、过期、资源不匹配都返回 403。

逐项配置、手工命令和排障见 [docs/cloudfront-s3-setup.md](docs/cloudfront-s3-setup.md)。

## 3. Web 应用实现

Go 标准库 `net/http`，签名用 AWS SDK 的 `github.com/aws/aws-sdk-go-v2/feature/cloudfront/sign`。

| 路径 | 方法 | 作用 |
|---|---|---|
| `/`、`/login` | GET | 登录页（纯 HTML 表单） |
| `/login` | POST | 校验密码，成功则下发 4 个 Cookie 并 303 跳转，失败 401 |
| `/logout` | POST | 清除 Cookie，303 跳转到 `/` |
| `/healthz` | GET | 健康检查 |

### 3.1 签发 Cookie（`internal/signer`）

```go
cs := sign.NewCookieSigner(keyID, privateKey)
cs.HashAlg = sign.HashSHA256 // 同时输出 CloudFront-Hash-Algorithm=SHA256

expires := time.Now().Add(ttl).UTC().Truncate(time.Second)
policy := &sign.Policy{Statements: []sign.Statement{{
    Resource:  "https://" + domain + "/protected/*",
    Condition: sign.Condition{DateLessThan: sign.NewAWSEpochTime(expires)},
}}}
cookies, err := cs.SignWithPolicy(policy, func(o *sign.CookieOptions) {
    o.Path = "/protected/"
    o.Secure = true
    o.SameSite = http.SameSiteLaxMode
    o.Expires = expires
})
```

SDK 默认用 SHA-1 且不输出 Hash 算法 Cookie，所以要显式设置 `HashAlg`。SDK 的 `LoadPEMPrivKey` 只认 PKCS#1，
本项目自己解析，PKCS#8 和 PKCS#1 都支持，并在启动时检查是不是 RSA 2048。

### 3.2 登录（`internal/app`）

```go
if !passwordMatches(r.PostForm.Get("password"), cfg.Password) { // SHA-256 后常量时间比较
    s.sleep(r.Context(), s.FailDelay)                           // 失败延迟 500 ms
    s.render(w, http.StatusUnauthorized, pageData{Error: "Wrong password.", Next: next})
    return
}
cookies, _, err := cfg.Signer.Issue()
if err != nil {
    http.Error(w, "could not issue cookies", http.StatusInternalServerError)
    return
}
for _, c := range cookies {
    http.SetCookie(w, c)
}
http.Redirect(w, r, next, http.StatusSeeOther) // next 只允许 /protected/ 下的本地路径
```

其他防护：标准库 `http.CrossOriginProtection` 拒绝跨站 POST；登录页用 `html/template` 转义；请求体限制 4 KB；
CSP 不允许任何脚本；访问日志只记路径和 CloudFront 请求 ID（`X-Amz-Cf-Id`），不记表单和 Cookie。

### 3.3 配置与机密（`internal/config`）

- 私钥和登录密码在 Secrets Manager，运行时读取，不落盘、不进环境变量；CloudFront 域名在 SSM 参数里。
- 配置缓存 5 分钟，轮换后自动生效；刷新失败时继续用上一次的配置。
- 首次加载失败（例如密钥还是占位值）时登录返回 500，不会签出无效 Cookie。

环境变量、部署形态、systemd、日志和运维见 [docs/webapp-setup.md](docs/webapp-setup.md)。

## 4. 目录与测试

```
cmd/server         入口：超时、优雅关闭
internal/signer    签名 Cookie
internal/app       HTTP 处理器、中间件、登录页
internal/config    读取 Secrets Manager / SSM
infra/             CDK 栈
scripts/           密钥生成、上传机密、部署、端到端检查
docs/              配置指引与部署指南
```

```bash
go vet ./... && go test -race ./...
```

签名测试用公钥验证签发的 Cookie（SHA-256），把哈希改成 SHA-1 测试会失败。部署后的端到端检查（30 项）见部署指南。

## 5. 文档

| 文档 | 内容 |
|---|---|
| [docs/deploy.md](docs/deploy.md) | 用 CDK 部署、更新、验证、清理，以及已知限制和费用 |
| [docs/cloudfront-s3-setup.md](docs/cloudfront-s3-setup.md) | CloudFront + S3 逐项配置、Cookie 细节、排障、密钥轮换 |
| [docs/webapp-setup.md](docs/webapp-setup.md) | Web 应用的网络、配置、主机布局、发布与回滚、运维 |
