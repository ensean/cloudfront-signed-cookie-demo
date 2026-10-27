# CloudFront 签名 Cookie：主站登录，静态站读取私有 S3

两个站点，两个 CloudFront 分发：

- **主站**：EC2 上的 Go 应用，只做登录。校验密码后用私钥签出 **CloudFront 签名 Cookie**。
- **静态站**：CloudFront + 私有 S3 桶，存放文件。浏览器带着签名 Cookie 访问，CloudFront 在边缘验签，通过后才从 S3 取文件。

在主站登录一次，就可以在静态站查看和下载文件。一次签名覆盖整个站点，不需要为每个对象生成签名 URL。

## 1. 工作原理

```
浏览器                    主站 CloudFront + EC2                 静态站 CloudFront                  S3（私有）
  │ 1. POST /login password=…      │                                   │                              │
  │───────────────────────────────>│ Go 应用校验密码，用私钥签策略         │                              │
  │ 2. 303 → https://静态站/_auth/set?p=…&s=…&k=…&e=…&n=/report.txt                                    │
  │<───────────────────────────────│（主站不设置任何 Cookie）            │                              │
  │ 3. GET /_auth/set?…  ──────────────────────────────────────────────>│ CloudFront Function          │
  │ 4. 303 /report.txt + 4 个 Set-Cookie（属于静态站的域名）              │ 校验参数，写入 Cookie          │
  │<────────────────────────────────────────────────────────────────────│                              │
  │ 5. GET /report.txt  Cookie: CloudFront-…                            │                              │
  │────────────────────────────────────────────────────────────────────>│ 用 Key group 里的公钥验签     │
  │                                                                     │ 通过 → 经 OAC 读取 ──────────>│
  │ 6. 200 文件内容                                                      │<─────────────────────────────│
  │<────────────────────────────────────────────────────────────────────│ 不通过 → 403，不访问 S3       │
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
    "Resource": "https://d222222abcdef8.cloudfront.net/*",
    "Condition": { "DateLessThan": { "AWS:EpochTime": 1792544400 } }
  }]
}
```

- `Resource` 是**静态站**的域名。它支持 `*` 通配，所以一组 Cookie 能访问整个站点。协议和域名必须与用户访问的完全一致。
- `DateLessThan` 是过期时间，默认签发后 1 小时。还可以加 `DateGreaterThan`（生效时间）和 `IpAddress`（来源 IP），本项目没用。

### 1.2 为什么需要"Cookie 跳转"

Cookie 只会发给设置它的主机。主站和静态站是两个分发，域名分别是 `dxxx.cloudfront.net` 和 `dyyy.cloudfront.net`：

- 主站无法为静态站设置 Cookie：浏览器只接受响应来源主机自己的 Cookie。
- 也无法用 `Domain=cloudfront.net` 让两个站共享：`cloudfront.net` 在公共后缀列表里，浏览器会拒绝。

所以主站登录成功后，不设置 Cookie，而是 **303 跳转到静态站的 `/_auth/set`**，把签好的值放在查询参数里：

| 参数 | 含义 |
|---|---|
| `p` | `CloudFront-Policy` 的值 |
| `s` | `CloudFront-Signature` 的值 |
| `k` | `CloudFront-Key-Pair-Id` 的值 |
| `e` | 过期时间（Unix 秒），用作 Cookie 的 `Expires` |
| `n` | 写完 Cookie 后要打开的本地路径 |

静态站上的 **CloudFront Function**（`infra/functions/auth-handoff.js`）把它们写成 4 个 `Set-Cookie`，再 303 跳转到 `n`。
Cookie 由静态站自己的响应设置，所以属于静态站的主机。退出登录同理：主站跳转到静态站的 `/_auth/clear`，由它删除 Cookie。

这个函数没有任何密钥：

- 每个参数都按它应有的字符集严格校验（`p`、`s` 只允许 CloudFront 的 Base64 字符，`e` 只允许数字，且必须在未来 7 天内，`n` 必须是本地路径），不会注入头、属性或站外跳转。
- 伪造的参数只能写入 CloudFront 会拒绝的 Cookie：没有有效签名就读不到任何内容。
- 参数里的值与 Cookie 值相同，有效期内等同于登录凭证。主站响应带 `Referrer-Policy: no-referrer` 和 `Cache-Control: no-store`，应用日志只记路径、不记查询字符串；两个分发都没有开启访问日志。

> 如果你有自己的域名，可以把两个分发放到同一个父域下（`app.example.com` 和 `files.example.com`），
> 应用直接设置 `Domain=example.com` 的 Cookie，就不需要这个函数。本栈没有域名，所以采用跳转方式。

### 1.3 Cookie 属性

`Secure; HttpOnly; SameSite=Lax; Path=/`，**不设置 `Domain`**，由静态站的函数设置。

- **不设 `Domain`**：Cookie 只发给静态站这一个主机。
- **`HttpOnly`**：页面脚本读不到，XSS 拿不走。
- **`SameSite=Lax`**：从主站点链接进入静态站（顶层 GET 导航）会带上 Cookie；第三方页面里嵌入静态站资源不会带。
- 退出登录只是让浏览器删除 Cookie。被复制走的 Cookie 在过期前仍然有效，CloudFront 没有吊销机制，所以有效期要短。

### 1.4 信任链

私钥只在应用端（存 Secrets Manager），用来签名。公钥注册到 CloudFront，放进 **Key group**，再在静态站的默认行为上设置
**Trusted key groups**。CloudFront 用 `CloudFront-Key-Pair-Id` 在 Key group 里找公钥。CloudFront 要求 RSA 2048。

## 2. CloudFront 配置

### 2.1 主站分发

一个默认行为，源站是 VPC origin → EC2 上的 Go 应用（HTTP 8080）。不缓存，允许全部方法（登录要 POST），
Origin request policy 用 `AllViewer`，把 `Host` 转发给应用：应用的跨站请求防护比较 `Origin` 和 `Host`，
用 `AllViewerExceptHostHeader` 时 Host 被改成源站内网域名，浏览器提交的登录表单会被当成跨站请求拒绝。

### 2.2 静态站分发

| 行为 | 源站 | 访问控制 | 作用 |
|---|---|---|---|
| 默认 `*` | 私有 S3，OAC | **Trusted key groups**（要求签名 Cookie） | 站点内容，根路径返回 `index.html` |
| `/_auth/*` | 同一个桶 | 无（CloudFront Function 直接应答，不访问 S3） | 写入 / 删除 Cookie |
| `/_public/*` | 同一个桶 | 无 | 登录提示页、已退出页、404 页 |

- **S3 桶完全私有。** 开启 Block Public Access，桶策略只允许 `cloudfront.amazonaws.com` 且 `AWS:SourceArn` 等于静态站分发的 ARN。直连 S3 返回 403。
- **缓存是安全的。** CloudFront 先验签再查缓存，缓存键不需要包含 Cookie。
- **没有有效 Cookie 时**，CloudFront 返回 403，自定义错误响应把它换成 `/_public/login-required.html`（状态码仍是 403），页面里有回主站登录的链接。
  这个页面放在不要求 Cookie 的 `/_public/*` 下，否则错误页本身也会被拒。
- **文件不存在**时返回 404 页（授予了 `s3:ListBucket`，否则私有桶对不存在的键也返回 403，会被误显示成"请登录"）。
- **签名失败的表现**：没有 Cookie、签名被篡改、缺少 Hash 算法 Cookie、过期、资源不匹配都返回 403，不访问 S3。

逐项配置、手工命令和排障见 [docs/cloudfront-s3-setup.md](docs/cloudfront-s3-setup.md)。

## 3. Web 应用实现

Go 标准库 `net/http`，签名用 AWS SDK 的 `github.com/aws/aws-sdk-go-v2/feature/cloudfront/sign`。

| 路径 | 方法 | 作用 |
|---|---|---|
| `/`、`/login` | GET | 登录页（纯 HTML 表单），带静态站入口链接 |
| `/login` | POST | 校验密码，成功则 303 跳转到静态站的 `/_auth/set`，失败 401 |
| `/logout` | POST | 303 跳转到静态站的 `/_auth/clear` |
| `/healthz` | GET | 健康检查 |

### 3.1 签名（`internal/signer`）

```go
cs := sign.NewCookieSigner(keyID, privateKey)
cs.HashAlg = sign.HashSHA256 // 同时输出 CloudFront-Hash-Algorithm=SHA256

expires := time.Now().Add(ttl).UTC().Truncate(time.Second)
policy := &sign.Policy{Statements: []sign.Statement{{
    Resource:  "https://" + staticDomain + "/*",
    Condition: sign.Condition{DateLessThan: sign.NewAWSEpochTime(expires)},
}}}
cookies, err := cs.SignWithPolicy(policy)
```

`HandoffURL` 把签出的 Cookie 值取出来，拼成 `https://<静态站>/_auth/set?p=…&s=…&k=…&e=…&n=…`。
SDK 默认用 SHA-1 且不输出 Hash 算法 Cookie，所以要显式设置 `HashAlg`。SDK 的 `LoadPEMPrivKey` 只认 PKCS#1，
本项目自己解析，PKCS#8 和 PKCS#1 都支持，并在启动时检查是不是 RSA 2048。

### 3.2 登录（`internal/app`）

```go
if !passwordMatches(r.PostForm.Get("password"), cfg.Password) { // SHA-256 后常量时间比较
    s.sleep(r.Context(), s.FailDelay)                           // 失败延迟 500 ms
    s.render(w, r, http.StatusUnauthorized, pageData{Error: "Wrong password.", Next: next})
    return
}
target, _, err := cfg.Signer.HandoffURL(next)                   // next 只允许本地路径
...
http.Redirect(w, r, target, http.StatusSeeOther)
```

其他防护：标准库 `http.CrossOriginProtection` 拒绝跨站 POST；登录页用 `html/template` 转义；请求体限制 4 KB；
CSP 不允许任何脚本，带表单的页面把 `form-action` 放行给静态站（Chrome 对表单提交后的重定向也检查它）；
访问日志只记路径和 CloudFront 请求 ID（`X-Amz-Cf-Id`），不记查询字符串、表单和 Cookie。

### 3.3 配置与机密（`internal/config`）

- 私钥和登录密码在 Secrets Manager，运行时读取，不落盘、不进环境变量；**静态站**的域名在 SSM 参数 `/cfcookie/static-domain` 里。
- 配置缓存 5 分钟，轮换后自动生效；刷新失败时继续用上一次的配置。
- 首次加载失败（例如密钥还是占位值）时登录返回 500，不会签出无效 Cookie。

环境变量、部署形态、systemd、日志和运维见 [docs/webapp-setup.md](docs/webapp-setup.md)。

## 4. 目录与测试

```
cmd/server         入口：超时、优雅关闭
internal/signer    签名、跳转 URL
internal/app       HTTP 处理器、中间件、登录页
internal/config    读取 Secrets Manager / SSM
infra/             CDK 栈；functions/ 是静态站上的 CloudFront Function，test/ 是它的单元测试
content/static     原样上传到静态站的文件
content/templates  要写入主站地址的页面（首页、登录提示、已退出、404）
scripts/           密钥生成、上传机密、部署、端到端检查
docs/              配置指引与部署指南
```

```bash
go vet ./... && go test -race ./...
node --test infra/test/auth-handoff.test.js
```

签名测试用公钥验证签发的值（SHA-256），把哈希改成 SHA-1 测试会失败。部署后的端到端检查见部署指南。

## 5. 文档

| 文档 | 内容 |
|---|---|
| [docs/deploy.md](docs/deploy.md) | 用 CDK 部署、更新、验证、清理，以及已知限制和费用 |
| [docs/cloudfront-s3-setup.md](docs/cloudfront-s3-setup.md) | CloudFront + S3 逐项配置、Cookie 细节、排障、密钥轮换 |
| [docs/webapp-setup.md](docs/webapp-setup.md) | Web 应用的网络、配置、主机布局、发布与回滚、运维 |
