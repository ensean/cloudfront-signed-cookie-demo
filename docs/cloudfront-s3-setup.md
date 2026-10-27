# CloudFront + S3 配置指引

本文说明如何用 CloudFront 签名 Cookie 保护私有 S3 内容（静态站）。CDK 栈（`infra/lib/cookie-stack.ts`）已经把下面所有资源建好，
这里解释每一项为什么要这样配，以及不用 CDK 时怎样手工配置、怎样排查。

适用环境：区域 `ap-northeast-1`，AWS profile `test`。示例里的域名、分发 ID 仅作说明，以 `infra/outputs.json` 为准。

## 1. 整体结构

```
浏览器 ─https─> 主站 CloudFront (dMMM.cloudfront.net) ──> VPC origin ──> EC2 上的 Go 应用（签发 Cookie）
   │                                                                    （见 docs/webapp-setup.md）
   └──https─> 静态站 CloudFront (dSSS.cloudfront.net)
                  ├─ 默认行为  /*          ──> S3 私有桶（OAC），要求 Trusted key group 的签名 Cookie
                  ├─ 行为      /_auth/*    ──> CloudFront Function 直接应答：写入 / 删除 Cookie
                  └─ 行为      /_public/*  ──> 同一个桶，不要求 Cookie：登录提示、已退出、404 页面
```

四个要点：

1. **S3 桶完全私有**，只允许静态站分发通过 OAC 读取，没有任何公开访问。
2. **默认行为要求签名 Cookie**，由 Trusted key group 里的公钥验签。没有 Cookie、Cookie 被改、签名算法不对，CloudFront 都返回 403。
3. **Cookie 必须由静态站的主机设置。** 主站和静态站是两个 `*.cloudfront.net` 主机，不共享 Cookie 范围（`cloudfront.net` 在公共后缀列表里）。
   所以主站登录后跳转到静态站的 `/_auth/set`，由 CloudFront Function 写入 Cookie，原理见 [README](../README.md) 1.2。
4. **登录提示页要放在不要求 Cookie 的路径下**（`/_public/*`），否则错误页本身也会被拒。

## 2. S3 私有桶

### 2.1 桶设置

| 设置 | 值 | 原因 |
|---|---|---|
| Block Public Access | 四项全部开启 | 防止任何公开读取 |
| 加密 | SSE-S3，开启 Bucket Key | 静态加密，不增加 KMS 费用 |
| 仅 HTTPS | 桶策略 `Deny` 且 `aws:SecureTransport=false` | 拒绝明文访问 |
| 对象所有权 | `BucketOwnerEnforced` | 关闭 ACL，只用策略控制 |
| 版本控制 | 开启 | 误删、误覆盖可恢复 |

URL 路径与 S3 键保持一致：`https://<静态站域名>/report.txt` 对应 `s3://<桶>/report.txt`；`_public/` 下是不要求 Cookie 的页面。
CloudFront 把请求路径原样作为键，所以**不要**在源站配置里再加 Origin Path，否则键会错位。

上传内容：

```bash
aws s3 cp ./content/static/ s3://<桶名>/ --recursive --profile test --region ap-northeast-1
```

本项目的示例文件由 CDK 的 `BucketDeployment` 上传：`content/static/` 原样上传；`content/templates/` 里的页面（首页、登录提示、已退出、404）
会把 `__MAIN_URL__` 换成主站地址后上传到 `index.html` 和 `_public/`。修改后 `cdk deploy` 即可，部署会让静态站缓存失效。

### 2.2 桶策略：只允许这个分发（OAC）

CloudFront 用 OAC（Origin Access Control）以 SigV4 访问 S3。桶策略只信任这一个分发：

```json
{
  "Effect": "Allow",
  "Principal": { "Service": "cloudfront.amazonaws.com" },
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::<桶名>/*",
  "Condition": {
    "StringEquals": { "AWS:SourceArn": "arn:aws:cloudfront::<账号ID>:distribution/<静态站分发ID>" }
  }
}
```

另外给同一个主体授予 `s3:ListBucket`（资源是桶本身）。没有它，私有桶对不存在的键也返回 403，会被"请登录"页面误导；
有了它，已登录用户访问不存在的文件得到 404。这不泄露内容：签名校验在访问 S3 之前，没有有效 Cookie 的人到不了这一步。

要点：

- 条件里是**分发 ARN**，不是账号。同账号的其他分发也读不了这个桶。
- 用 OAC，不要用旧的 OAI。OAC 使用 SigV4，支持 SSE-KMS。
- 桶如果用 SSE-KMS 加密，还要在 KMS 密钥策略里给 `cloudfront.amazonaws.com` 授予 `kms:Decrypt`、`kms:GenerateDataKey*`。本项目用 SSE-S3，不需要。

创建 OAC（手工方式）：

```bash
aws cloudfront create-origin-access-control --profile test --origin-access-control-config '{
  "Name": "cfcookie-s3-oac",
  "SigningProtocol": "sigv4",
  "SigningBehavior": "always",
  "OriginAccessControlOriginType": "s3"
}'
```

`SigningBehavior` 必须是 `always`，设成 `never` 时 CloudFront 不签名，私有桶会返回 403。

## 3. 签名密钥：公钥、私钥、Key group

签名 Cookie 的信任链：**私钥**（只在应用端，用来签名）→ **公钥**（在 CloudFront，用来验签）→ **Key group**（行为里引用的一组公钥）。

### 3.1 生成密钥对

CloudFront 要求 **RSA 2048**。

```bash
./scripts/gen-keys.sh
```

脚本生成下面三个文件，不会把任何内容打印到终端：

- `.secrets/private_key.pem`：私钥，权限 600。
- `infra/public_key.pem`：公钥，CDK 读取它创建 CloudFront 公钥。
- `.secrets/login_password`：随机登录密码。

**已有密钥对时脚本拒绝运行**（`infra/public_key.pem` 存在，或本地私钥存在）。私钥上传后按流程会被删除，
所以"没有私钥"不代表"没有密钥对"。如果覆盖已注册的公钥，下次 `cdk deploy` 会替换 CloudFront 公钥，所有 Cookie 失效。
确实要轮换时用 `ROTATE_KEYS=yes`，见第 7 节。

### 3.1.1 公钥不入库，换一台机器时怎么找回

`infra/public_key.pem` 是某个部署专属的密钥材料，已被 `.gitignore` 排除，**不会出现在新克隆的仓库里**。
全新部署：按 [deploy.md](deploy.md) 先运行 `gen-keys.sh`，它会生成这个文件。

**已有部署、换了一台机器或重新克隆时，不要运行 `gen-keys.sh`。** 它会生成一把新的密钥对，下次 `cdk deploy` 会替换 CloudFront 公钥，
线上所有 Cookie 失效，而 Secrets Manager 里还是旧私钥，服务会签出无效的 Cookie。应该从 CloudFront 把已注册的公钥取回来：

```bash
KID=<PublicKeyId，见 cdk deploy 的输出>
aws cloudfront get-public-key --id "$KID" --profile test --region ap-northeast-1 \
  --query 'PublicKey.PublicKeyConfig.EncodedKey' --output text \
  | sed -e :a -e '/^\n*$/{$d;N;ba' -e '}' > infra/public_key.pem
```

末尾那条 `sed` 不能省：`--output text` 会在内容后多输出一个空行。实测带着这个空行时，`cdk diff` 会把 `SigningPublicKey` 列为变更，
部署时会去修改 CloudFront 公钥；去掉空行后 `cdk diff` 里公钥资源没有差异。

取回后用 `cdk diff` 确认 `SigningPublicKey` 没有出现在变更里，再继续部署。

等价的手工命令：

```bash
openssl genrsa -out private_key.pem 2048
openssl rsa -pubout -in private_key.pem -out public_key.pem
```

### 3.2 在 CloudFront 注册公钥和 Key group（手工方式）

```bash
# 公钥。CallerReference 任意唯一字符串。
aws cloudfront create-public-key --profile test --public-key-config "{
  \"CallerReference\": \"cfcookie-$(date +%s)\",
  \"Name\": \"cfcookie-key\",
  \"EncodedKey\": $(python3 -c 'import json;print(json.dumps(open("public_key.pem").read()))')
}"
# 记下返回的 Id（形如 K2EXAMPLE12345），它就是 Cookie 里的 CloudFront-Key-Pair-Id。

aws cloudfront create-key-group --profile test --key-group-config '{
  "Name": "cfcookie-signers",
  "Items": ["<公钥 Id>"]
}'
```

### 3.3 私钥放哪里

私钥**只放 Secrets Manager**，不进代码、环境变量文件、镜像或日志：

- 密钥 `cfcookie/signing-key`（PEM 文本）和 `cfcookie/login-password`，用专用 KMS 密钥加密。
- CDK 创建时只放随机占位值，真实内容用脚本从文件上传（`file://`，不会出现在进程列表或 shell 历史里）：

```bash
./scripts/put-secrets.sh
rm .secrets/private_key.pem      # 上传完成后删除本地私钥
```

- 应用的实例角色只有这两个密钥的 `GetSecretValue`，KMS 解密还被限定为只能经 Secrets Manager 使用（`kms:ViaService`）。

占位值不是有效的 PEM，所以在上传真实私钥之前，登录接口返回 500，不会签出无效 Cookie。

## 4. 分发（Distribution）配置

### 4.1 行为总览

**主站分发**只有一个默认行为：

| | 默认行为 `*` |
|---|---|
| 源站 | VPC origin → EC2:8080（HTTP） |
| Viewer protocol | `redirect-to-https` |
| 允许的方法 | GET HEAD OPTIONS PUT POST PATCH DELETE |
| Cache policy | `Managed-CachingDisabled` |
| Origin request policy | `Managed-AllViewer` |

**静态站分发**：

| | 默认行为 `*` | `/_public/*` | `/_auth/*` |
|---|---|---|---|
| 源站 | S3 桶（OAC） | 同一个桶 | 同一个桶（不会被访问） |
| Viewer protocol | `https-only` | `https-only` | `https-only` |
| 允许的方法 | GET HEAD | GET HEAD | GET HEAD |
| Cache policy | `Managed-CachingOptimized` | `Managed-CachingOptimized` | `Managed-CachingDisabled` |
| Trusted key groups | 本项目的 Key group | 无 | 无 |
| Function | 无 | 无 | `AuthHandoffFunction`（viewer request） |
| Response headers policy | `Managed-SecurityHeadersPolicy` | 同左 | 无（函数自己设头） |
| 其他 | 根路径 `index.html`；403 → `/_public/login-required.html`，404 → `/_public/not-found.html` | | |

几处容易配错的地方：

- **主站默认行为必须允许 POST。** 登录是 `POST /login`，只开 GET/HEAD 会得到 403。
- **主站默认行为不缓存。** 登录页、重定向都不能被缓存。
- **主站默认行为的 Origin request policy 必须转发 `Host`。** 用 `Managed-AllViewer`。应用的跨站请求防护会比较 `Origin` 和 `Host`，用 `AllViewerExceptHostHeader` 时 Host 被改成源站内网域名，浏览器提交的登录表单会被误判为跨站，返回 403。
- **静态站用缓存是安全的。** CloudFront 在查缓存**之前**先校验签名 Cookie，缓存键里不需要包含 Cookie，所以不同用户共用同一份缓存对象也不会绕过认证。
- **错误页必须在开放路径下。** 自定义错误页由对应路径的行为取回；放在要求 Cookie 的默认行为下，它自己也会被拒。错误页缓存时间设为 0。
- **行为按列表顺序匹配，默认行为永远最后。** `/_public/*` 和 `/_auth/*` 先于默认行为命中。新增行为时注意顺序，范围大的模式放在后面。
- **`/_auth/*` 的函数是 viewer request 类型**，在缓存和源站之前运行并直接返回响应。它读完整的查询字符串，不受缓存策略里查询字符串白名单的影响。

### 4.2 域名与 TLS

- 默认使用 `*.cloudfront.net` 证书，此时**最低 TLS 版本固定为 TLSv1**，无法修改。HTTP 请求会被重定向到 HTTPS。
- 要强制 TLS 1.2：使用自定义域名，在 `us-east-1` 申请 ACM 证书，分发里设置 `SecurityPolicy = TLSv1.2_2021`。
- **本栈目前不支持自定义域名。** 要使用，需要在 `infra/lib/cookie-stack.ts` 的 `StaticDistribution` 里加 `domainNames` 和 `certificate`，
  并把 SSM 参数 `/cfcookie/static-domain` 的值改成静态站的自定义域名。不要手工改这个参数：它由 CDK 管理，下次部署会被覆盖回 `*.cloudfront.net`。
  Cookie 策略里的域名必须与用户实际访问的域名一致，否则签名有效但资源不匹配，CloudFront 返回 403。
  两个站放在同一个父域下时，应用可以直接设置 `Domain=<父域>` 的 Cookie，不再需要 `/_auth/set` 这一跳。
  应用每 5 分钟重新读取一次配置，部署后最多 5 分钟生效。

### 4.3 Cookie 内容

应用签出 4 个 Cookie 的值，由静态站的函数写成 Cookie，缺一个签名就会失败：

| Cookie | 内容 |
|---|---|
| `CloudFront-Policy` | Base64（CloudFront 变体）编码的自定义策略 JSON |
| `CloudFront-Signature` | 对策略 JSON 的 RSA-SHA256 签名 |
| `CloudFront-Key-Pair-Id` | CloudFront 公钥 ID |
| `CloudFront-Hash-Algorithm` | 固定 `SHA256` |

策略示例（自定义策略，一次签名覆盖整个路径；`EpochTime` 是过期时间，此处为 2026-10-21 01:00 UTC）：

```json
{
  "Statement": [{
    "Resource": "https://d222222abcdef8.cloudfront.net/*",
    "Condition": { "DateLessThan": { "AWS:EpochTime": 1792544400 } }
  }]
}
```

- **必须带 `CloudFront-Hash-Algorithm=SHA256`。** 缺少这个 Cookie 时 CloudFront 默认按 SHA-1 验签，SHA-256 的签名会被拒绝。
- Base64 编码要换字符：`+`→`-`，`=`→`_`，`/`→`~`。用 AWS SDK 的 `sign` 包不用自己处理。
- `Resource` 里的协议和域名要与访问的完全一致，路径支持 `*` 通配。
- Cookie 属性：`Secure; HttpOnly; SameSite=Lax; Path=/`，**不设置 `Domain`**（只对静态站这一个主机有效）。
  Cookie 在静态站的主机上，不会发给主站的应用。

## 5. 验证

CDK 部署后，用脚本做端到端检查：

```bash
./scripts/e2e.sh
```

手工验证 S3 + Cookie 这部分：

```bash
M=<主站域名>; S=<静态站域名>
# 1. 没有 Cookie：403，页面是"请登录"
curl -i https://$S/index.html

# 2. 登录：主站返回 303，Location 是静态站的 /_auth/set?p=…&s=…&k=…&e=…&n=…，主站没有 Set-Cookie
curl -i -X POST https://$M/login --data-urlencode "password=$(cat .secrets/login_password)"

# 3. 把 Location 交给静态站：303 + 4 个 Set-Cookie（保存到 jar）
curl -i -c jar.txt '<上一步的 Location>'

# 4. 带 Cookie：200
curl -b jar.txt -i https://$S/report.txt

# 5. 绕过 CloudFront 直连 S3：403
curl -i https://<桶名>.s3.ap-northeast-1.amazonaws.com/index.html
```

## 6. 常见问题

| 现象 | 原因与处理 |
|---|---|
| 静态站显示"Sign in required" | 请求没带有效 Cookie（没登录、已过期、或域名不对）。从主站登录。直接用 curl 看原始响应时是 `403`，原因 `MissingKey`。 |
| 登录后停在 `/_auth/set` 并返回 `400` | 函数拒绝了参数：值含非法字符、`e` 已过期或超过 7 天、参数缺失或重复。检查主站与静态站的时钟，以及 `HandoffURL` 的输出。 |
| 登录后表单提交没有任何反应（Chrome） | 登录页的 CSP `form-action` 没放行静态站。检查 SSM 参数 `/cfcookie/static-domain` 是否已写入，应用配置是否加载成功。 |
| `403`，Cookie 都在 | 先看 Hash 算法：缺 `CloudFront-Hash-Algorithm=SHA256` 就会失败。再看策略里的域名是否是**静态站**的域名（不是主站的），以及是否已过期。 |
| `403`，`AccessDenied` XML 来自 S3 | OAC 或桶策略有问题：桶策略里的分发 ARN 是否正确（应是静态站分发），OAC 的 `SigningBehavior` 是否 `always`。 |
| 登录后马上又要登录 | 客户端时钟偏差大，或 `COOKIE_TTL` 太短。Cookie 过期时间是服务端时间 + TTL。 |
| 换了新密钥对后所有人都 403 | 三处必须是同一对：Key group 里的公钥、`/etc/cfcookie/env` 里的 `KEY_ID`、Secrets Manager 里的私钥。按第 7 节的顺序操作，并等最多 5 分钟让应用读到新私钥。 |
| 修改分发后行为没变 | CloudFront 配置传播到全部边缘约需几分钟，`aws cloudfront get-distribution` 的 `Status` 为 `Deployed` 才算完成。 |

查看 CloudFront 请求 ID 对应的应用日志：应用日志里每条请求都带 `cf_id`，与响应头 `x-amz-cf-id` 一致，
可以把用户报告的请求直接对上应用日志。

## 7. 轮换签名密钥

```bash
rm -f .secrets/private_key.pem        # 如果还在
ROTATE_KEYS=yes ./scripts/gen-keys.sh # 生成新密钥对，覆盖 infra/public_key.pem
./scripts/deploy-app.sh               # CDK 创建新公钥、更新 Key group，并让实例应用新的 KEY_ID
./scripts/put-secrets.sh              # 上传新私钥
```

要点：

- **顺序有讲究。** `deploy-app.sh` 之后、`put-secrets.sh` 之前，应用用的是新的 `KEY_ID` 和旧私钥，签出的 Cookie 会 403，登录后拿不到内容。
  两步之间的时间越短越好。应用最多 5 分钟后读到新私钥（配置缓存），所以上传后最长有 5 分钟窗口。
- `KEY_ID` 写在实例的 `/etc/cfcookie/env` 里，由 `releases/setup.sh` 生成。`deploy-app.sh` 会让实例重新拉取并应用 `setup.sh`，
  **不会替换实例**。
- 旧 Cookie 在新 Key group 生效后立即失效，用户需要重新登录。

CloudFront 的 Key group 可以放多把公钥。零中断的轮换做法是：先把新公钥加入 Key group，应用切换到新私钥签发，
等旧 Cookie 全部过期（最长 `COOKIE_TTL`）后再移除旧公钥。本项目没有实现这个流程。

## 8. 费用

按东京区域标价，主要固定成本在应用侧（见 `docs/webapp-setup.md`）。CloudFront 和 S3 部分只按用量计费：
CloudFront 请求与流量、S3 存储与请求，演示规模可以忽略。KMS 密钥和两个密钥合计每月约 1.8 美元。
