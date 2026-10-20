# CloudFront 签名 Cookie 保护私有 S3 内容

用 Go Web 应用登录用户并下发 **CloudFront 签名 Cookie**。浏览器拿到 Cookie 后，可以通过 CloudFront 直接读取私有 S3 里的文件，
不需要为每个对象生成签名 URL。

应用部署在**私有子网的 EC2** 上，CloudFront 通过 **VPC origin** 访问它。实例没有公网 IP，不对公网开放任何端口。

```
                        https://<分发>.cloudfront.net
                                     │
          ┌──────────────────────────┴───────────────────────────┐
          │ 默认行为 /*                                           │ /protected/*
          │ 不需要 Cookie                                         │ 需要 Trusted key group 的签名 Cookie
          ▼                                                       ▼
   VPC origin (HTTP :8080)                                  私有 S3 桶（OAC，Block Public Access）
          │
          ▼
   EC2 t4g.micro，私有子网，无公网 IP
   Go 应用（systemd）：GET / /login，POST /login /logout
          │
          ├─ Secrets Manager（专用 KMS）：cfcookie/signing-key, cfcookie/login-password
          ├─ SSM 参数：/cfcookie/distribution-domain
          └─ 以上都经 VPC endpoint 访问，实例没有互联网出口
```

为什么登录应用和内容放在同一个分发里：签名 Cookie 只会发给设置它的主机，所以签发 Cookie 的服务必须能通过同一个 CloudFront 域名访问。

## 文档

| 文档 | 内容 |
|---|---|
| [docs/cloudfront-s3-setup.md](docs/cloudfront-s3-setup.md) | CloudFront + S3 配置：私有桶与 OAC、公钥与 Key group、行为与缓存策略、Cookie 格式、验证与排障、密钥轮换 |
| [docs/webapp-setup.md](docs/webapp-setup.md) | Web 应用配置：网络与安全组、环境变量与机密、主机布局与 systemd、部署更新与回滚、运维与日志、本地开发、费用 |

## 快速开始

使用 AWS profile `test`，区域 `ap-northeast-1`。需要 Go、Node.js、AWS CDK、OpenSSL。

### 部署前的准备

仓库里的部署专属内容已经去掉或换成占位符，需要你按情况处理：

| 内容 | 仓库里的状态 | 全新部署 | 已有部署（换机器、重新克隆） |
|---|---|---|---|
| 账号 ID | 占位符 `123456789012` | 换成你的账号 ID | 同左 |
| 公钥 `infra/public_key.pem` | 不入库 | 运行 `gen-keys.sh` 生成 | **不要运行 `gen-keys.sh`**，从 CloudFront 取回，见 `docs/cloudfront-s3-setup.md` 3.1.1 |
| `infra/cdk.context.json` | 入库，键名里是占位账号 | 删掉，CDK 会重新生成 | **不要删**：它固定实例用的 AMI，重新解析会得到更新的 AMI，实例被替换，而 VPC origin 不允许这样，部署会失败并回滚（`docs/webapp-setup.md` 第 7 节） |

账号 ID 要替换三处：`infra/bin/app.ts` 里的 `env.account`、下面的 `cdk bootstrap` 命令，以及（已有部署时）`infra/cdk.context.json` 键名里的 `account=`。
查账号：

```bash
aws sts get-caller-identity --profile test --query Account --output text
```

### 命令

```bash
./scripts/gen-keys.sh                 # RSA-2048 密钥对 + 随机登录密码（不打印任何内容）。只用于全新部署
./scripts/build-server.sh             # build/server/cfcookie-server (linux/arm64)
cd infra && npm install
AWS_PROFILE=test npx cdk bootstrap aws://123456789012/ap-northeast-1   # 每个账号区域一次
AWS_PROFILE=test npx cdk deploy --outputs-file outputs.json             # 约 15 分钟，大部分在等 VPC origin
cd .. && ./scripts/put-secrets.sh     # 从 .secrets/ 上传私钥和密码到 Secrets Manager（file://）
rm .secrets/private_key.pem           # 现在 Secrets Manager 里是唯一副本
./scripts/e2e.sh                      # 30 项端到端检查
```

CDK 用随机占位值创建两个密钥，真实内容不会出现在模板里。`put-secrets.sh` 运行之前，`POST /login` 返回 500，不会签出任何 Cookie。

登录密码保存在 `.secrets/login_password`（权限 600）。存到别处之后可以删除这个文件，用 `put-secrets.sh` 随时重新设置。

## 使用

浏览器打开 `https://<DistributionDomain>/`，输入密码，登录后跳转到 `/protected/index.html`。域名见 `infra/outputs.json`。这个文件由 `cdk deploy --outputs-file outputs.json` 生成，**不提交到 git**（每个环境不同）。
丢失后可以重新生成：`aws cloudformation describe-stacks --stack-name CfCookieStack --query 'Stacks[0].Outputs' --profile test --region ap-northeast-1`，
但 `e2e.sh` 和 `deploy-app.sh` 读的是 `outputs.json`，所以更简单的办法是在 `infra/` 下重新执行 `npx cdk deploy --outputs-file outputs.json`。没有实际变更时很快；如果本地重新构建过二进制，会顺带更新一次制品，约 1 到 2 分钟。

命令行：

```bash
D=<DistributionDomain>
curl -c jar.txt -X POST https://$D/login --data-urlencode "password=$(cat .secrets/login_password)"
curl -b jar.txt https://$D/protected/report.txt
curl -b jar.txt -X POST https://$D/logout -c jar.txt
```

## 目录

```
cmd/server         Web 应用入口
internal/signer    签名 Cookie（RSA-SHA256 自定义策略）
internal/config    读取 Secrets Manager / SSM，5 分钟缓存
internal/app       HTTP 处理器、CSRF 防护、安全头、访问日志、登录页（web/）
infra/             CDK（TypeScript）栈 CfCookieStack
content/protected  示例文件，部署到 s3://<桶>/protected/
scripts/           gen-keys.sh  build-server.sh  put-secrets.sh  deploy-app.sh  e2e.sh
docs/              两份配置指引
```

## 更新应用

```bash
./scripts/deploy-app.sh               # 测试 → 构建 → cdk deploy → 实例拉取新版本 → 健康检查，不健康自动回滚
```

**不要替换实例。** CloudFront VPC origin 在被分发使用期间不能改指向另一个实例，替换会让部署失败并回滚。
本栈已经为此设计（固定的逻辑 ID、恒定的 user data），改代码和改配置都不会替换实例。详见 `docs/webapp-setup.md` 第 7 节。

## 测试

```bash
go vet ./... && go test -race ./...
```

- 单元测试验证签发的 Cookie：用公钥验证 RSA 签名（SHA-256），哈希改成 SHA-1 时测试会失败；还覆盖登录、跨站请求拒绝、开放重定向、模板转义。
- `scripts/e2e.sh` 对线上分发检查 30 项，包括：篡改签名和缺少 Hash 算法 Cookie 被拒绝、绕过 CloudFront 直连 S3 被拒绝、
  实例没有公网 IP、安全组没有 `0.0.0.0/0`、应用子网没有互联网路由、IMDSv2、没有 SSH 密钥对。

## 已知限制

- **所有人共用一个密码，没有用户身份。** 演示足够。真实用户场景把 `internal/app` 里的密码校验换成 Cognito 或其他 OIDC，签名部分不用改。
- **没有速率限制。** 失败登录只延迟 500 ms，挡不住并发猜密码。对外开放前在分发上挂 AWS WAF 速率规则。
- **退出登录只清除浏览器里的 Cookie。** 被复制走的 Cookie 在过期前仍然有效（`COOKIE_TTL`，默认 1 小时），所以 TTL 要短。
- **单实例，单可用区。** 没有高可用。发布有问题的版本时，从重启到自动回滚约 13 秒，期间观众收到 504。需要零中断要加 ALB 和多实例。
- **TLS 最低版本是 TLSv1。** 使用默认的 `*.cloudfront.net` 证书时 CloudFront 不允许设置最低协议版本。要 TLS 1.2 需要自定义域名和 ACM 证书（本栈未实现）。HTTP 请求会被重定向到 HTTPS。
- **CloudFront 到应用这一段是 HTTP**，走 VPC origin，流量不经过公网。
- **安全组放行的是 CloudFront 托管前缀列表**，不是你自己分发的专属安全组。实例在私有子网，没有公网路径，所以这条规则只会被 VPC origin 的网卡用到。
  更严格的做法见 `docs/webapp-setup.md` 2.3。
- **没有访问日志。** 分发和桶都没开，应用日志只在实例本地的 journald，实例重建就没了。也没有 CloudTrail 告警。
- **密钥没有自动轮换。** CloudFront 签名密钥需要手动轮换，见 `docs/cloudfront-s3-setup.md` 第 7 节。
- **演示用的销毁策略。** 存储桶、KMS 密钥、密钥设置了销毁时删除，生产环境应改成 `RETAIN`。
- 没有 Cookie 时 CloudFront 返回纯 XML 的 403（`MissingKey`）。想跳转到登录页，可以加自定义错误响应。
- **固定月费约 $52**，其中 4 个 VPC 接口端点约 $41。明细见 `docs/webapp-setup.md` 第 10 节。

## 清理

```bash
cd infra && AWS_PROFILE=test npx cdk destroy
```

删除顺序由依赖关系保证（分发 → VPC origin → 实例），桶会先被清空。这条命令我没有在本环境实际执行过。
Secrets Manager 的两个密钥和 KMS 密钥有待删除期，期间同名密钥不能重新创建，立刻重新部署前要注意。
