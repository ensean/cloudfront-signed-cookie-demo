# 用 CDK 部署

本文说明如何用 CDK 部署整套环境（`infra/` 下的栈 `CfCookieStack`），以及更新、验证、清理。
原理和实现见 [README](../README.md)，各组件的详细配置见 [cloudfront-s3-setup.md](cloudfront-s3-setup.md) 和 [webapp-setup.md](webapp-setup.md)。

## 1. 栈里有什么

| 资源 | 说明 |
|---|---|
| VPC | 单可用区，应用子网没有互联网路由；一个空的公有子网只为满足 VPC origin 对互联网网关的要求 |
| VPC endpoint | S3 网关端点，Secrets Manager、SSM、SSM Messages、EC2 Messages 接口端点 |
| EC2 | `t4g.micro`，Amazon Linux 2023 arm64，无公网 IP，IMDSv2，无密钥对，只能 Session Manager 登录 |
| CloudFront（主站） | 分发 + VPC origin，源站是 EC2 上的 Go 应用 |
| CloudFront（静态站） | 分发 + S3 OAC、公钥、Key group、Cookie 跳转函数 `AuthHandoffFunction`、自定义错误页 |
| S3 | 内容桶（静态站文件，`_public/` 下是登录提示等开放页面）和制品桶（二进制与主机配置脚本） |
| KMS + Secrets Manager | 专用 KMS 密钥，加密签名私钥和登录密码两个密钥 |
| SSM 参数 | `/cfcookie/static-domain`，应用从这里读静态站域名（签名策略和跳转地址用它） |

## 2. 前提

- AWS profile `test`，区域 `ap-northeast-1`。
- 本机有 Go、Node.js、AWS CLI、OpenSSL；Session Manager 登录还需要 `session-manager-plugin`。

## 3. 部署前的准备

仓库里的部署专属内容已经去掉或换成占位符，按情况处理：

| 内容 | 仓库里的状态 | 全新部署 | 已有部署（换机器、重新克隆） |
|---|---|---|---|
| 账号 ID | 取自 CDK 运行时的凭证（`CDK_DEFAULT_ACCOUNT`） | 无需修改 | 无需修改 |
| 公钥 `infra/public_key.pem` | 不入库 | 运行 `gen-keys.sh` 生成 | **不要运行 `gen-keys.sh`**，从 CloudFront 取回，见 [cloudfront-s3-setup.md](cloudfront-s3-setup.md) 3.1.1 |
| `infra/cdk.context.json` | 入库；键名带账号 ID | 没有就让 CDK 生成（里面是查询缓存） | **不要删**，见下 |
| `infra/outputs.json` | 不入库 | `cdk deploy` 生成 | 重新执行一次 `cdk deploy --outputs-file outputs.json` |

账号 ID 不写在代码里：`infra/bin/app.ts` 用 `CDK_DEFAULT_ACCOUNT`，由 `AWS_PROFILE` 指向的凭证决定。第 4 节的 `cdk bootstrap` 命令里要填同一个账号：

```bash
aws sts get-caller-identity --profile test --query Account --output text
```

**为什么已有部署不能删 `cdk.context.json`：** 它固定了实例用的 AMI。删掉后 CDK 会解析到更新的 AMI，实例需要替换，
而 VPC origin 在被分发使用期间不能改指向另一个实例，部署会失败并回滚。见 [webapp-setup.md](webapp-setup.md) 第 7 节。

## 4. 首次部署

```bash
./scripts/gen-keys.sh                 # RSA-2048 密钥对 + 随机登录密码（不打印任何内容）。只用于全新部署
./scripts/build-server.sh             # build/server/cfcookie-server (linux/arm64)
cd infra && npm install
AWS_PROFILE=test npx cdk bootstrap aws://<账号ID>/ap-northeast-1   # 每个账号区域一次
AWS_PROFILE=test npx cdk deploy --outputs-file outputs.json             # 约 15 分钟，大部分在等 VPC origin
cd .. && ./scripts/put-secrets.sh     # 从 .secrets/ 上传私钥和密码到 Secrets Manager（file://）
rm .secrets/private_key.pem           # 现在 Secrets Manager 里是唯一副本
./scripts/e2e.sh                      # 端到端检查（主站 + 静态站）
```

- CDK 用随机占位值创建两个密钥，真实内容不会出现在模板里。`put-secrets.sh` 运行之前，`POST /login` 返回 500，不会签出任何 Cookie。
- 登录密码保存在 `.secrets/login_password`（权限 600）。存到别处之后可以删除这个文件，用 `put-secrets.sh` 随时重新设置。
- 两个站点的域名（`MainDomain`、`StaticDomain`）、实例 ID、桶名等输出在 `infra/outputs.json`，`e2e.sh` 和 `deploy-app.sh` 都读这个文件。

## 5. 验证

自动检查：

```bash
./scripts/e2e.sh
```

覆盖：主站登录页与 CSP；没有 Cookie 时静态站返回 403 和登录提示页；登录后跳转到静态站、Cookie 写在静态站主机上（`HttpOnly`、`Secure`、`Path=/`、无 `Domain`）、主站自己不设 Cookie；
带 Cookie 能查看和下载文件（下载内容与源文件逐字节一致）；缺失文件返回 404；篡改签名和缺少 Hash 算法 Cookie 被拒绝；`/_auth/set` 拒绝畸形、缺失、过期的参数，站外 `n` 被换成默认页，
伪造的 Cookie 被 CloudFront 拒绝；跨站 POST 被拒绝；直连 S3 被拒绝；实例没有公网 IP、安全组没有 `0.0.0.0/0`、应用子网没有互联网路由、IMDSv2、没有 SSH 密钥对；退出后无法访问。

命令行手动验证：

```bash
M=<MainDomain>; S=<StaticDomain>
curl -s -o /dev/null -w '%{http_code}\n' https://$S/report.txt              # 403：没有 Cookie
LOC=$(curl -s -D - -o /dev/null -X POST https://$M/login \
  --data-urlencode "password=$(cat .secrets/login_password)" \
  --data-urlencode 'next=/report.txt' | grep -i '^location:' | cut -d' ' -f2 | tr -d '\r')   # 303 到静态站的 /_auth/set
curl -s -o /dev/null -c jar.txt "$LOC"                                       # 303：静态站写入 4 个 Cookie
curl -s -b jar.txt https://$S/report.txt                                     # 200：文件内容
curl -s -o /dev/null -b jar.txt -c jar.txt https://$S/_auth/clear            # 删除 Cookie
curl -s -o /dev/null -w '%{http_code}\n' -b jar.txt https://$S/report.txt    # 403：已退出
```

浏览器：打开 `https://<MainDomain>/`，输入密码后会经过静态站的 `/_auth/set`，落在 `https://<StaticDomain>/index.html`，页面列出可查看和下载的文件。
开发者工具里应该能在**静态站**的域名下看到 4 个 Cookie，都是 `HttpOnly`、`Secure`、`Path=/`；主站域名下没有 Cookie。
在主站页面点 "Sign out"，会经静态站的 `/_auth/clear` 删除 Cookie，并显示已退出页。

## 6. 更新

```bash
./scripts/deploy-app.sh               # 测试 → 构建 → cdk deploy → 实例拉取新版本 → 健康检查，不健康自动回滚
./scripts/deploy-app.sh --no-cdk      # 只让实例重新拉取当前版本
```

**不要替换实例。** 栈已经为此设计：实例逻辑 ID 固定，user data 恒定，所有可变配置通过 S3 上的 `setup.sh` 下发。
改代码、改配置、换公钥都不会替换实例。哪些属性变化会触发替换，见 [webapp-setup.md](webapp-setup.md) 第 7 节。

发布、回滚到更早版本、日志和排障见 [webapp-setup.md](webapp-setup.md) 第 6、8 节。

## 7. 已知限制

- **所有人共用一个密码，没有用户身份。** 真实用户场景把 `internal/app` 里的密码校验换成 Cognito 或其他 OIDC，签名部分不用改。
- **没有速率限制。** 失败登录只延迟 500 ms，挡不住并发猜密码。对外开放前在分发上挂 AWS WAF 速率规则。
- **单实例，单可用区。** 发布有问题的版本时，从重启到自动回滚约 13 秒，期间观众收到 504。需要零中断要加 ALB 和多实例。
- **TLS 最低版本是 TLSv1。** 默认 `*.cloudfront.net` 证书不允许设置最低协议版本。要 TLS 1.2 需要自定义域名和 ACM 证书（本栈未实现）。
- **签名值经过 URL。** 跳转到静态站的 `/_auth/set` 时，策略和签名在查询参数里（有效期内等同登录凭证）。两个分发都没开访问日志，主站响应带 `Referrer-Policy: no-referrer`。
  有自己的域名时，把两个站放在同一个父域下，应用直接设置 `Domain=<父域>` 的 Cookie，就不需要这一跳。
- **Cookie 过期后看到的是登录提示页，不会自动跳转。** 静态站返回 403 并显示带"回主站登录"链接的页面。
- **CloudFront 到应用是 HTTP**，走 VPC origin，不经过公网。
- **安全组放行的是 CloudFront 托管前缀列表**，不是你自己分发的专属安全组。更严格的做法见 [webapp-setup.md](webapp-setup.md) 2.3。
- **没有访问日志和告警。** 两个分发和桶都没开日志，应用日志只在实例本地 journald。
- **密钥不会自动轮换**，手动轮换见 [cloudfront-s3-setup.md](cloudfront-s3-setup.md) 第 7 节。
- **演示用的销毁策略。** 桶、KMS 密钥、密钥都设置了销毁时删除，生产环境应改成 `RETAIN`。

## 8. 费用

固定月费约 **$52**（东京按需价），其中 4 个 VPC 接口端点约 $41、`t4g.micro` 约 $7.9。
CloudFront 和 S3 按用量计费，演示规模可以忽略。明细见 [webapp-setup.md](webapp-setup.md) 第 10 节。

## 9. 清理

```bash
cd infra && AWS_PROFILE=test npx cdk destroy
```

删除顺序由依赖关系保证（分发 → VPC origin → 实例），桶会先被清空。这条命令没有在本环境实际执行过。
KMS 密钥和两个 Secrets Manager 密钥有待删除期，期间同名密钥不能重新创建，立刻重新部署前要注意。
