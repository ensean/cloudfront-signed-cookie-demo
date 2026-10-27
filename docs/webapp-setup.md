# Web 应用配置指引（EC2 上的 Go 服务）

本文说明签发 CloudFront 签名 Cookie 的 Go Web 应用怎么部署在 EC2 上、怎么配置、怎么更新和排障。
CloudFront 与 S3 的配置见 `docs/cloudfront-s3-setup.md`。

适用环境：账号 `123456789012`，区域 `ap-northeast-1`，AWS profile `test`。

## 1. 应用做什么

| 路径 | 方法 | 作用 |
|---|---|---|
| `/` `/login` | GET | 登录页（纯 HTML 表单，没有 JavaScript） |
| `/login` | POST | 校验密码；成功后签出 4 个 Cookie 的值，303 跳转到**静态站**的 `/_auth/set`（由那里写入 Cookie，主站不设 Cookie）；失败返回 401 并重新显示表单 |
| `/logout` | POST | 303 跳转到静态站的 `/_auth/clear`，由那里删除 Cookie 并显示已退出页 |
| `/style.css` | GET | 登录页样式 |
| `/healthz` | GET | 健康检查，返回 `ok`，不读取配置 |

代码结构：

```
cmd/server/main.go     入口：读取环境变量、超时、优雅关闭
internal/app           HTTP 处理器、中间件（CSRF 防护、安全头、访问日志）、登录页
internal/config        从 Secrets Manager / SSM 读取配置，5 分钟缓存
internal/signer        生成签名 Cookie（RSA-SHA256 自定义策略）
```

## 2. 部署形态

```
CloudFront ──VPC origin──> EC2 (私有子网, 无公网 IP) :8080  ── cfcookie-server (systemd)
                                  │
                                  ├─ VPC endpoint ─> Secrets Manager（私钥、登录密码）
                                  ├─ VPC endpoint ─> SSM（域名参数；Session Manager；Run Command）
                                  └─ S3 网关端点 ──> 制品桶（二进制、setup.sh）
```

### 2.1 为什么用 VPC origin

应用要接收明文 HTTP（CloudFront 到源站这一段，见 2.3），并且处理登录密码。VPC origin 让这一段流量留在 AWS 内部网络里，
实例不需要公网 IP，也不需要对公网开放任何端口。

不用 VPC origin 的替代方案是给实例公网 IP，安全组放行 CloudFront 的托管前缀列表。这样 CloudFront 到源站走公网，
如果没有自定义域名和证书就只能是 HTTP 明文，登录密码会明文经过公网。本项目没有这样做。

### 2.2 网络

| 项目 | 配置 |
|---|---|
| VPC | `10.20.0.0/24`，单可用区 `ap-northeast-1a` |
| 应用子网 | `/26` 私有隔离子网，没有任何指向 IGW 或 NAT 的路由 |
| 空的公有子网 | `/28`，只是为了让 VPC 有互联网网关（VPC origin 的要求），里面没有任何资源 |
| 出口 | S3 网关端点（免费）+ 4 个接口端点：`secretsmanager`、`ssm`、`ssmmessages`、`ec2messages` |

**可用区限制：** CloudFront VPC origin 在东京区域不支持可用区 ID `apne1-az3`。可用区名称到 ID 的映射因账号而异，
本账号的 `ap-northeast-1a` 是 `apne1-az4`。换账号部署时先确认：

```bash
aws ec2 describe-availability-zones --profile test --region ap-northeast-1 \
  --query 'AvailabilityZones[].[ZoneName,ZoneId]' --output text
```

### 2.3 安全组

应用实例的安全组（`AppSg`）：

| 方向 | 对端 | 端口 | 说明 |
|---|---|---|---|
| 入站 | CloudFront 托管前缀列表 `com.amazonaws.global.cloudfront.origin-facing` | TCP 8080 | 只允许 CloudFront |
| 出站 | VPC endpoint 的安全组 | TCP 443 | Secrets Manager、SSM |
| 出站 | S3 托管前缀列表 | TCP 443 | 下载二进制 |

没有 `0.0.0.0/0`，没有 SSH（22 端口）。这条规则在 `scripts/e2e.sh` 里每次都会检查。

注意：CloudFront 前缀列表有约 55 个条目，**计入安全组 60 条入站规则的默认配额**。不要往这个安全组里再加别的入站规则。

更严格的做法是改成只放行 VPC origin 自动创建的服务安全组（`CloudFront-VPCOrigins-Service-SG`），把流量限定到你自己的分发。
这个安全组要等 VPC origin 建好之后才存在，CDK 里需要用自定义资源查询它的 ID，见 CDK 文档中 VPC origin 一节。本项目没有做这一步。

### 2.4 实例

| 项目 | 值 |
|---|---|
| 机型 | `t4g.micro`（Graviton，1 GiB 内存），实际占用约 20 MB |
| 系统 | Amazon Linux 2023 arm64（AMI 固定在 `infra/cdk.context.json`） |
| 磁盘 | 8 GiB gp3，加密 |
| 元数据 | 强制 IMDSv2 |
| 登录方式 | 只有 SSM Session Manager，没有密钥对 |
| IAM 角色 | `AmazonSSMManagedInstanceCore` + 两个密钥的读取 + 域名参数读取 + 制品桶 `releases/*` 读取 |

## 3. 配置

### 3.1 环境变量

应用只用环境变量配置。在实例上它们写在 `/etc/cfcookie/env`（权限 640，`root:cfcookie`），由 systemd 的 `EnvironmentFile` 加载。
**这个文件里没有任何机密**，只有名称和标识。

| 变量 | 必需 | 默认 | 说明 |
|---|---|---|---|
| `KEY_ID` | 是 | | CloudFront 公钥 ID（`CloudFront-Key-Pair-Id` Cookie 的值） |
| `SIGNING_KEY_SECRET_ID` | 二选一 | | Secrets Manager 里 PEM 私钥的密钥名 |
| `PRIVATE_KEY_FILE` | 二选一 | | 本地开发：私钥文件路径 |
| `LOGIN_SECRET_ID` | 二选一 | | Secrets Manager 里登录密码的密钥名 |
| `LOGIN_PASSWORD` | 二选一 | | 本地开发：登录密码 |
| `DOMAIN_PARAM` | 二选一 | | 保存**静态站**域名的 SSM 参数名（`/cfcookie/static-domain`） |
| `DOMAIN` | 二选一 | | 本地开发：静态站域名 |
| `COOKIE_TTL` | 否 | `1h` | Cookie 有效期，Go duration 格式，最长 7 天 |
| `PROTECTED_PREFIX` | 否 | `/protected/` | Cookie 策略覆盖的静态站路径，必须以 `/` 开头和结尾。本栈设为 `/`（整个静态站），默认登录后打开 `<前缀>index.html` |
| `LISTEN_ADDR` | 否 | `127.0.0.1:8080` | 监听地址。实例上是 `0.0.0.0:8080` |
| `AWS_REGION` | 是（EC2 上） | | AWS SDK 区域 |

规则：

- 私钥必须是 **RSA 2048**，PKCS#8（`BEGIN PRIVATE KEY`）或 PKCS#1（`BEGIN RSA PRIVATE KEY`）都可以。其他位数或类型启动时就会报错。
- 登录密码至少 12 个字符，否则拒绝加载（防止空值或占位符）。
- 配置缓存 5 分钟。密钥轮换后最多 5 分钟生效；刷新失败时继续使用上一次成功的配置并记警告日志。
- 首次加载失败（例如密钥还是占位值）时，登录接口返回 500，**不会签出 Cookie**。

### 3.2 机密

| 密钥 | 内容 | 存放 |
|---|---|---|
| `cfcookie/signing-key` | PEM 私钥 | Secrets Manager，专用 KMS 密钥加密 |
| `cfcookie/login-password` | 登录密码 | 同上 |

- 应用启动后通过 VPC endpoint 读取，不写磁盘。
- 实例角色只有这两个密钥的 `GetSecretValue`；KMS 解密被限定为只能经 Secrets Manager 使用（`kms:ViaService`）。
- 不要把它们放进 user data、`/etc/cfcookie/env`、镜像或日志。应用的错误信息只包含密钥名，不包含内容。

上传真实值（从文件读取，不出现在进程列表或 shell 历史里）：

```bash
./scripts/gen-keys.sh        # 首次：生成密钥对和随机登录密码（已有密钥对时拒绝运行）
./scripts/put-secrets.sh     # 上传到 Secrets Manager
rm .secrets/private_key.pem  # 上传后删除本地私钥
```

修改登录密码：把新密码写入 `.secrets/login_password`（不要带换行），再运行 `./scripts/put-secrets.sh`。最多 5 分钟后生效。

## 4. 主机上的布局

| 路径 | 内容 | 权限 |
|---|---|---|
| `/opt/cfcookie/cfcookie-server` | 应用二进制 | 755 `root:root` |
| `/opt/cfcookie/cfcookie-server.prev` | 上一个版本，供回滚 | 755 |
| `/etc/cfcookie/env` | 环境变量文件 | 640 `root:cfcookie` |
| `/etc/systemd/system/cfcookie.service` | systemd 单元 | |
| `/usr/local/bin/cfcookie-update` | 更新脚本（下载、替换、重启、健康检查、回滚） | 755 |
| `/root/setup.sh` | 最近一次应用的主机配置脚本 | |

systemd 单元的加固设置：

```ini
[Service]
User=cfcookie                      # 专用系统用户，无登录 shell
EnvironmentFile=/etc/cfcookie/env
ExecStart=/opt/cfcookie/cfcookie-server
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict               # 文件系统只读
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=             # 不保留任何 capability
LockPersonality=true
```

## 5. 首次部署

部署命令见 [deploy.md](deploy.md) 第 4 节。第一次 `cdk deploy` 约 15 分钟，大部分时间在等 CloudFront VPC origin。

首次启动流程：

1. CDK 把二进制和 `releases/setup.sh` 放进制品桶。
2. 实例启动，user data 只做两件事：从制品桶下载 `setup.sh`，执行它。
3. `setup.sh` 创建 `cfcookie` 用户、写环境变量文件、安装更新脚本和 systemd 单元，然后调用更新脚本。
4. 更新脚本下载二进制、启动服务、检查 `/healthz`。

在密钥写入之前，服务已经在跑，但登录返回 500（见 3.1）。

## 6. 更新应用

```bash
./scripts/deploy-app.sh
```

脚本依次做：`go vet` 和 `go test` → 构建 → `cdk deploy` → 通过 SSM Run Command 让实例重新执行 `setup.sh`。

实例上的更新脚本做：

1. 下载最新的 `setup.sh` 并应用（环境变量文件、systemd 单元、更新脚本本身）。
2. 下载新二进制，把旧的备份为 `.prev`，换入新的。
3. 重启服务，最多等 20 秒看 `/healthz`。
4. **不健康就自动换回旧二进制并重启**，脚本以非零状态退出，`deploy-app.sh` 随之失败。

只想让实例重新拉取当前版本（不重新构建、不跑 CDK）：

```bash
./scripts/deploy-app.sh --no-cdk
```

### 6.1 更新期间的影响

单实例没有滚动更新，重启服务会短暂中断：

- 正常更新：服务重启约 1 秒，观众可能遇到少量失败请求。
- 发布了有问题的版本：从重启到回滚完成约 **13 秒**，期间 CloudFront 返回 504，之后自动恢复。（用一个立即退出的假二进制实测。）

需要零中断时，要在 CloudFront 的 VPC origin 前面放 ALB，后面放两台以上实例。本项目没有做。

### 6.2 回滚到更早的版本

制品桶开启了版本控制。`.prev` 只保留上一个版本。更早的版本在 S3 里：

```bash
B=$(python3 -c "import json;print(json.load(open('infra/outputs.json'))['CfCookieStack']['ArtifactBucketName'])")
aws s3api list-object-versions --bucket $B --prefix releases/cfcookie-server --profile test --region ap-northeast-1 \
  --query 'Versions[].[VersionId,LastModified,Size]' --output text
# 选版本时看 Size：几十字节的是测试用的假二进制，不是真实版本（真实二进制约 17 MB）。
# 把选中的版本复制成最新版本，再让实例重新拉取：
aws s3api copy-object --bucket $B --key releases/cfcookie-server \
  --copy-source "$B/releases/cfcookie-server?versionId=<VersionId>" --profile test --region ap-northeast-1
./scripts/deploy-app.sh --no-cdk
```

## 7. 重要限制：不能替换实例

**CloudFront VPC origin 在被分发使用期间，不能改指向另一个实例。** 替换实例会让 CloudFormation 更新 VPC origin，
返回 `409: The specified VPC origin is currently associated with one or more distributions`，整个部署回滚。
本项目实测过这个失败（回滚是安全的，线上没有中断）。

因此本栈这样设计：

- 实例的**逻辑 ID 被固定**（`overrideLogicalId`），避免 CDK 因内容变化生成新 ID。
- **user data 是恒定的三行**，只负责下载并执行 `setup.sh`。所有会变化的内容（环境变量、systemd 单元、更新脚本）都在 `setup.sh` 里，
  通过 S3 + SSM 下发，不依赖 user data。
- 因此改配置、换公钥、改代码**都不会**替换或重启实例。

哪些改动会替换实例（依据 CloudFormation 的 `AWS::EC2::Instance` 文档）：

| 改动 | 对实例的影响 |
|---|---|
| `ImageId`（换 AMI）、`SubnetId`（换子网或可用区） | **替换**，部署会因 VPC origin 的 409 失败并回滚 |
| `InstanceType`（改机型） | 取决于新旧机型是否兼容，可能重启，也可能替换。同一系列内改大小通常只是重启，换架构（如 arm64 换 x86）会替换 |
| `SecurityGroupIds`、user data | 重启，不替换（EBS 根卷实例） |
| `IamInstanceProfile`、IAM 策略 | 无中断 |

因此**不要随便改 AMI**：`infra/cdk.context.json` 里固定了 AMI ID，就是为了防止 CDK 在你不注意时解析到新 AMI 而触发替换。
系统补丁用 `dnf upgrade` 在实例上打（经 SSM 执行），不要换 AMI。

真的需要换实例（换 AMI、换子网）时，有两种做法：

- 在 CloudFront 里先把这个 VPC origin 从分发的默认行为上解除，再换实例，再重新关联。期间登录页不可用。
- 改用 ALB 作为 VPC origin 的目标，实例放在 ALB 后面。以后换实例不影响 VPC origin，但每月增加 ALB 的固定费用，本项目没有做。

**不要随便改 `infra/lib/cookie-stack.ts` 里 user data 那三行**。改动会让实例重启一次（EBS 实例更新 user data 的行为），而且重启**不会重新执行 user data**。

## 8. 日常运维

### 8.1 登录实例

没有 SSH。用 Session Manager（需要本机安装 `session-manager-plugin`，在交互式终端里运行）：

```bash
INSTANCE=$(python3 -c "import json;print(json.load(open('infra/outputs.json'))['CfCookieStack']['InstanceId'])")
aws ssm start-session --target $INSTANCE --profile test --region ap-northeast-1
```

### 8.2 看状态和日志

在实例上：

```bash
systemctl status cfcookie
journalctl -u cfcookie -f                    # 实时日志
journalctl -u cfcookie --since "10 min ago"
curl -s http://127.0.0.1:8080/healthz
```

不登录，直接从本机执行一条命令：

```bash
aws ssm send-command --profile test --region ap-northeast-1 --instance-ids $INSTANCE \
  --document-name AWS-RunShellScript --parameters 'commands=["systemctl is-active cfcookie","journalctl -u cfcookie -n 20 --no-pager -o cat"]' \
  --query Command.CommandId --output text
# 用返回的 CommandId 取结果：
aws ssm get-command-invocation --profile test --region ap-northeast-1 --instance-id $INSTANCE --command-id <CommandId> \
  --query '[Status,StandardOutputContent]' --output text
```

### 8.3 日志格式

日志是 JSON，输出到 journald。每个请求一行：

```json
{"time":"...","level":"INFO","msg":"request","method":"POST","path":"/login","status":303,"ms":4,"cf_id":"gYuLq9I9..."}
```

- 只记录**路径**，不记录查询字符串、表单内容、Cookie。
- `cf_id` 是 CloudFront 的请求 ID（响应头 `x-amz-cf-id`），把用户报告的请求直接对到这一行。
- 登录成功记 `login ok`（含 Cookie 过期时间，不含签名），失败记 `login failed`（不含任何输入内容）。
- 日志只在实例本地的 journald 里，实例重建就没了。需要长期保留要装 CloudWatch Agent，本项目没有做。

### 8.4 常用检查

| 现象 | 看什么 |
|---|---|
| 访问首页 502/504 | `systemctl status cfcookie`；`ss -ltn sport = :8080`；VPC origin 状态；安全组是否被改过 |
| 登录返回 500 | `journalctl -u cfcookie`，找 `load config`：密钥还是占位值、私钥不是 RSA 2048、密码少于 12 字符、IAM 或 VPC endpoint 不通 |
| 登录返回 403 | 不是应用返回的。浏览器提交的表单被跨站防护拒绝时应用返回 403（日志里 `status:403`）：检查 CloudFront 默认行为的 Origin request policy 是否转发 `Host`（见 `docs/cloudfront-s3-setup.md` 4.1） |
| 登录成功但静态站仍 403 | Cookie 问题，见 `docs/cloudfront-s3-setup.md` 第 6 节 |
| `deploy-app.sh` 失败，提示 `new release is not healthy` | 新版本起不来，已自动回滚。看输出里的 journal 片段，修好后重新部署 |
| SSM 命令一直 `Pending` | 实例的 SSM Agent 连不上 endpoint：检查三个 SSM endpoint 和 endpoint 安全组 |

### 8.5 应用自带的安全措施

| 措施 | 说明 |
|---|---|
| 密码比较 | 先做 SHA-256 再常量时间比较，不泄露密码长度 |
| 失败延迟 | 密码错误时延迟 500 ms 再响应（响应可被客户端取消） |
| CSRF 防护 | Go 标准库 `http.CrossOriginProtection`：拒绝 `Sec-Fetch-Site: cross-site` 或 `Origin` 与 `Host` 不一致的 POST |
| 开放重定向 | `next` 参数只接受配置前缀下的本地路径（不含 `//`、反斜杠、换行），其他值一律换成默认页；静态站的函数还会再检查一次 |
| 输出转义 | 登录页用 `html/template`，`next` 和错误信息自动转义 |
| 请求体限制 | 4 KB |
| 响应头 | `Cache-Control: no-store`、`X-Content-Type-Options`、`Referrer-Policy: no-referrer`、`X-Frame-Options: DENY`、CSP（不允许任何脚本） |
| 服务器超时 | 读请求头 5 秒、读 10 秒、写 15 秒、空闲 60 秒 |

**没有的东西：** 速率限制（失败延迟挡不住并发猜密码，对外开放前应在 CloudFront 上挂 AWS WAF 速率规则）、
多用户、审计日志、登录失败锁定。

## 9. 本地开发

不需要 AWS 凭证，用文件和环境变量。本地用一把**一次性私钥**，不要用线上的密钥对
（`scripts/gen-keys.sh` 在已有密钥对时会拒绝运行，这是有意的，见 `docs/cloudfront-s3-setup.md` 第 7 节）：

```bash
go test -race ./...

mkdir -p /tmp/cfcookie-local && openssl genrsa -out /tmp/cfcookie-local/key.pem 2048
KEY_ID=KLOCALTEST \
PRIVATE_KEY_FILE=/tmp/cfcookie-local/key.pem \
LOGIN_PASSWORD='a-local-password-123' \
DOMAIN=d111111abcdef8.cloudfront.net \
go run ./cmd/server
```

然后访问 `http://127.0.0.1:8080/`。

本地没有静态站，登录后的跳转指向 `DOMAIN` 里的域名，浏览器会真的去那里。用 curl 看跳转地址：

```bash
curl -i -X POST http://127.0.0.1:8080/login --data-urlencode 'password=a-local-password-123'
```

应该得到 `303`，`Location` 是 `https://<DOMAIN>/_auth/set?e=…&k=…&n=/index.html&p=…&s=…`，响应里没有 `Set-Cookie`。
本地启动时要设置 `PROTECTED_PREFIX=/`，与线上一致。

`go run` 在没有 AWS 凭证时仍能启动，因为 AWS SDK 的客户端是惰性创建的，只有设置了 `*_SECRET_ID` 或 `DOMAIN_PARAM` 才会真正调用 AWS。

## 10. 费用

东京区域按需价格，每月 730 小时。固定成本：

| 项目 | 单价 | 每月 |
|---|---|---|
| EC2 `t4g.micro` | $0.0108/小时 | 约 $7.9 |
| 4 个接口端点 | $0.014/小时/个 | 约 $41 |
| KMS 密钥 | | 约 $1 |
| 2 个密钥 | $0.40/个 | $0.80 |
| EBS 8 GiB gp3 | | 约 $0.8 |
| **合计（不含流量与请求）** | | **约 $52** |

接口端点是最大的一块。替代方案是 NAT 网关（$0.062/小时，约 $45，另加 $0.062/GB 流量），费用相当，
但会让实例有互联网出口，本项目为了保持实例完全隔离选了端点。

想省钱：去掉 `ssm`、`ssmmessages`、`ec2messages` 三个端点可以省约 $31/月，代价是没有 Session Manager 和 Run Command，
更新只能靠重建实例（受第 7 节限制）或别的方式，不推荐。

## 11. 清理

```bash
cd infra && AWS_PROFILE=test npx cdk destroy
```

存储桶、KMS 密钥、密钥都设置了销毁时删除，适合演示。KMS 密钥有 7 天的待删除期，密钥名在删除期内不能重用。
生产环境应把这些改成 `RETAIN`。
