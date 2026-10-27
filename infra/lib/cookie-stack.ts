import * as fs from "fs";
import * as path from "path";
import * as cdk from "aws-cdk-lib";
import * as cloudfront from "aws-cdk-lib/aws-cloudfront";
import * as origins from "aws-cdk-lib/aws-cloudfront-origins";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as iam from "aws-cdk-lib/aws-iam";
import * as kms from "aws-cdk-lib/aws-kms";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as s3deploy from "aws-cdk-lib/aws-s3-deployment";
import * as secretsmanager from "aws-cdk-lib/aws-secretsmanager";
import * as ssm from "aws-cdk-lib/aws-ssm";
import { Construct } from "constructs";

// The static site's CloudFront domain, read by the application to know which host the cookies are for.
const DOMAIN_PARAM = "/cfcookie/static-domain";
const PUBLIC_PREFIX = "_public"; // objects under it are served without cookies
const SIGNING_SECRET_NAME = "cfcookie/signing-key";
const LOGIN_SECRET_NAME = "cfcookie/login-password";
const APP_PORT = 8080;
const RELEASE_PREFIX = "releases";
const RELEASE_KEY = `${RELEASE_PREFIX}/cfcookie-server`; // the Go binary
const SETUP_KEY = `${RELEASE_PREFIX}/setup.sh`; // host configuration (env file, systemd unit, updater)

// CloudFront VPC origins are not available in apne1-az3. In this account
// ap-northeast-1a is apne1-az4 (check with `aws ec2 describe-availability-zones`).
const AZ = "ap-northeast-1a";

export class CookieStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const root = path.join(__dirname, "..", "..");
    const publicKeyFile = path.join(__dirname, "..", "public_key.pem");
    const serverDir = path.join(root, "build", "server");
    const contentDir = path.join(root, "content", "static"); // files served as they are
    const templatesDir = path.join(root, "content", "templates"); // pages that link back to the main site
    const authFunctionFile = path.join(__dirname, "..", "functions", "auth-handoff.js");

    for (const [file, hint] of [
      [publicKeyFile, "run scripts/gen-keys.sh"],
      [path.join(serverDir, "cfcookie-server"), "run scripts/build-server.sh"],
    ]) {
      if (!fs.existsSync(file)) {
        throw new Error(`${file} not found: ${hint}`);
      }
    }

    // ---- Encryption key for the two secrets (dedicated CMK, rotation on) ----
    const secretsKey = new kms.Key(this, "SecretsKey", {
      alias: "alias/cfcookie-secrets",
      description: "Encrypts the cfcookie signing key and login password secrets",
      enableKeyRotation: true,
      removalPolicy: cdk.RemovalPolicy.DESTROY, // demo stack; use RETAIN for production
      pendingWindow: cdk.Duration.days(7),
    });

    // Both secrets are created with a throwaway random value and are overwritten
    // out-of-band by scripts/put-secrets.sh, so the real values never enter
    // the template, the CDK state or CloudFormation.
    const placeholder = { passwordLength: 32, excludePunctuation: true };
    const signingKeySecret = new secretsmanager.Secret(this, "SigningKeySecret", {
      secretName: SIGNING_SECRET_NAME,
      description: "PEM RSA-2048 private key used to sign CloudFront cookies",
      encryptionKey: secretsKey,
      generateSecretString: placeholder,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });
    const loginSecret = new secretsmanager.Secret(this, "LoginSecret", {
      secretName: LOGIN_SECRET_NAME,
      description: "Password that unlocks the protected content",
      encryptionKey: secretsKey,
      generateSecretString: placeholder,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // ---- Private bucket behind the static site ----
    const bucket = new s3.Bucket(this, "ContentBucket", {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      bucketKeyEnabled: true,
      enforceSSL: true,
      versioned: true,
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
      removalPolicy: cdk.RemovalPolicy.DESTROY, // demo stack
      autoDeleteObjects: true,
    });

    // ---- CloudFront public key + trusted key group ----
    const publicKey = new cloudfront.PublicKey(this, "SigningPublicKey", {
      encodedKey: fs.readFileSync(publicKeyFile, "utf8"),
      comment: "cfcookie signed cookie verification key",
    });
    const keyGroup = new cloudfront.KeyGroup(this, "KeyGroup", {
      items: [publicKey],
      comment: "cfcookie trusted signers",
    });

    // ---- Network: one private subnet, no internet route ----
    // A VPC origin requires an internet gateway on the VPC, and CDK only creates one
    // when a public subnet exists, so a tiny empty public subnet is declared. The instance
    // lives in the isolated subnet: no public IP, no NAT, no route to the internet.
    const vpc = new ec2.Vpc(this, "AppVpc", {
      ipAddresses: ec2.IpAddresses.cidr("10.20.0.0/24"),
      availabilityZones: [AZ],
      natGateways: 0,
      subnetConfiguration: [
        { name: "igw-only", subnetType: ec2.SubnetType.PUBLIC, cidrMask: 28 },
        { name: "app", subnetType: ec2.SubnetType.PRIVATE_ISOLATED, cidrMask: 26 },
      ],
    });
    const appSubnets: ec2.SubnetSelection = { subnetType: ec2.SubnetType.PRIVATE_ISOLATED };

    // ---- Security groups ----
    const appSg = new ec2.SecurityGroup(this, "AppSg", {
      vpc,
      description: "cfcookie app - inbound from CloudFront only",
      allowAllOutbound: false,
    });
    // The endpoints only answer; they never need to open connections.
    const endpointSg = new ec2.SecurityGroup(this, "EndpointSg", {
      vpc,
      description: "cfcookie VPC endpoints - inbound from the app only",
      allowAllOutbound: false,
    });
    endpointSg.addIngressRule(appSg, ec2.Port.tcp(443), "HTTPS from the app");
    appSg.addEgressRule(endpointSg, ec2.Port.tcp(443), "VPC endpoints");

    // AWS API access without internet: S3 (gateway, free) for the release download,
    // interface endpoints for Secrets Manager (app) and SSM (Session Manager + RunCommand).
    const s3Endpoint = vpc.addGatewayEndpoint("S3Endpoint", {
      service: ec2.GatewayVpcEndpointAwsService.S3,
      subnets: [appSubnets],
    });
    const interfaceEndpoints = [
      ["SecretsEndpoint", ec2.InterfaceVpcEndpointAwsService.SECRETS_MANAGER],
      ["SsmEndpoint", ec2.InterfaceVpcEndpointAwsService.SSM],
      ["SsmMessagesEndpoint", ec2.InterfaceVpcEndpointAwsService.SSM_MESSAGES],
      ["Ec2MessagesEndpoint", ec2.InterfaceVpcEndpointAwsService.EC2_MESSAGES],
    ].map(([name, service]) =>
      vpc.addInterfaceEndpoint(name as string, {
        service: service as ec2.InterfaceVpcEndpointAwsService,
        subnets: appSubnets,
        securityGroups: [endpointSg],
        open: false, // do not add the default "whole VPC CIDR" rule; only the app SG may connect
      }),
    );

    // ---- Release artifacts (the Go binary) ----
    const artifactBucket = new s3.Bucket(this, "ArtifactBucket", {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      bucketKeyEnabled: true,
      enforceSSL: true,
      versioned: true, // previous releases stay recoverable
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
      removalPolicy: cdk.RemovalPolicy.DESTROY, // demo stack
      autoDeleteObjects: true,
    });
    // The binary and the host setup script travel together. The setup script holds everything
    // that may change over time (environment file, systemd unit, updater). It is not part of the
    // instance's user data: a CloudFront VPC origin cannot be re-pointed at a replacement
    // instance while a distribution uses it, so the instance must never be replaced or restarted
    // by a configuration change.
    const release = new s3deploy.BucketDeployment(this, "DeployRelease", {
      sources: [
        s3deploy.Source.asset(serverDir),
        s3deploy.Source.data(
          path.posix.basename(SETUP_KEY),
          setupScript({
            region: this.region,
            keyId: publicKey.publicKeyId,
            // Literal names (not resource references) keep the key -> role -> deployment -> secret
            // chain from becoming a dependency cycle.
            signingSecret: SIGNING_SECRET_NAME,
            loginSecret: LOGIN_SECRET_NAME,
            releaseBucket: artifactBucket.bucketName,
          }),
        ),
      ],
      destinationBucket: artifactBucket,
      destinationKeyPrefix: RELEASE_PREFIX,
      memoryLimit: 256,
    });

    // ---- Rules: only CloudFront may reach the app ----
    // The managed prefix list holds CloudFront's origin-facing ranges (about 55 entries,
    // which counts against the 60-rule SG quota, so do not add further inbound rules here).
    const cloudFrontPrefixList = ec2.PrefixList.fromLookup(this, "CloudFrontOriginFacing", {
      prefixListName: "com.amazonaws.global.cloudfront.origin-facing",
    });
    const s3PrefixList = ec2.PrefixList.fromLookup(this, "S3PrefixList", {
      prefixListName: `com.amazonaws.${this.region}.s3`,
    });
    appSg.addIngressRule(
      ec2.Peer.prefixList(cloudFrontPrefixList.prefixListId),
      ec2.Port.tcp(APP_PORT),
      "CloudFront origin-facing",
    );
    appSg.addEgressRule(ec2.Peer.prefixList(s3PrefixList.prefixListId), ec2.Port.tcp(443), "S3 gateway endpoint");

    // ---- The web application host ----
    // User data is constant on purpose (see above): it only fetches and runs the setup script.
    const userData = ec2.UserData.forLinux({ shebang: "#!/bin/bash" });
    userData.addCommands(
      "set -euo pipefail",
      `aws s3 cp s3://${artifactBucket.bucketName}/${SETUP_KEY} /root/setup.sh --region ${this.region} --only-show-errors`,
      "bash /root/setup.sh",
    );

    const instance = new ec2.Instance(this, "AppInstance", {
      vpc,
      vpcSubnets: appSubnets,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T4G, ec2.InstanceSize.MICRO),
      machineImage: ec2.MachineImage.latestAmazonLinux2023({
        cpuType: ec2.AmazonLinuxCpuType.ARM_64,
        cachedInContext: true, // pinned in cdk.context.json; refresh deliberately
      }),
      securityGroup: appSg,
      requireImdsv2: true,
      ssmSessionPermissions: true, // Session Manager instead of SSH; no key pair
      blockDevices: [
        {
          deviceName: "/dev/xvda",
          volume: ec2.BlockDeviceVolume.ebs(8, { volumeType: ec2.EbsDeviceVolumeType.GP3, encrypted: true }),
        },
      ],
      userData,
    });
    // Keep the logical ID the instance had while its user data still caused replacement
    // (CDK appended a hash). A CloudFront VPC origin cannot be re-pointed to another instance while
    // a distribution uses it, so the ID must not change again.
    (instance.node.defaultChild as ec2.CfnInstance).overrideLogicalId("AppInstance13C82D50888bd7b5bcd905d6");

    // The first boot downloads the binary through the S3 endpoint.
    instance.node.addDependency(release, s3Endpoint, ...interfaceEndpoints);

    signingKeySecret.grantRead(instance);
    loginSecret.grantRead(instance);
    artifactBucket.grantRead(instance, `${RELEASE_PREFIX}/*`);
    instance.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["ssm:GetParameter"],
        resources: [
          cdk.Stack.of(this).formatArn({
            service: "ssm",
            resource: "parameter",
            resourceName: DOMAIN_PARAM.replace(/^\//, ""),
          }),
        ],
      }),
    );

    // ---- Main site: login page + cookie issuing, served by the Go app ----
    const mainDistribution = new cloudfront.Distribution(this, "MainDistribution", {
      comment: "cfcookie: main site (login)",
      priceClass: cloudfront.PriceClass.PRICE_CLASS_200,
      httpVersion: cloudfront.HttpVersion.HTTP2_AND_3,
      defaultBehavior: {
        // CloudFront reaches the app through a VPC origin; plain HTTP stays on AWS's network.
        origin: origins.VpcOrigin.withEc2Instance(instance, {
          protocolPolicy: cloudfront.OriginProtocolPolicy.HTTP_ONLY,
          httpPort: APP_PORT,
        }),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL, // POST /login, /logout
        cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
        // Forward everything, including Host / Origin / Sec-Fetch-Site: the app's cross-site
        // request protection compares Origin with Host, so Host must be the viewer's.
        originRequestPolicy: cloudfront.OriginRequestPolicy.ALL_VIEWER,
      },
    });

    // ---- Static site: private S3, readable only with the signed cookies ----
    // The two sites have different *.cloudfront.net hosts, which share no cookie scope. The app
    // cannot set cookies for the static host, so after a login it redirects the browser to
    // /_auth/set on the static host; this function stores the cookies there (see functions/).
    const authFunction = new cloudfront.Function(this, "AuthHandoffFunction", {
      code: cloudfront.FunctionCode.fromFile({ filePath: authFunctionFile }),
      runtime: cloudfront.FunctionRuntime.JS_2_0,
      comment: "Stores / removes the signed cookies handed over by the main site",
    });
    const staticOrigin = origins.S3BucketOrigin.withOriginAccessControl(bucket);
    const staticBehavior = {
      origin: staticOrigin,
      viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.HTTPS_ONLY,
      allowedMethods: cloudfront.AllowedMethods.ALLOW_GET_HEAD,
      cachePolicy: cloudfront.CachePolicy.CACHING_OPTIMIZED,
      responseHeadersPolicy: cloudfront.ResponseHeadersPolicy.SECURITY_HEADERS,
      compress: true,
    };
    const errorPage = (status: number, page: string): cloudfront.ErrorResponse => ({
      httpStatus: status,
      responseHttpStatus: status,
      responsePagePath: `/${PUBLIC_PREFIX}/${page}`,
      ttl: cdk.Duration.seconds(0),
    });
    const staticDistribution = new cloudfront.Distribution(this, "StaticDistribution", {
      comment: "cfcookie: static site (signed cookies)",
      priceClass: cloudfront.PriceClass.PRICE_CLASS_200,
      httpVersion: cloudfront.HttpVersion.HTTP2_AND_3,
      defaultRootObject: "index.html",
      defaultBehavior: {
        ...staticBehavior,
        // Viewers must present a valid signed cookie from this key group.
        trustedKeyGroups: [keyGroup],
      },
      additionalBehaviors: {
        // Open to everyone: the pages that tell a visitor to sign in or that they are signed out.
        [`/${PUBLIC_PREFIX}/*`]: staticBehavior,
        // The function answers every request itself; the origin is never contacted.
        "/_auth/*": {
          ...staticBehavior,
          cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
          functionAssociations: [{ function: authFunction, eventType: cloudfront.FunctionEventType.VIEWER_REQUEST }],
        },
      },
      errorResponses: [
        // No / invalid / expired cookie. These pages sit under the open path above.
        errorPage(403, "login-required.html"),
        errorPage(404, "not-found.html"),
      ],
    });
    // Without s3:ListBucket, S3 answers 403 for a missing key, which would be shown as "sign in".
    bucket.addToResourcePolicy(
      new iam.PolicyStatement({
        actions: ["s3:ListBucket"],
        resources: [bucket.bucketArn],
        principals: [new iam.ServicePrincipal("cloudfront.amazonaws.com")],
        conditions: {
          StringEquals: {
            "AWS:SourceArn": cdk.Stack.of(this).formatArn({
              service: "cloudfront",
              region: "",
              resource: "distribution",
              resourceName: staticDistribution.distributionId,
            }),
          },
        },
      }),
    );

    new ssm.StringParameter(this, "DomainParam", {
      parameterName: DOMAIN_PARAM,
      stringValue: staticDistribution.distributionDomainName,
      description: "Static site domain the cookie policy is issued for",
    });

    // ---- Static content ----
    // Pages that link to the main site get its domain here; the static distribution itself does not
    // depend on the main one, so the two do not reference each other.
    const mainUrl = `https://${mainDistribution.distributionDomainName}`;
    const page = (file: string, key: string) =>
      s3deploy.Source.data(key, fs.readFileSync(path.join(templatesDir, file), "utf8").replaceAll("__MAIN_URL__", mainUrl));
    new s3deploy.BucketDeployment(this, "DeployContent", {
      sources: [
        s3deploy.Source.asset(contentDir),
        page("index.html", "index.html"),
        page("login-required.html", `${PUBLIC_PREFIX}/login-required.html`),
        page("signed-out.html", `${PUBLIC_PREFIX}/signed-out.html`),
        page("not-found.html", `${PUBLIC_PREFIX}/not-found.html`),
      ],
      destinationBucket: bucket,
      distribution: staticDistribution, // drop cached copies of changed files
      distributionPaths: ["/*"],
    });

    new cdk.CfnOutput(this, "MainDomain", { value: mainDistribution.distributionDomainName });
    new cdk.CfnOutput(this, "StaticDomain", { value: staticDistribution.distributionDomainName });
    new cdk.CfnOutput(this, "PublicKeyId", { value: publicKey.publicKeyId });
    new cdk.CfnOutput(this, "ContentBucketName", { value: bucket.bucketName });
    new cdk.CfnOutput(this, "SigningKeySecretName", { value: signingKeySecret.secretName });
    new cdk.CfnOutput(this, "LoginSecretName", { value: loginSecret.secretName });
    new cdk.CfnOutput(this, "InstanceId", { value: instance.instanceId });
    new cdk.CfnOutput(this, "ArtifactBucketName", { value: artifactBucket.bucketName });
  }
}

interface SetupParams {
  region: string;
  keyId: string;
  signingSecret: string;
  loginSecret: string;
  releaseBucket: string;
}

// Host setup, safe to run repeatedly: system user, non-secret environment file, updater script,
// systemd unit, then download and start the current release. It holds no secrets: the app reads the
// key and password from Secrets Manager at runtime.
function setupScript(p: SetupParams): string {
  return `#!/bin/bash
set -euo pipefail
useradd --system --no-create-home --shell /sbin/nologin cfcookie 2>/dev/null || true
install -d -m 0755 /opt/cfcookie
install -d -m 0750 -o root -g cfcookie /etc/cfcookie

cat > /etc/cfcookie/env <<'ENVEOF'
AWS_REGION=${p.region}
LISTEN_ADDR=0.0.0.0:${APP_PORT}
KEY_ID=${p.keyId}
SIGNING_KEY_SECRET_ID=${p.signingSecret}
LOGIN_SECRET_ID=${p.loginSecret}
DOMAIN_PARAM=${DOMAIN_PARAM}
COOKIE_TTL=1h
PROTECTED_PREFIX=/
ENVEOF
chown root:cfcookie /etc/cfcookie/env
chmod 0640 /etc/cfcookie/env

# Downloads the current release, swaps it in, restarts, and rolls back if it is not healthy.
# A release that crashes on start makes "systemctl restart" fail and trips systemd's start
# limit, so the restart result is checked explicitly (not via set -e) and the failed state is
# cleared before the previous binary is started again.
cat > /usr/local/bin/cfcookie-update.new <<'UPDEOF'
#!/bin/bash
set -uo pipefail
BUCKET=${p.releaseBucket}
KEY=${RELEASE_KEY}
SETUP=${SETUP_KEY}
BIN=/opt/cfcookie/cfcookie-server
TMP=$(mktemp /opt/cfcookie/.download.XXXXXX)
trap 'rm -f "$TMP"' EXIT

healthy() {
  for _ in $(seq 1 20); do
    if curl -fsS http://127.0.0.1:${APP_PORT}/healthz >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  return 1
}

# Refresh the host configuration first (env file, unit, this script) when the setup script
# changed; "--apply-only" prevents it from calling this updater again.
aws s3 cp "s3://$BUCKET/$SETUP" /root/setup.sh --region ${p.region} --only-show-errors || { echo "setup download failed" >&2; exit 1; }
CFCOOKIE_APPLY_ONLY=1 bash /root/setup.sh || { echo "setup failed" >&2; exit 1; }

aws s3 cp "s3://$BUCKET/$KEY" "$TMP" --region ${p.region} --only-show-errors || { echo "download failed" >&2; exit 1; }
chmod 0755 "$TMP"
HAVE_PREV=0
if [ -f "$BIN" ]; then cp -p "$BIN" "$BIN.prev" && HAVE_PREV=1; fi
mv -f "$TMP" "$BIN"

systemctl reset-failed cfcookie 2>/dev/null || true
systemctl restart cfcookie || true
if healthy; then
  echo "healthy: $(sha256sum "$BIN" | cut -c1-16)"
  exit 0
fi

echo "new release is not healthy" >&2
journalctl -u cfcookie -n 20 --no-pager -o cat >&2 || true
if [ "$HAVE_PREV" = 1 ]; then
  mv -f "$BIN.prev" "$BIN"
  systemctl reset-failed cfcookie 2>/dev/null || true
  systemctl restart cfcookie || true
  if healthy; then echo "rolled back to the previous release" >&2; else echo "rollback is not healthy either" >&2; fi
else
  echo "no previous release to roll back to" >&2
fi
exit 1
UPDEOF
chmod 0755 /usr/local/bin/cfcookie-update.new
# rename(2) swaps the inode: a copy of the updater that is currently running keeps reading the old file.
mv -f /usr/local/bin/cfcookie-update.new /usr/local/bin/cfcookie-update

cat > /etc/systemd/system/cfcookie.service <<'UNITEOF'
[Unit]
Description=cfcookie signed cookie web application
After=network-online.target
Wants=network-online.target

[Service]
User=cfcookie
Group=cfcookie
EnvironmentFile=/etc/cfcookie/env
ExecStart=/opt/cfcookie/cfcookie-server
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
LockPersonality=true

[Install]
WantedBy=multi-user.target
UNITEOF

systemctl daemon-reload
systemctl enable cfcookie >/dev/null 2>&1

# First boot: the updater also downloads the binary and starts the service.
# When called from the updater itself, stop here to avoid a loop.
if [ -z "\${CFCOOKIE_APPLY_ONLY:-}" ]; then
  /usr/local/bin/cfcookie-update
fi
`;
}
