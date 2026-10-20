#!/usr/bin/env node
import * as cdk from "aws-cdk-lib";
import { CookieStack } from "../lib/cookie-stack";

const app = new cdk.App();

new CookieStack(app, "CfCookieStack", {
  env: { account: "123456789012", region: "ap-northeast-1" },
  description: "CloudFront signed cookies for private S3 content, issued by a Go web app on EC2 behind a VPC origin",
  tags: { Project: "cfcookie" },
});
