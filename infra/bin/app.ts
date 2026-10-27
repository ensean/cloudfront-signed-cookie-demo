#!/usr/bin/env node
import * as cdk from "aws-cdk-lib";
import { CookieStack } from "../lib/cookie-stack";

const app = new cdk.App();

new CookieStack(app, "CfCookieStack", {
  // The account comes from the credentials the CDK CLI runs with (AWS_PROFILE).
  env: { account: process.env.CDK_DEFAULT_ACCOUNT, region: "ap-northeast-1" },
  description: "Main site (Go app on EC2 behind a VPC origin) issues CloudFront signed cookies for a separate static site on private S3",
  tags: { Project: "cfcookie" },
});
