#!/usr/bin/env bash
# Build the web server, publish it with CDK and restart it on the instance.
#
#   scripts/deploy-app.sh            build + cdk deploy + restart
#   scripts/deploy-app.sh --no-cdk   skip build and cdk deploy; only re-run the update on the instance
#
# CDK uploads build/server/cfcookie-server and releases/setup.sh (host configuration) to the artifact
# bucket. The instance then fetches and runs setup.sh through SSM Run Command: it refreshes the
# environment file, systemd unit and /usr/local/bin/cfcookie-update, downloads the binary, restarts
# the service and rolls back if /healthz does not come up. The instance itself is never replaced
# for a configuration or code change (a CloudFront VPC origin cannot follow a replacement).
set -euo pipefail
cd "$(dirname "$0")/.."

export AWS_PROFILE="${AWS_PROFILE:-test}"
REGION="${AWS_REGION:-ap-northeast-1}"

if [[ "${1:-}" != "--no-cdk" ]]; then
  go vet ./... && go test -race -count=1 ./... | grep -v "no test files"
  ./scripts/build-server.sh
  (cd infra && npx cdk deploy CfCookieStack --require-approval never --outputs-file outputs.json)
fi

out() { python3 -c "import json;print(json.load(open('infra/outputs.json'))['CfCookieStack']['$1'])"; }
INSTANCE_ID=$(out InstanceId)
BUCKET=$(out ArtifactBucketName)

echo "restarting the app on $INSTANCE_ID ..."
CMD_ID=$(aws ssm send-command --region "$REGION" \
  --instance-ids "$INSTANCE_ID" \
  --document-name AWS-RunShellScript \
  --parameters "commands=[\"aws s3 cp s3://$BUCKET/releases/setup.sh /root/setup.sh --region $REGION --only-show-errors && bash /root/setup.sh\"]" \
  --query Command.CommandId --output text)

# Wait for the command to finish (up to ~2 minutes).
for _ in $(seq 1 40); do
  status=$(aws ssm get-command-invocation --region "$REGION" --command-id "$CMD_ID" --instance-id "$INSTANCE_ID" \
    --query Status --output text 2>/dev/null || echo Pending)
  case "$status" in
    Success) break ;;
    Failed|Cancelled|TimedOut) break ;;
  esac
  sleep 3
done

aws ssm get-command-invocation --region "$REGION" --command-id "$CMD_ID" --instance-id "$INSTANCE_ID" \
  --query '{status:Status,stdout:StandardOutputContent,stderr:StandardErrorContent}' --output yaml
[[ "$status" == "Success" ]]
