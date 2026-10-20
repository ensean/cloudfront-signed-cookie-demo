#!/usr/bin/env bash
# Upload the locally generated private key and login password into Secrets Manager.
# The values are sent from files (file://) so they never appear in the process list,
# shell history or this script's output. The secrets are never read back.
set -euo pipefail
cd "$(dirname "$0")/.."

PROFILE="${AWS_PROFILE:-test}"
REGION="${AWS_REGION:-ap-northeast-1}"

for f in .secrets/private_key.pem .secrets/login_password; do
  [[ -s "$f" ]] || { echo "missing $f - run scripts/gen-keys.sh first" >&2; exit 1; }
done

put() {
  local secret_id="$1" file="$2"
  aws secretsmanager put-secret-value \
    --profile "$PROFILE" --region "$REGION" \
    --secret-id "$secret_id" \
    --secret-string "file://$file" \
    --query VersionId --output text > /dev/null
  echo "updated secret $secret_id"
}

put cfcookie/signing-key    .secrets/private_key.pem
put cfcookie/login-password .secrets/login_password
