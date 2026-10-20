#!/usr/bin/env bash
# Generate the CloudFront signing key pair and the login password locally.
#
#   .secrets/private_key.pem   RSA-2048 private key (PKCS#8). NEVER commit. Uploaded to
#                              Secrets Manager by put-secrets.sh, then delete it.
#   infra/public_key.pem       public half, read by CDK to create the CloudFront public key.
#   .secrets/login_password    random login password for the demo page.
#
# Nothing secret is printed.
set -euo pipefail
cd "$(dirname "$0")/.."

umask 077
mkdir -p .secrets

if [[ -e .secrets/private_key.pem ]]; then
  echo "refusing to overwrite .secrets/private_key.pem (delete it first to rotate)" >&2
  exit 1
fi
# The private key is deleted after it has been uploaded, so its absence does not mean there is no
# key pair. infra/public_key.pem is the registered half: overwriting it would make the next
# "cdk deploy" replace the CloudFront public key, and every issued cookie would stop working
# until the matching private key is uploaded.
if [[ -e infra/public_key.pem && "${ROTATE_KEYS:-}" != "yes" ]]; then
  echo "refusing to overwrite infra/public_key.pem: a key pair already exists." >&2
  echo "To rotate on purpose, run:  ROTATE_KEYS=yes ./scripts/gen-keys.sh   (see docs/cloudfront-s3-setup.md, section 7)" >&2
  exit 1
fi

openssl genrsa -out .secrets/private_key.pem 2048 2>/dev/null
openssl rsa -in .secrets/private_key.pem -pubout -out infra/public_key.pem 2>/dev/null
# 32 hex characters (128 bits of entropy), no trailing newline.
printf '%s' "$(openssl rand -hex 16)" > .secrets/login_password

chmod 600 .secrets/private_key.pem .secrets/login_password
echo "generated .secrets/private_key.pem, .secrets/login_password and infra/public_key.pem"
