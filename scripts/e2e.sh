#!/usr/bin/env bash
# End-to-end check of the deployed stack. Reads the login password from
# .secrets/login_password (never printed) and the stack outputs from infra/outputs.json.
#   scripts/e2e.sh
set -uo pipefail
cd "$(dirname "$0")/.."

PROFILE="${AWS_PROFILE:-test}"
REGION="${AWS_REGION:-ap-northeast-1}"
out() { python3 -c "import json;print(json.load(open('infra/outputs.json'))['CfCookieStack']['$1'])"; }
D=$(out DistributionDomain); BUCKET=$(out ContentBucketName); INSTANCE=$(out InstanceId)
PW=$(cat .secrets/login_password)
J=$(mktemp); H=$(mktemp); trap 'rm -f "$J" "$H"' EXIT
pass=0; fail=0
aws_() { aws --profile "$PROFILE" --region "$REGION" "$@"; }

# post <form body> [curl args...]  -> prints the HTTP status; response headers go to $H
post() {
  local body="$1"; shift
  curl -s -D "$H" -o /dev/null -w '%{http_code}' -X POST \
    -H 'content-type: application/x-www-form-urlencoded' --data "$body" "$@"
}
cookie_header() { # "name=value; ..." for the cookies in a curl jar
  awk -F'\t' '{sub(/^#HttpOnly_/,"",$1)} NF>=7 && $1 !~ /^#/ {printf "%s%s=%s", sep, $6, $7; sep="; "}' "$1"
}
check() { # check <name> <want> <got>
  if [[ "$2" == "$3" ]]; then pass=$((pass+1)); printf '  PASS  %-62s %s\n' "$1" "$3"
  else fail=$((fail+1)); printf '  FAIL  %-62s want [%s] got [%s]\n' "$1" "$2" "$3"; sed 's/^/        /' "$H" | head -12; fi
}
header() { grep -i "^$1:" "$H" | head -1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//'; }

echo "distribution: https://$D   instance: $INSTANCE"
echo "== login flow"
check "login page is served by the app" 200 "$(curl -s -o /dev/null -w '%{http_code}' https://$D/)"
check "login page contains no script" 0 "$(curl -s https://$D/ | grep -ci '<script')"
check "protected content without cookie is denied" 403 "$(curl -s -o /dev/null -w '%{http_code}' https://$D/protected/index.html)"
check "wrong password is rejected" 401 "$(post 'password=definitely-the-wrong-password' https://$D/login)"
check "wrong password page shows the error" 1 "$(curl -s -X POST --data 'password=definitely-the-wrong-password' https://$D/login | grep -c 'Wrong password')"
check "login with the right password redirects" 303 "$(post "password=$PW&next=/protected/report.txt" -c "$J" https://$D/login)"
check "redirect goes to the requested protected file" "/protected/report.txt" "$(header location)"

echo "== cookies"
check "four signed cookies were set" 4 "$(awk -F'\t' 'NF>=7 && $1 !~ /^# /' "$J" | wc -l | tr -d ' ')"
bad=$(awk -F'\t' '{h=($1 ~ /^#HttpOnly_/)} NF>=7 && $1 !~ /^# / {if(!h||$4!="TRUE"||$3!="/protected/")print $6}' "$J")
check "all cookies are HttpOnly, Secure and scoped to /protected/" "" "$bad"
check "Set-Cookie carries SameSite=Lax on every cookie" 4 "$(grep -ic 'samesite=lax' "$H")"

echo "== protected content"
check "protected index with cookies" 200 "$(curl -s -b "$J" -o /dev/null -w '%{http_code}' https://$D/protected/index.html)"
check "protected report.txt with cookies" 200 "$(curl -s -b "$J" -o /dev/null -w '%{http_code}' https://$D/protected/report.txt)"
check "served body is the S3 object" "Quarterly report (sample)" "$(curl -s -b "$J" https://$D/protected/report.txt | head -1)"
check "security headers added on protected path" 1 "$(curl -s -b "$J" -D - -o /dev/null https://$D/protected/index.html | grep -ic '^strict-transport-security')"

CH=$(cookie_header "$J")
SIG=$(printf '%s' "$CH" | tr ';' '\n' | sed 's/^ *//' | grep '^CloudFront-Signature=' | cut -d= -f2-)
first=${SIG:0:1}; flip=$([[ $first == A ]] && echo B || echo A)
TAMPERED=${CH/CloudFront-Signature=$SIG/CloudFront-Signature=$flip${SIG:1}}
check "tampered signature is rejected" 403 "$(curl -s -H "Cookie: $TAMPERED" -o /dev/null -w '%{http_code}' https://$D/protected/index.html)"
NOHASH=$(printf '%s' "$CH" | tr ';' '\n' | sed 's/^ *//' | grep -v '^CloudFront-Hash-Algorithm=' | paste -sd';' - | sed 's/;/; /g')
check "missing Hash-Algorithm cookie is rejected" 403 "$(curl -s -H "Cookie: $NOHASH" -o /dev/null -w '%{http_code}' https://$D/protected/index.html)"

echo "== web application hardening"
check "cross-site POST (foreign Origin) is rejected" 403 "$(post "password=$PW" -H 'Origin: https://evil.example' https://$D/login)"
check "cross-site POST (Sec-Fetch-Site) is rejected" 403 "$(post "password=$PW" -H 'Sec-Fetch-Site: cross-site' https://$D/login)"
check "same-origin browser POST is accepted" 303 "$(post "password=$PW" -H "Origin: https://$D" -H 'Sec-Fetch-Site: same-origin' https://$D/login)"
post "password=$PW&next=https://evil.example/" https://$D/login >/dev/null
check "open redirect target is replaced by the default" "/protected/index.html" "$(header location)"
check "S3 object is not readable directly" 403 "$(curl -s -o /dev/null -w '%{http_code}' https://$BUCKET.s3.$REGION.amazonaws.com/protected/index.html)"

echo "== EC2 origin is private"
read -r PUBIP SGID SUBNET < <(aws_ ec2 describe-instances --instance-ids "$INSTANCE" \
  --query 'Reservations[0].Instances[0].[PublicIpAddress||`none`,SecurityGroups[0].GroupId,SubnetId]' --output text)
check "instance has no public IP" none "$PUBIP"
check "app security group has no 0.0.0.0/0 or ::/0 ingress" 0 "$(aws_ ec2 describe-security-groups --group-ids "$SGID" \
  --query 'length(SecurityGroups[0].IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`] || Ipv6Ranges[?CidrIpv6==`::/0`]])' --output text)"
check "app security group only allows TCP 8080 inbound" "8080 8080" "$(aws_ ec2 describe-security-groups --group-ids "$SGID" \
  --query 'SecurityGroups[0].IpPermissions[].[FromPort,ToPort]' --output text | sort -u | tr '\t' ' ')"
check "subnet has no route to an internet gateway" 0 "$(aws_ ec2 describe-route-tables --filters "Name=association.subnet-id,Values=$SUBNET" \
  --query 'length(RouteTables[].Routes[?starts_with(GatewayId||``,`igw-`) || starts_with(NatGatewayId||``,`nat-`)][])' --output text)"
check "instance enforces IMDSv2" required "$(aws_ ec2 describe-instances --instance-ids "$INSTANCE" \
  --query 'Reservations[0].Instances[0].MetadataOptions.HttpTokens' --output text)"
check "instance has no SSH key pair" None "$(aws_ ec2 describe-instances --instance-ids "$INSTANCE" \
  --query 'Reservations[0].Instances[0].KeyName' --output text)"

echo "== logout"
check "logout redirects to /" 303 "$(post '' -b "$J" -c "$J" https://$D/logout)"
check "no cookies left in the jar after logout" 0 "$(awk -F'\t' 'NF>=7 && $1 !~ /^# /' "$J" | wc -l | tr -d ' ')"
check "protected content denied after logout" 403 "$(curl -s -b "$J" -o /dev/null -w '%{http_code}' https://$D/protected/index.html)"

echo; echo "passed: $pass  failed: $fail"
[[ $fail -eq 0 ]]
