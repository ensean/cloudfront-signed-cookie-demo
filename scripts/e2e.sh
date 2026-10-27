#!/usr/bin/env bash
# End-to-end check of the deployed stack (main site + static site). Reads the login password from
# .secrets/login_password (never printed) and the stack outputs from infra/outputs.json.
#   scripts/e2e.sh
set -uo pipefail
cd "$(dirname "$0")/.."

PROFILE="${AWS_PROFILE:-test}"
REGION="${AWS_REGION:-ap-northeast-1}"
out() { python3 -c "import json;print(json.load(open('infra/outputs.json'))['CfCookieStack']['$1'])"; }
M=$(out MainDomain); S=$(out StaticDomain); BUCKET=$(out ContentBucketName); INSTANCE=$(out InstanceId)
PW=$(cat .secrets/login_password)
J=$(mktemp); H=$(mktemp); TMP=$(mktemp); trap 'rm -f "$J" "$H" "$TMP"' EXIT
pass=0; fail=0
aws_() { aws --profile "$PROFILE" --region "$REGION" "$@"; }

code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
# post <form body> [curl args...]  -> prints the HTTP status; response headers go to $H
post() {
  local body="$1"; shift
  curl -s -D "$H" -o /dev/null -w '%{http_code}' -X POST \
    -H 'content-type: application/x-www-form-urlencoded' --data "$body" "$@"
}
cookie_header() { # "name=value; ..." for the cookies in a curl jar
  awk -F'\t' '{sub(/^#HttpOnly_/,"",$1)} NF>=7 && $1 !~ /^#/ {printf "%s%s=%s", sep, $6, $7; sep="; "}' "$1"
}
jar_count() { awk -F'\t' 'NF>=7 && $1 !~ /^# /' "$1" | wc -l | tr -d ' '; }
check() { # check <name> <want> <got>
  if [[ "$2" == "$3" ]]; then pass=$((pass+1)); printf '  PASS  %-66s %s\n' "$1" "$3"
  else fail=$((fail+1)); printf '  FAIL  %-66s want [%s] got [%s]\n' "$1" "$2" "$3"; sed 's/^/        /' "$H" | head -12; fi
}
header() { grep -i "^$1:" "$H" | head -1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//'; }

echo "main site:   https://$M"
echo "static site: https://$S   instance: $INSTANCE"

echo "== main site"
check "login page is served by the app" 200 "$(code https://$M/)"
check "login page contains no script" 0 "$(curl -s https://$M/ | grep -ci '<script')"
check "login page links to the static site" 1 "$(curl -s https://$M/ | grep -c "href=\"https://$S/\"")"
check "CSP lets the login form reach the static site" 1 "$(curl -s -D - -o /dev/null https://$M/ | grep -ci "content-security-policy:.*form-action 'self' https://$S;")"
check "wrong password is rejected" 401 "$(post 'password=definitely-the-wrong-password' https://$M/login)"
check "wrong password sends no redirect to the static site" "" "$(header location)"
check "wrong password page shows the error" 1 "$(curl -s -X POST --data 'password=definitely-the-wrong-password' https://$M/login | grep -c 'Wrong password')"
check "main site no longer serves protected files" 404 "$(code https://$M/protected/index.html)"

echo "== static site without cookies"
check "index is denied" 403 "$(code https://$S/index.html)"
check "root is denied" 403 "$(code https://$S/)"
check "denial shows the sign-in page" 1 "$(curl -s https://$S/ | grep -c '<h1>Sign in required</h1>')"
check "denial page links to the main site" 1 "$(curl -s https://$S/ | grep -c "href=\"https://$M/\"")"
check "sign-in page itself is open" 200 "$(code https://$S/_public/login-required.html)"
check "S3 object is not readable directly" 403 "$(code https://$BUCKET.s3.$REGION.amazonaws.com/index.html)"

echo "== login and cookie handoff"
check "login with the right password redirects" 303 "$(post "password=$PW&next=/report.txt" https://$M/login)"
LOC=$(header location)
check "redirect leads to the static site's handoff endpoint" "https://$S/_auth/set" "${LOC%%\?*}"
check "main site sets no cookie itself" 0 "$(grep -ci '^set-cookie:' "$H")"
check "handoff stores the cookies and redirects" 303 "$(curl -s -D "$H" -o /dev/null -c "$J" -w '%{http_code}' "$LOC")"
check "handoff returns to the requested file" "/report.txt" "$(header location)"
check "four Set-Cookie headers" 4 "$(grep -ci '^set-cookie:' "$H")"
check "every cookie has Secure, HttpOnly, SameSite=Lax, Path=/ and no Domain" 4 \
  "$(grep -i '^set-cookie:' "$H" | grep -i 'secure' | grep -i 'httponly' | grep -i 'samesite=lax' | grep -i 'path=/;' | grep -vic 'domain=')"
check "four cookies are stored for the static host" 4 "$(jar_count "$J")"
bad=$(awk -F'\t' -v s="$S" '{h=($1 ~ /^#HttpOnly_/)} NF>=7 && $1 !~ /^# / {if(!h||$1!="#HttpOnly_" s||$2!="FALSE"||$4!="TRUE"||$3!="/")print $6}' "$J")
check "jar: host-only, HttpOnly, Secure, Path=/ on the static host" "" "$bad"

echo "== static site with cookies (view and download)"
check "index" 200 "$(curl -s -b "$J" -o /dev/null -w '%{http_code}' https://$S/index.html)"
check "root serves the index" 1 "$(curl -s -b "$J" https://$S/ | grep -c '<h1>Static site</h1>')"
check "index links back to the main site" yes "$([[ $(curl -s -b "$J" https://$S/ | grep -c "href=\"https://$M/\"") -ge 1 ]] && echo yes || echo no)"
check "report.txt" 200 "$(curl -s -b "$J" -o /dev/null -w '%{http_code}' https://$S/report.txt)"
check "report.txt body is the S3 object" "Quarterly report (sample)" "$(curl -s -b "$J" https://$S/report.txt | head -1)"
curl -s -b "$J" -o "$TMP" https://$S/data.csv
check "data.csv download is byte-identical to the source" 0 "$(cmp -s "$TMP" content/static/data.csv; echo $?)"
check "svg is served with its content type (viewable inline)" "image/svg+xml" "$(curl -s -b "$J" -o /dev/null -w '%{content_type}' https://$S/images/logo.svg)"
check "security headers on the static site" 1 "$(curl -s -b "$J" -D - -o /dev/null https://$S/index.html | grep -ic '^strict-transport-security')"
check "missing file gives 404, not the sign-in page" 404 "$(curl -s -b "$J" -o /dev/null -w '%{http_code}' https://$S/nope.txt)"
check "the open area is reachable with cookies too" 200 "$(curl -s -b "$J" -o /dev/null -w '%{http_code}' https://$S/_public/signed-out.html)"

CH=$(cookie_header "$J")
SIG=$(printf '%s' "$CH" | tr ';' '\n' | sed 's/^ *//' | grep '^CloudFront-Signature=' | cut -d= -f2-)
first=${SIG:0:1}; flip=$([[ $first == A ]] && echo B || echo A)
TAMPERED=${CH/CloudFront-Signature=$SIG/CloudFront-Signature=$flip${SIG:1}}
check "tampered signature is rejected" 403 "$(curl -s -H "Cookie: $TAMPERED" -o /dev/null -w '%{http_code}' https://$S/index.html)"
NOHASH=$(printf '%s' "$CH" | tr ';' '\n' | sed 's/^ *//' | grep -v '^CloudFront-Hash-Algorithm=' | paste -sd';' - | sed 's/;/; /g')
check "missing Hash-Algorithm cookie is rejected" 403 "$(curl -s -H "Cookie: $NOHASH" -o /dev/null -w '%{http_code}' https://$S/index.html)"

echo "== handoff endpoint hardening"
NOW=$(date +%s)
check "malformed value is rejected" 400 "$(code "https://$S/_auth/set?p=a%3Bb&s=x&k=K1&e=$((NOW+3600))")"
check "missing parameter is rejected" 400 "$(code "https://$S/_auth/set?p=a&s=x&k=K1")"
check "expired value is rejected" 400 "$(code "https://$S/_auth/set?p=a&s=x&k=K1&e=1")"
check "POST is refused (the behavior allows GET and HEAD only)" 403 "$(code -X POST "$LOC")"
check "unknown path under /_auth/ is 404" 404 "$(code https://$S/_auth/other)"
EVIL=${LOC/n=\/report.txt/n=\/\/evil.example\/}
curl -s -D "$H" -o /dev/null "$EVIL"
check "off-site next is replaced by the default page" "/index.html" "$(header location)"
FORGED="${LOC%&s=*}&s=AAAAAAAAAAAAAAAA" # same policy, made-up signature (s is the last parameter)
JF=$(mktemp); curl -s -o /dev/null -c "$JF" "$FORGED"
check "forged handoff differs from the real one" yes "$([[ $FORGED != "$LOC" ]] && echo yes || echo no)"
check "cookies from a forged handoff are refused by CloudFront" 403 "$(curl -s -b "$JF" -o /dev/null -w '%{http_code}' https://$S/index.html)"
rm -f "$JF"

echo "== main site hardening"
check "cross-site POST (foreign Origin) is rejected" 403 "$(post "password=$PW" -H 'Origin: https://evil.example' https://$M/login)"
check "cross-site POST (Sec-Fetch-Site) is rejected" 403 "$(post "password=$PW" -H 'Sec-Fetch-Site: cross-site' https://$M/login)"
check "same-origin browser POST is accepted" 303 "$(post "password=$PW" -H "Origin: https://$M" -H 'Sec-Fetch-Site: same-origin' https://$M/login)"
check "default landing page is the static index" "/index.html" "$(header location | sed 's/.*[?&]n=\([^&]*\).*/\1/')"
post "password=$PW&next=https://evil.example/" https://$M/login >/dev/null
check "open redirect target is replaced by the default" "/index.html" "$(header location | sed 's/.*[?&]n=\([^&]*\).*/\1/')"

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
check "logout on the main site redirects to the static site's clear endpoint" 303 "$(post '' https://$M/logout)"
check "logout target" "https://$S/_auth/clear" "$(header location)"
check "clear removes the cookies and redirects" 303 "$(curl -s -D "$H" -o /dev/null -b "$J" -c "$J" -w '%{http_code}' https://$S/_auth/clear)"
check "clear lands on the signed-out page" "/_public/signed-out.html" "$(header location)"
check "no cookies left in the jar" 0 "$(jar_count "$J")"
check "signed-out page is open" 200 "$(code https://$S/_public/signed-out.html)"
check "static content denied after logout" 403 "$(curl -s -b "$J" -o /dev/null -w '%{http_code}' https://$S/index.html)"

echo; echo "passed: $pass  failed: $fail"
[[ $fail -eq 0 ]]
