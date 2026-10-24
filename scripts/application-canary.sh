#!/usr/bin/env bash
set -euo pipefail
trap 'status=$?; echo "application canary failed at line $LINENO status=$status" >&2; exit "$status"' ERR

if [[ "$EUID" -ne 0 ]]; then
  echo "application-canary.sh must run as root" >&2
  exit 1
fi

exec 9>/run/lock/my-vpn-application-canary.lock
flock -w 30 9
work="$(mktemp -d /var/lib/my-vpn/.application-canary.XXXXXX)"
chmod 0700 "$work"
invitation_id=""
device_id=""

admin_request() {
  local method="$1" path="$2" body_file="${3:-}"
  local token
  token="$(sed -n 's/^ADMIN_API_TOKEN=//p' /etc/my-vpn/my-vpn.env | tail -n 1)"
  [[ ${#token} -ge 24 && "$token" != *$'\n'* ]]
  if [[ -n "$body_file" ]]; then
    printf 'header = "Authorization: Bearer %s"\n' "$token" |
      curl --fail --silent --show-error --config - --request "$method" \
        --header 'Content-Type: application/json' --data-binary "@$body_file" \
        "http://127.0.0.1:8080$path"
  else
    printf 'header = "Authorization: Bearer %s"\n' "$token" |
      curl --fail --silent --show-error --config - --request "$method" \
        "http://127.0.0.1:8080$path"
  fi
}

cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [[ -n "$device_id" ]]; then
    admin_request POST "/api/v1/admin/devices/$device_id/revoke" >/dev/null 2>&1 || true
  elif [[ -n "$invitation_id" ]]; then
    admin_request POST "/api/v1/admin/invitations/$invitation_id/revoke" >/dev/null 2>&1 || true
  fi
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT INT TERM

nonce="$(openssl rand -hex 6)"
jq -cn --arg name "canary-$nonce" \
  '{relative_name:$name,device_name:"deployment-canary",ttl_seconds:600}' > "$work/invitation-request.json"
admin_request POST /api/v1/admin/invitations "$work/invitation-request.json" > "$work/invitation.json"
echo "application canary: invitation created"
invitation_id="$(jq -r '.invitation.id // empty' "$work/invitation.json")"
code="$(jq -r '.code // empty' "$work/invitation.json")"
[[ "$invitation_id" =~ ^[0-9a-f]{32}$ && -n "$code" ]]

jq -cn --arg code "$code" \
  '{code:$code,platform:"linux",device_name:"deployment-canary"}' > "$work/activation-request.json"
curl --fail --silent --show-error --request POST \
  --header 'Content-Type: application/json' --data-binary "@$work/activation-request.json" \
  http://127.0.0.1:8080/api/v1/activate > "$work/activation.json"
echo "application canary: invitation activated"
device_id="$(jq -r '.device_id // empty' "$work/activation.json")"
subscription="$(jq -r '.config_download_url // empty' "$work/activation.json")"
[[ "$device_id" =~ ^[0-9a-f]{32}$ && "$subscription" == https://vpn.akalmaz.tech/s/*'?download=1' ]]
subscription_path="/${subscription#https://vpn.akalmaz.tech/}"

printf 'url = "http://127.0.0.1:8080%s"\n' "$subscription_path" |
  curl --fail --silent --show-error --config - > "$work/subscription.txt"
if jq -e '
  (."profile-name" == "Family VPN · LT + FI") and
  (.mode == "rule") and (.ipv6 == false) and (.tun.enable == true) and
  (.dns.enable == true) and (.dns.ipv6 == false) and (.dns."enhanced-mode" == "fake-ip") and
  ([.proxies[]? | select(
    .type == "vless" and .tls == true and .network == "tcp" and .udp == true and
    .flow == "xtls-rprx-vision" and .port == 443 and
    (.server | test("^[0-9]{1,3}(\\.[0-9]{1,3}){3}$")) and
    (."reality-opts"."public-key" | test("^[A-Za-z0-9_-]{43}$")) and
    (."reality-opts"."short-id" | test("^[0-9a-f]{16}$"))
  )] | length == 2) and
  ([."proxy-groups"[]? | select(
    .name == "🚀 Автовыбор" and .type == "url-test" and .lazy == false and
    .proxies == ["🇱🇹 Литва 🚀", "🇫🇮 Финляндия 🚀"]
  )] | length == 1) and
  (.rules | index("DOMAIN-SUFFIX,ru,DIRECT") != null) and
  (.rules | index("DOMAIN-SUFFIX,xn--p1ai,DIRECT") != null) and
  (.rules[-1] == "MATCH,🚀 Автовыбор")
' "$work/subscription.txt" >/dev/null 2>&1; then
  echo "application canary: full Clash Mi dual-edge subscription validated"
else
  echo 'application canary: invalid dual-edge profile' >&2
  exit 1
fi

admin_request POST "/api/v1/admin/devices/$device_id/revoke" > "$work/revoke.json"
device_id=""
http_code="$(printf 'url = "http://127.0.0.1:8080%s"\n' "$subscription_path" |
  curl --silent --output /dev/null --write-out '%{http_code}' --config -)"
[[ "$http_code" == 404 ]]

invitation_id=""
echo "application activation and revoke canary passed"
