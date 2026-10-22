#!/usr/bin/env bash
set -euo pipefail
trap 'status=$?; echo "application canary failed at line $LINENO status=$status" >&2; exit "$status"' ERR

[[ "$EUID" -eq 0 ]] || exit 1
exec 9>/run/lock/my-vpn-application-canary.lock
flock -w 30 9
work="$(mktemp -d /var/lib/my-vpn/.application-canary.XXXXXX)"
chmod 0700 "$work"
invitation_id=""
device_id=""

admin_request() {
  local method="$1" path="$2" body_file="${3:-}" token
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
invitation_id="$(jq -r '.invitation.id // empty' "$work/invitation.json")"
code="$(jq -r '.code // empty' "$work/invitation.json")"
[[ "$invitation_id" =~ ^[0-9a-f]{32}$ && -n "$code" ]]

jq -cn --arg code "$code" \
  '{code:$code,platform:"linux",device_name:"deployment-canary"}' > "$work/activation-request.json"
curl --fail --silent --show-error --request POST \
  --header 'Content-Type: application/json' --data-binary "@$work/activation-request.json" \
  http://127.0.0.1:8080/api/v1/activate > "$work/activation.json"
device_id="$(jq -r '.device_id // empty' "$work/activation.json")"
subscription="$(jq -r '.config_download_url // empty' "$work/activation.json")"
[[ "$device_id" =~ ^[0-9a-f]{32}$ && "$subscription" == https://vpn.akalmaz.tech/s/*'?download=1' ]]
subscription_path="/${subscription#https://vpn.akalmaz.tech/}"

printf 'url = "http://127.0.0.1:8080%s"\n' "$subscription_path" |
  curl --fail --silent --show-error --config - > "$work/profile.conf"
grep -Fxq '[Interface]' "$work/profile.conf"
grep -Eq '^PrivateKey = [A-Za-z0-9+/]{43}=$' "$work/profile.conf"
grep -Eq '^Address = ([0-9]{1,3}\.){3}[0-9]{1,3}/32$' "$work/profile.conf"
grep -Fxq '[Peer]' "$work/profile.conf"
grep -Eq '^PublicKey = [A-Za-z0-9+/]{43}=$' "$work/profile.conf"
grep -Eq '^PresharedKey = [A-Za-z0-9+/]{43}=$' "$work/profile.conf"
grep -Fxq 'AllowedIPs = 0.0.0.0/0, ::/0' "$work/profile.conf"
grep -Fxq 'Endpoint = vpn.akalmaz.tech:35473' "$work/profile.conf"
for field in Jc Jmin Jmax S1 S2 H1 H2 H3 H4; do
  grep -Eq "^${field} = -?[0-9]+$" "$work/profile.conf"
done

admin_request POST "/api/v1/admin/devices/$device_id/revoke" > "$work/revoke.json"
device_id=""
http_code="$(printf 'url = "http://127.0.0.1:8080%s"\n' "$subscription_path" |
  curl --silent --output /dev/null --write-out '%{http_code}' --config -)"
[[ "$http_code" == 404 ]]
invitation_id=""
echo "AmneziaWG activation, profile and revoke canary passed"
