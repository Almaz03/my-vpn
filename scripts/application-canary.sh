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
client_pid=""
client_work=""

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
  if [[ -n "$client_pid" ]]; then
    kill "$client_pid" >/dev/null 2>&1 || true
    wait "$client_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "$device_id" ]]; then
    admin_request POST "/api/v1/admin/devices/$device_id/revoke" >/dev/null 2>&1 || true
  elif [[ -n "$invitation_id" ]]; then
    admin_request POST "/api/v1/admin/invitations/$invitation_id/revoke" >/dev/null 2>&1 || true
  fi
  if [[ -n "$client_work" ]]; then
    rm -rf "$client_work"
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
  (.remarks == "Family VPN") and
  (.dns.queryStrategy == "UseIPv4") and
	(.dns.tag == "dns_out") and
  ([.inbounds[]? | select(.protocol == "socks" and .port == 10808)] | length == 1) and
  ([.outbounds[]? | select(.tag == "family-proxy" and .protocol == "vless")] | length == 1) and
	([.outbounds[]? | select(.tag == "family-proxy") | .settings.vnext[0].address |
	  test("^[0-9]{1,3}(\\.[0-9]{1,3}){3}$"))] | length == 1) and
  ([.outbounds[]? | select(.tag == "direct" and .protocol == "freedom")] | length == 1) and
  ([.outbounds[]? | select(.tag == "block" and .protocol == "blackhole")] | length == 1) and
	([.routing.rules[]? | select(.outboundTag == "direct" and (.inboundTag == ["dns_out"]) and (.ip == ["77.88.8.8"]))] | length == 1) and
	([.routing.rules[]? | select(.outboundTag == "family-proxy" and (.inboundTag == ["dns_out"]))] | length == 1) and
	([.routing.rules[]? | select(.outboundTag == "dns-out" and .port == 53)] | length == 1) and
  ([.routing.rules[]? | select(.outboundTag == "family-proxy" and .network == "tcp,udp")] | length == 1)
' "$work/subscription.txt" >/dev/null 2>&1; then
  echo "application canary: full Xray subscription validated"

  client_work="$(mktemp -d /var/lib/xray/.application-canary.XXXXXX)"
  socks_port=18150
  while ss -H -ltn "sport = :$socks_port" | grep -q .; do
    ((socks_port++))
    ((socks_port < 18200))
  done
  http_port=$((socks_port + 50))
  while ss -H -ltn "sport = :$http_port" | grep -q .; do
    ((http_port++))
    ((http_port < 18300))
  done
  jq --argjson socks_port "$socks_port" --argjson http_port "$http_port" '
    (.inbounds[] | select(.protocol == "socks") | .port) = $socks_port |
    (.inbounds[] | select(.protocol == "http") | .port) = $http_port |
    (.outbounds[] | select(.tag == "family-proxy") | .settings.vnext[0].address) = "127.0.0.1"
  ' "$work/subscription.txt" > "$client_work/config.json"
  chown -R xray:xray "$client_work"
  chmod 0750 "$client_work"
  chmod 0600 "$client_work/config.json"
  runuser -u xray -- /usr/local/bin/xray run -config "$client_work/config.json" \
    >"$client_work/xray.log" 2>&1 &
  client_pid=$!
  ready=false
  for _ in {1..20}; do
    if ss -H -ltn "sport = :$socks_port" | grep -q .; then
      ready=true
      break
    fi
    sleep 0.25
  done
  [[ "$ready" == true ]]
  curl --fail --silent --show-error --max-time 15 \
    --proxy "socks5h://127.0.0.1:$socks_port" \
    --output "$client_work/trace.txt" \
    https://www.cloudflare.com/cdn-cgi/trace
  grep -Eq '^ip=[0-9a-fA-F:.]+$' "$client_work/trace.txt"
  kill "$client_pid" >/dev/null 2>&1 || true
  wait "$client_pid" >/dev/null 2>&1 || true
  client_pid=""
  rm -rf "$client_work"
  client_work=""
  echo "application canary: full Xray foreign egress passed"
else
  grep -Eq '^vless://[^[:space:]]+$' "$work/subscription.txt"
  grep -Fxq 'incy://autorouting/onadd/https://vpn.akalmaz.tech/routing/family-ru-direct.json' "$work/subscription.txt"
  echo "application canary: legacy VLESS subscription validated"
fi

admin_request POST "/api/v1/admin/devices/$device_id/revoke" > "$work/revoke.json"
device_id=""
http_code="$(printf 'url = "http://127.0.0.1:8080%s"\n' "$subscription_path" |
  curl --silent --output /dev/null --write-out '%{http_code}' --config -)"
[[ "$http_code" == 404 ]]

invitation_id=""
echo "application activation and revoke canary passed"
