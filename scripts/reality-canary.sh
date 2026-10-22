#!/usr/bin/env bash
set -euo pipefail
trap 'status=$?; echo "reality canary failed at line $LINENO status=$status" >&2; exit "$status"' ERR

if [[ "$EUID" -ne 0 ]]; then
  echo "reality-canary.sh must run as root" >&2
  exit 1
fi

exec 9>/run/lock/my-vpn-reality-canary.lock
flock -w 30 9
work="$(mktemp -d /var/lib/xray/.canary.XXXXXX)"
device_id="$(openssl rand -hex 16)"
client_pid=""
provisioned=false
cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [[ -n "$client_pid" ]]; then
    kill "$client_pid" >/dev/null 2>&1 || true
    wait "$client_pid" >/dev/null 2>&1 || true
  fi
  if [[ "$provisioned" == true ]]; then
    jq -cn --arg credential "vless-reality:$device_id" \
      '{version:1,credential_ref:$credential}' |
      /usr/local/libexec/my-vpn/reality-helper revoke >/dev/null 2>&1 || true
  fi
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT INT TERM

jq -cn --arg id "$device_id" \
  '{version:1,device_id:$id,relative_name:"canary",device_name:"canary",platform:"linux"}' |
  /usr/local/libexec/my-vpn/reality-helper provision > "$work/provision.json"
provisioned=true
echo "reality canary: temporary client provisioned"
uuid="$(jq -r --arg email "device-$device_id" '
  .inbounds[] | select(.tag == "my-vpn-reality") |
  .settings.clients[] | select(.email == $email) | .id
' /etc/xray/config.json)"
[[ "$uuid" =~ ^[0-9a-f-]{36}$ ]]
rm -f "$work/provision.json"

get_env() { sed -n "s/^$1=//p" /etc/my-vpn/xray-client.env; }
public_key="$(get_env XRAY_PUBLIC_KEY)"
short_id="$(get_env XRAY_SHORT_ID)"
sni="$(get_env XRAY_SNI)"
port=18090
while ss -H -ltn "sport = :$port" | grep -q .; do
  ((port++))
  ((port < 18150))
done

jq -n --arg id "$uuid" --arg public_key "$public_key" --arg short_id "$short_id" \
  --arg sni "$sni" --argjson port "$port" '{
    log: {loglevel:"warning"},
    inbounds:[{
      listen:"127.0.0.1", port:$port, protocol:"socks",
      settings:{auth:"noauth",udp:false}
    }],
    outbounds:[{
      protocol:"vless",
      settings:{vnext:[{address:"127.0.0.1",port:8443,users:[{
        id:$id,encryption:"none",flow:"xtls-rprx-vision"
      }]}]},
      streamSettings:{
        network:"raw",security:"reality",
        realitySettings:{
          show:false,fingerprint:"chrome",serverName:$sni,
          publicKey:$public_key,shortId:$short_id,spiderX:"/"
        }
      }
    }]
  }' > "$work/client.json"
chown root:xray "$work"
chmod 0750 "$work"
chown xray:xray "$work/client.json"
chmod 0600 "$work/client.json"
runuser -u xray -- /usr/local/bin/xray run -config "$work/client.json" >/dev/null 2>&1 &
client_pid=$!

ready=false
for _ in {1..20}; do
  if ss -H -ltn "sport = :$port" | grep -q .; then
    ready=true
    break
  fi
  sleep 0.25
done
[[ "$ready" == true ]]
curl --fail --silent --show-error --max-time 15 \
  --proxy "socks5h://127.0.0.1:$port" \
  --output "$work/trace.txt" \
  https://www.cloudflare.com/cdn-cgi/trace
grep -Eq '^ip=[0-9a-fA-F:.]+$' "$work/trace.txt"
echo "VLESS Reality egress canary passed"
