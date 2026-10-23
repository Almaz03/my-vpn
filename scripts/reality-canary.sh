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
rm -f "$work/provision.json"

config_request="$(jq -cn --arg credential "vless-reality:$device_id" '{version:1,credential_ref:$credential}')"
config_response="$(printf '%s' "$config_request" | /usr/local/libexec/my-vpn/reality-helper config)"
[[ "$(jq -r '.vless_uris | length' <<<"$config_response")" == 2 ]]
test_edge() {
  local index="$1" uri authority uuid server_and_query server_authority server client_server server_port
  local query public_key short_id sni port ready
  uri="$(jq -er --argjson index "$index" '.vless_uris[$index] | select(startswith("vless://"))' <<<"$config_response")"
  authority="${uri#vless://}"
  uuid="${authority%%@*}"
  server_and_query="${authority#*@}"
  server_authority="${server_and_query%%\?*}"
  server="${server_authority%:*}"
  server_port="${server_authority##*:}"
  query="${server_and_query#*\?}"
  query="${query%%#*}"
  public_key="$(tr '&' '\n' <<<"$query" | sed -n 's/^pbk=//p' | head -n 1)"
  short_id="$(tr '&' '\n' <<<"$query" | sed -n 's/^sid=//p' | head -n 1)"
  sni="$(tr '&' '\n' <<<"$query" | sed -n 's/^sni=//p' | head -n 1)"
  [[ "$uuid" =~ ^[0-9a-f-]{36}$ && "$server" =~ ^[A-Za-z0-9.-]+$ ]]
  [[ "$public_key" =~ ^[A-Za-z0-9_-]{43}$ && "$short_id" =~ ^[0-9a-f]{16}$ ]]
  [[ "$server_port" =~ ^[0-9]{1,5}$ ]] && ((server_port >= 1 && server_port <= 65535))
  client_server="$server"
  # The control plane is itself the LT edge. Some providers do not implement
  # public-IP hairpin NAT, so exercise the same listener through loopback while
  # still asserting that Cloudflare observes the configured LT egress IP.
  if ((index == 0)); then client_server=127.0.0.1; fi
  port=$((18090 + index))
  while ss -H -ltn "sport = :$port" | grep -q .; do
    ((port++))
    ((port < 18150))
  done

  jq -n --arg id "$uuid" --arg server "$client_server" --arg public_key "$public_key" --arg short_id "$short_id" \
    --arg sni "$sni" --argjson port "$port" --argjson server_port "$server_port" '{
    log: {loglevel:"warning"},
    inbounds:[{
      listen:"127.0.0.1", port:$port, protocol:"socks",
      settings:{auth:"noauth",udp:false}
    }],
    outbounds:[{
      protocol:"vless",
      settings:{vnext:[{address:$server,port:$server_port,users:[{
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
  }' > "$work/client-$index.json"
  chown xray:xray "$work/client-$index.json"
  chmod 0600 "$work/client-$index.json"
  if ! runuser -u xray -- /usr/local/bin/xray run -test -config "$work/client-$index.json" \
    >"$work/xray-$index.log" 2>&1; then
    echo "reality canary: edge $index client configuration rejected" >&2
    sed -n '1,80p' "$work/xray-$index.log" >&2
    return 1
  fi
  runuser -u xray -- /usr/local/bin/xray run -config "$work/client-$index.json" \
    >"$work/xray-$index.log" 2>&1 &
  client_pid=$!
  ready=false
  for _ in {1..20}; do
    if ss -H -ltn "sport = :$port" | grep -q .; then ready=true; break; fi
    sleep 0.25
  done
  if [[ "$ready" != true ]]; then
    echo "reality canary: edge $index local client did not become ready" >&2
    sed -n '1,80p' "$work/xray-$index.log" >&2
    return 1
  fi
  echo "reality canary: edge $index local client ready"
  if ! curl --fail --silent --show-error --max-time 15 \
    --proxy "socks5h://127.0.0.1:$port" \
    --output "$work/trace-$index.txt" \
    https://www.cloudflare.com/cdn-cgi/trace; then
    echo "reality canary: edge $index tunnel request failed" >&2
    sed -n '1,80p' "$work/xray-$index.log" >&2
    return 1
  fi
  if ! grep -Fxq "ip=$server" "$work/trace-$index.txt"; then
    echo "reality canary: edge $index returned an unexpected egress address" >&2
    sed -n '/^ip=/p' "$work/trace-$index.txt" >&2
    return 1
  fi
  kill "$client_pid" >/dev/null 2>&1 || true
  wait "$client_pid" >/dev/null 2>&1 || true
  client_pid=""
  echo "VLESS Reality edge $index egress canary passed"
}

chown root:xray "$work"
chmod 0750 "$work"
test_edge 0
test_edge 1
echo "dual-edge VLESS Reality egress canary passed"
