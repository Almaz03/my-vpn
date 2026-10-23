#!/usr/bin/env bash
set -euo pipefail

if [[ "$EUID" -ne 0 ]]; then
  exit 1
fi
if [[ $# -ne 1 || ! "$1" =~ ^(provision|revoke|config)$ ]]; then
  exit 2
fi

action="$1"
trap 'status=$?; echo "reality helper failed action=$action line=$LINENO status=$status" >&2; exit "$status"' ERR
xray_config=/etc/xray/config.json
client_env=/etc/my-vpn/xray-client.env
lock=/run/lock/my-vpn-xray.lock
api_server=127.0.0.1:10085
request="$(head -c 65537)"
(( ${#request} <= 65536 )) || exit 2
jq -e 'type == "object" and .version == 1' <<<"$request" >/dev/null || exit 2

get_env() {
  local name="$1" value
  value="$(sed -n "s/^${name}=//p" "$client_env")"
  [[ -n "$value" && "$value" != *$'\n'* ]] || exit 1
  printf '%s' "$value"
}
validate_device_id() { [[ "$1" =~ ^[0-9a-f]{32}$ ]]; }
device_from_credential() {
  local credential="$1"
  [[ "$credential" =~ ^vless-reality:([0-9a-f]{32})$ ]] || exit 2
  printf '%s' "${BASH_REMATCH[1]}"
}
find_uuid() {
  jq -r --arg email "device-$1" '
    .inbounds[] | select(.tag == "my-vpn-reality") |
    .settings.clients[]? | select(.email == $email) | .id
  ' "$xray_config"
}
build_links() {
  local device_id="$1" uuid="$2"
  local server port public_key short_id sni flow fragment uri encoded deep_link
  server="$(get_env XRAY_SERVER)"
  port="$(get_env XRAY_PORT)"
  public_key="$(get_env XRAY_PUBLIC_KEY)"
  short_id="$(get_env XRAY_SHORT_ID)"
  sni="$(get_env XRAY_SNI)"
  flow="$(get_env XRAY_FLOW)"
  [[ "$server" =~ ^[A-Za-z0-9.-]+$ && "$port" =~ ^[0-9]{1,5}$ ]]
  [[ "$public_key" =~ ^[A-Za-z0-9_-]{43}$ && "$short_id" =~ ^[0-9a-f]{16}$ ]]
  [[ "$sni" =~ ^[A-Za-z0-9.-]+$ && "$flow" == xtls-rprx-vision ]]
  fragment="Family-VPN-${device_id:0:8}"
  uri="vless://${uuid}@${server}:${port}?encryption=none&flow=${flow}&security=reality&sni=${sni}&fp=chrome&pbk=${public_key}&sid=${short_id}&type=raw#${fragment}"
  encoded="$(printf '%s' "$uri" | base64 -w 0)"
  deep_link="incy://import/${encoded}"
  printf '%s\n%s\n' "$uri" "$deep_link"
}
validate_candidate() {
  local candidate="$1"
  jq -e '([.inbounds[] | select(.tag == "my-vpn-reality")] | length) == 1' "$candidate" >/dev/null
  chown xray:xray "$candidate"
  chmod 0640 "$candidate"
  local validation_output
  if ! validation_output="$(xray run -test -config "$candidate" 2>&1)"; then
    echo "Xray rejected a generated candidate configuration:" >&2
    sed -E \
      -e 's/[0-9a-f]{8}-[0-9a-f-]{27,36}/[REDACTED_UUID]/g' \
      -e 's/[A-Za-z0-9_-]{32,}/[REDACTED_VALUE]/g' \
      <<<"$validation_output" >&2
    exit 1
  fi
}
runtime_add() {
  local uuid="$1" email="$2" runtime_config output
  runtime_config="$(mktemp --suffix=.json /etc/xray/.runtime-user.XXXXXX)"
  chmod 0600 "$runtime_config"
  jq -n --arg id "$uuid" --arg email "$email" '{
    inbounds: [{
      tag: "my-vpn-reality", listen: "127.0.0.1", port: 1, protocol: "vless",
      settings: {decryption: "none", clients: [{id: $id, flow: "xtls-rprx-vision", email: $email}]}
    }]
  }' > "$runtime_config"
  output="$(xray api adu --server="$api_server" --timeout=5 "$runtime_config")"
  rm -f "$runtime_config"
  grep -Fxq 'Added 1 user(s) in total.' <<<"$output"
}
runtime_remove() {
  local email="$1" output
  output="$(xray api rmu --server="$api_server" --timeout=5 -tag my-vpn-reality "$email")"
  grep -Fxq 'Removed 1 user(s) in total.' <<<"$output"
}

test -f "$xray_config" -a -f "$client_env"
install -d -m 0755 -o root -g root /run/lock
exec 9>"$lock"
flock -w 30 9

case "$action" in
  provision)
    device_id="$(jq -r '.device_id // empty' <<<"$request")"
    validate_device_id "$device_id" || exit 2
    jq -e '
      (.relative_name | type == "string" and length > 0 and length <= 100) and
      (.device_name | type == "string" and length > 0 and length <= 100) and
      (.platform | IN("android", "ios", "ipad", "windows", "macos", "linux"))
    ' <<<"$request" >/dev/null || exit 2
    uuid="$(find_uuid "$device_id")"
    if [[ -z "$uuid" ]]; then
      uuid="$(xray uuid | tr -d '\r\n')"
      [[ "$uuid" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]]
      before="$(mktemp /etc/xray/.config.before.XXXXXX)"
      candidate="$(mktemp --suffix=.json /etc/xray/.config.candidate.XXXXXX)"
      trap 'rm -f "$before" "$candidate"' EXIT
      cp --preserve=mode,ownership "$xray_config" "$before"
      jq --arg id "$uuid" --arg email "device-$device_id" '
        (.inbounds[] | select(.tag == "my-vpn-reality") | .settings.clients) +=
          [{"id": $id, "flow": "xtls-rprx-vision", "email": $email}]
      ' "$xray_config" > "$candidate"
      validate_candidate "$candidate"
      runtime_add "$uuid" "device-$device_id"
      if ! mv -f "$candidate" "$xray_config"; then
        runtime_remove "device-$device_id" >/dev/null 2>&1 || true
        install -m 0640 -o xray -g xray "$before" "$xray_config"
        exit 1
      fi
    fi
    mapfile -t links < <(build_links "$device_id" "$uuid")
    jq -cn --arg link "${links[1]}" --arg path "/api/v1/devices/$device_id/config" \
      '{version:1,state:"active",incy_deep_link:$link,config_path:$path}'
    ;;
  config)
    credential="$(jq -r '.credential_ref // empty' <<<"$request")"
    device_id="$(device_from_credential "$credential")"
    uuid="$(find_uuid "$device_id")"
    [[ -n "$uuid" ]] || exit 1
    mapfile -t links < <(build_links "$device_id" "$uuid")
    jq -cn --arg uri "${links[0]}" --arg link "${links[1]}" \
      '{version:1,vless_uri:$uri,incy_deep_link:$link}'
    ;;
  revoke)
    credential="$(jq -r '.credential_ref // empty' <<<"$request")"
    device_id="$(device_from_credential "$credential")"
    uuid="$(find_uuid "$device_id")"
    if [[ -z "$uuid" ]]; then
      jq -cn '{version:1,state:"absent"}'
      exit 0
    fi
    before="$(mktemp /etc/xray/.config.before.XXXXXX)"
    candidate="$(mktemp --suffix=.json /etc/xray/.config.candidate.XXXXXX)"
    trap 'rm -f "$before" "$candidate"' EXIT
    cp --preserve=mode,ownership "$xray_config" "$before"
    jq --arg email "device-$device_id" '
      (.inbounds[] | select(.tag == "my-vpn-reality") | .settings.clients) |=
        map(select(.email != $email))
    ' "$xray_config" > "$candidate"
    validate_candidate "$candidate"
    runtime_remove "device-$device_id"
    if ! mv -f "$candidate" "$xray_config"; then
      runtime_add "$uuid" "device-$device_id" >/dev/null 2>&1 || true
      install -m 0640 -o xray -g xray "$before" "$xray_config"
      exit 1
    fi
    jq -cn '{version:1,state:"revoked"}'
    ;;
esac
