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

edge_controller_env=/etc/my-vpn/edge-controller.env
edge_private_key=/etc/my-vpn/edge-deploy-key
edge_known_hosts=/etc/my-vpn/edge-known-hosts

controller_env() {
  local name="$1" value
  value="$(sed -n "s/^${name}=//p" "$edge_controller_env")"
  [[ -n "$value" && "$value" != *$'\n'* ]] || exit 1
  printf '%s' "$value"
}
remote_edge() {
  local remote_action="$1" device_id="$2" host port user
  host="$(controller_env EDGE_HOST)"
  port="$(controller_env EDGE_PORT)"
  user="$(controller_env EDGE_USER)"
  [[ "$host" =~ ^([A-Za-z0-9.-]+|[0-9]{1,3}(\.[0-9]{1,3}){3})$ ]]
  [[ "$port" =~ ^[0-9]{1,5}$ ]]
  [[ "$user" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]
  [[ "$remote_action" =~ ^(provision|config|remove)$ && "$device_id" =~ ^[0-9a-f]{32}$ ]]
  ssh -F none -i "$edge_private_key" -o BatchMode=yes -o IdentitiesOnly=yes \
    -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$edge_known_hosts" \
    -o ConnectTimeout=8 -p "$port" "$user@$host" \
    sudo -- /usr/local/libexec/my-vpn/edge-user-helper "$remote_action" "$device_id"
}
remote_links() {
  local response="$1" device_id="$2" uuid server port public_key short_id sni flow fragment uri encoded deep_link
  jq -e --arg device_id "$device_id" '
    .version == 1 and .device_id == $device_id and
    (.uuid | test("^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")) and
    (.server | test("^[A-Za-z0-9.-]+$")) and (.port >= 1 and .port <= 65535) and
    (.public_key | test("^[A-Za-z0-9_-]{43}$")) and
    (.short_id | test("^[0-9a-f]{16}$")) and
    (.sni | test("^[A-Za-z0-9.-]+$")) and .flow == "xtls-rprx-vision"
  ' <<<"$response" >/dev/null
  uuid="$(jq -r .uuid <<<"$response")"
  server="$(jq -r .server <<<"$response")"
  port="$(jq -r .port <<<"$response")"
  public_key="$(jq -r .public_key <<<"$response")"
  short_id="$(jq -r .short_id <<<"$response")"
  sni="$(jq -r .sni <<<"$response")"
  flow="$(jq -r .flow <<<"$response")"
  fragment="🇫🇮 Финляндия 🚀"
  uri="vless://${uuid}@${server}:${port}?encryption=none&flow=${flow}&security=reality&sni=${sni}&fp=chrome&pbk=${public_key}&sid=${short_id}&type=raw#${fragment}"
  encoded="$(printf '%s' "$uri" | base64 -w 0)"
  deep_link="incy://import/${encoded}"
  printf '%s\n%s\n' "$uri" "$deep_link"
}

if [[ -f "$edge_controller_env" || -f "$edge_private_key" || -f "$edge_known_hosts" ]]; then
  test -f "$edge_controller_env" -a -f "$edge_private_key" -a -f "$edge_known_hosts"
  case "$action" in
    provision)
      device_id="$(jq -r '.device_id // empty' <<<"$request")"
      [[ "$device_id" =~ ^[0-9a-f]{32}$ ]] || exit 2
      jq -e '
        (.relative_name | type == "string" and length > 0 and length <= 100) and
        (.device_name | type == "string" and length > 0 and length <= 100) and
        (.platform | IN("android", "ios", "ipad", "windows", "macos", "linux"))
      ' <<<"$request" >/dev/null || exit 2
      response="$(remote_edge provision "$device_id")"
      mapfile -t links < <(remote_links "$response" "$device_id")
      jq -cn --arg link "${links[1]}" --arg path "/api/v1/devices/$device_id/config" \
        '{version:1,state:"active",incy_deep_link:$link,config_path:$path}'
      ;;
    config)
      credential="$(jq -r '.credential_ref // empty' <<<"$request")"
      [[ "$credential" =~ ^vless-reality:([0-9a-f]{32})$ ]] || exit 2
      device_id="${BASH_REMATCH[1]}"
      # Provision-on-read migrates pre-edge active devices without changing
      # their portal subscription URL or database credential reference.
      response="$(remote_edge provision "$device_id")"
      mapfile -t links < <(remote_links "$response" "$device_id")
      jq -cn --arg uri "${links[0]}" --arg link "${links[1]}" \
        '{version:1,vless_uri:$uri,incy_deep_link:$link}'
      ;;
    revoke)
      credential="$(jq -r '.credential_ref // empty' <<<"$request")"
      [[ "$credential" =~ ^vless-reality:([0-9a-f]{32})$ ]] || exit 2
      remote_edge remove "${BASH_REMATCH[1]}" >/dev/null
      jq -cn '{version:1,state:"revoked"}'
      ;;
  esac
  exit 0
fi

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
  fragment="🇫🇮 Финляндия 🚀"
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
