#!/usr/bin/env bash
set -euo pipefail

[[ "$EUID" -eq 0 ]] || exit 1
[[ $# -ge 1 ]] || exit 2

action="$1"
config=/etc/xray/config.json
api_server=127.0.0.1:10085
lock=/run/lock/my-vpn-edge-users.lock

valid_device() { [[ "$1" =~ ^[0-9a-f]{32}$ ]]; }
valid_uuid() { [[ "$1" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]]; }
email_for() { printf 'device-%s' "$1"; }

runtime_add() {
  local uuid="$1" email="$2" candidate output
  candidate="$(mktemp --suffix=.json /etc/xray/.edge-user.XXXXXX)"
  jq -n --arg id "$uuid" --arg email "$email" '{inbounds:[{
    tag:"my-vpn-reality",listen:"127.0.0.1",port:1,protocol:"vless",
    settings:{decryption:"none",clients:[{id:$id,flow:"xtls-rprx-vision",email:$email}]}
  }]}' > "$candidate"
  if ! output="$(xray api adu --server="$api_server" --timeout=5 "$candidate")"; then
    rm -f "$candidate"
    return 1
  fi
  rm -f "$candidate"
  grep -Fxq 'Added 1 user(s) in total.' <<<"$output"
}

runtime_remove() {
  local email="$1" output
  output="$(xray api rmu --server="$api_server" --timeout=5 -tag my-vpn-reality "$email")"
  grep -Fxq 'Removed 1 user(s) in total.' <<<"$output"
}

test -f "$config"
install -d -m 0755 /run/lock
exec 9>"$lock"
flock -w 30 9

case "$action" in
  add)
    [[ $# -eq 3 ]] || exit 2
    device_id="$2"
    uuid="${3,,}"
    valid_device "$device_id" && valid_uuid "$uuid" || exit 2
    email="$(email_for "$device_id")"
    existing="$(jq -r --arg email "$email" '.inbounds[] | select(.tag=="my-vpn-reality") | .settings.clients[]? | select(.email==$email) | .id' "$config")"
    if [[ -n "$existing" ]]; then
      [[ "$existing" == "$uuid" ]] || exit 1
      exit 0
    fi
    candidate="$(mktemp --suffix=.json /etc/xray/.edge-config.XXXXXX)"
    trap 'rm -f "$candidate"' EXIT
    jq --arg id "$uuid" --arg email "$email" '(.inbounds[] | select(.tag=="my-vpn-reality") | .settings.clients) += [{id:$id,flow:"xtls-rprx-vision",email:$email}]' "$config" > "$candidate"
    chown xray:xray "$candidate"
    chmod 0640 "$candidate"
    xray run -test -config "$candidate" >/dev/null
    runtime_add "$uuid" "$email"
    mv -f "$candidate" "$config"
    ;;
  remove)
    [[ $# -eq 2 ]] || exit 2
    device_id="$2"
    valid_device "$device_id" || exit 2
    email="$(email_for "$device_id")"
    existing="$(jq -r --arg email "$email" '.inbounds[] | select(.tag=="my-vpn-reality") | .settings.clients[]? | select(.email==$email) | .id' "$config")"
    [[ -n "$existing" ]] || exit 0
    candidate="$(mktemp --suffix=.json /etc/xray/.edge-config.XXXXXX)"
    trap 'rm -f "$candidate"' EXIT
    jq --arg email "$email" '(.inbounds[] | select(.tag=="my-vpn-reality") | .settings.clients) |= map(select(.email!=$email))' "$config" > "$candidate"
    chown xray:xray "$candidate"
    chmod 0640 "$candidate"
    xray run -test -config "$candidate" >/dev/null
    runtime_remove "$email"
    mv -f "$candidate" "$config"
    ;;
  metadata)
    [[ $# -eq 1 ]] || exit 2
    jq -cn --arg server "$(sed -n 's/^XRAY_SERVER=//p' /etc/my-vpn/edge.env)" \
      --arg port "$(sed -n 's/^XRAY_PORT=//p' /etc/my-vpn/edge.env)" \
      --arg public_key "$(sed -n 's/^XRAY_PUBLIC_KEY=//p' /etc/my-vpn/edge.env)" \
      --arg short_id "$(sed -n 's/^XRAY_SHORT_ID=//p' /etc/my-vpn/edge.env)" \
      --arg sni "$(sed -n 's/^XRAY_SNI=//p' /etc/my-vpn/edge.env)" \
      '{server:$server,port:($port|tonumber),public_key:$public_key,short_id:$short_id,sni:$sni,flow:"xtls-rprx-vision"}'
    ;;
  *) exit 2 ;;
esac
