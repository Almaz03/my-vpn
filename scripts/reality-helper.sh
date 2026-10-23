#!/usr/bin/env bash
set -euo pipefail

# Root-owned dual-edge coordinator.
edges_file=/etc/my-vpn/edges.json
state_dir=/var/lib/my-vpn/reality/devices
local_helper=/usr/local/libexec/my-vpn/edge-user-helper
ssh_key=/etc/my-vpn/edge-deploy-key
known_hosts=/etc/my-vpn/edge-known-hosts

fail() { printf '%s\n' "$1" >&2; exit 1; }
valid_device_id() { [[ "$1" =~ ^[0-9a-f]{32}$ ]]; }
valid_uuid() { [[ "$1" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]]; }

validate_config() {
  [[ -r "$edges_file" ]] || fail "edge configuration unavailable"
  jq -e '
    type == "array" and length == 2 and
    ([.[].id] | sort == ["fi", "lt"]) and
    all(.[];
      (.id | test("^(lt|fi)$")) and
      (.mode == "local" or .mode == "ssh") and
      (if .mode == "ssh" then
        (.host | test("^([0-9]{1,3}\\.){3}[0-9]{1,3}$")) and
        (.port | type == "number" and . >= 1 and . <= 65535) and
        (.user | test("^[a-z_][a-z0-9_-]{0,31}$"))
      else true end))
  ' "$edges_file" >/dev/null || fail "invalid edge configuration"
  [[ -x "$local_helper" ]] || fail "local edge helper unavailable"
  if jq -e 'any(.[]; .mode == "ssh")' "$edges_file" >/dev/null; then
    [[ -r "$ssh_key" && -r "$known_hosts" ]] || fail "remote edge SSH material unavailable"
  fi
}

edge_call() {
  local edge="$1" action="$2" device_id="${3:-}" uuid="${4:-}"
  local mode host port user
  mode="$(jq -r '.mode' <<<"$edge")"
  if [[ "$mode" == local ]]; then
    "$local_helper" "$action" ${device_id:+"$device_id"} ${uuid:+"$uuid"}
    return
  fi
  host="$(jq -r '.host' <<<"$edge")"
  port="$(jq -r '.port' <<<"$edge")"
  user="$(jq -r '.user' <<<"$edge")"
  ssh -i "$ssh_key" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile="$known_hosts" -o ConnectTimeout=10 -p "$port" "$user@$host" \
    sudo -n -- /usr/local/libexec/my-vpn/edge-user-helper "$action" \
    ${device_id:+"$device_id"} ${uuid:+"$uuid"}
}

ordered_edges() {
  jq -c 'sort_by(if .id == "lt" then 0 else 1 end)[]' "$edges_file"
}

state_path() { printf '%s/%s.json' "$state_dir" "$1"; }

provision_device() {
  local device_id="$1" path uuid edge edge_id response completed_id rollback_edge tmp
  path="$(state_path "$device_id")"
  if [[ -f "$path" ]]; then
    uuid="$(jq -r '.uuid' "$path")"
    valid_uuid "$uuid" || fail "invalid stored credential"
  else
    uuid="$(cat /proc/sys/kernel/random/uuid)"
    valid_uuid "$uuid" || fail "uuid generation failed"
  fi

  local -a completed=()
  while IFS= read -r edge; do
    edge_id="$(jq -r '.id' <<<"$edge")"
    if ! response="$(edge_call "$edge" add "$device_id" "$uuid")" ||
       ! jq -e --arg uuid "$uuid" '.uuid == $uuid and (.state == "active" or .state == "exists")' <<<"$response" >/dev/null; then
      for completed_id in "${completed[@]}"; do
        rollback_edge="$(jq -c --arg id "$completed_id" '.[] | select(.id == $id)' "$edges_file")"
        edge_call "$rollback_edge" remove "$device_id" >/dev/null 2>&1 || true
      done
      fail "dual-edge provision failed"
    fi
    completed+=("$edge_id")
  done < <(ordered_edges)

  install -d -m 0700 -o root -g root "$state_dir"
  tmp="$(mktemp "$state_dir/.device.XXXXXX")"
  jq -n --arg device_id "$device_id" --arg uuid "$uuid" \
    '{device_id:$device_id,uuid:$uuid,version:1}' >"$tmp"
  chmod 0600 "$tmp"
  mv -f "$tmp" "$path"
  jq -n --arg path "/api/v1/devices/$device_id/config" \
    '{version:1,state:"active",config_path:$path}'
}

revoke_device() {
  local device_id="$1" edge failed=false
  while IFS= read -r edge; do
    if ! edge_call "$edge" remove "$device_id" >/dev/null; then failed=true; fi
  done < <(ordered_edges)
  [[ "$failed" == false ]] || fail "dual-edge revoke incomplete"
  rm -f -- "$(state_path "$device_id")"
  jq -n '{version:1,state:"revoked"}'
}

client_config() {
  local device_id="$1" path uuid edge metadata uri edge_id label uris='[]'
  path="$(state_path "$device_id")"
  [[ -r "$path" ]] || fail "device credential unavailable"
  uuid="$(jq -r '.uuid' "$path")"
  valid_uuid "$uuid" || fail "invalid stored credential"
  while IFS= read -r edge; do
    metadata="$(edge_call "$edge" metadata)"
    jq -e '
      (.server | test("^([0-9]{1,3}\\.){3}[0-9]{1,3}$")) and
      (.port | type == "number" and . >= 1 and . <= 65535) and
      (.public_key | test("^[A-Za-z0-9_-]{43}$")) and
      (.short_id | test("^[0-9a-f]{16}$")) and
      (.sni | test("^[a-z0-9.-]+$")) and .flow == "xtls-rprx-vision"
    ' <<<"$metadata" >/dev/null || fail "invalid edge metadata"
    edge_id="$(jq -r '.id' <<<"$edge")"
    if [[ "$edge_id" == lt ]]; then label='🇱🇹 Литва 🚀'; else label='🇫🇮 Финляндия 🚀'; fi
    uri="$(jq -nr --arg uuid "$uuid" --argjson m "$metadata" --arg label "$label" '
      "vless://\($uuid)@\($m.server):\($m.port)?encryption=none&security=reality&type=tcp&flow=\($m.flow)&sni=\($m.sni)&fp=chrome&pbk=\($m.public_key)&sid=\($m.short_id)#\($label|@uri)"
    ')"
    uris="$(jq -c --arg uri "$uri" '. + [$uri]' <<<"$uris")"
  done < <(ordered_edges)
  jq -n --argjson uris "$uris" '{version:1,vless_uris:$uris}'
}

main() {
  [[ $# == 1 ]] || fail "usage: reality-helper ACTION"
  validate_config
  local action="$1" request credential device_id
  request="$(head -c 65537)"
  (( ${#request} <= 65536 )) || fail "request too large"
  jq -e 'type == "object" and .version == 1' <<<"$request" >/dev/null || fail "invalid request"
  case "$action" in
    provision)
      device_id="$(jq -r '.device_id // ""' <<<"$request")"
      valid_device_id "$device_id" || fail "invalid device id"
      provision_device "$device_id"
      ;;
    revoke|config)
      credential="$(jq -r '.credential_ref // ""' <<<"$request")"
      [[ "$credential" == vless-reality:* ]] || fail "invalid credential"
      device_id="${credential#vless-reality:}"
      valid_device_id "$device_id" || fail "invalid device id"
      if [[ "$action" == revoke ]]; then revoke_device "$device_id"; else client_config "$device_id"; fi
      ;;
    *) fail "unsupported action" ;;
  esac
}

main "$@"
