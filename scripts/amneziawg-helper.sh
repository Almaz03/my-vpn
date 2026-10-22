#!/usr/bin/env bash
set -euo pipefail

if [[ "$EUID" -ne 0 ]]; then
  exit 1
fi
if [[ $# -ne 1 || ! "$1" =~ ^(provision|revoke|config)$ ]]; then
  exit 2
fi

action="$1"
temporary_paths=()
cleanup_temporary() {
  local path
  for path in "${temporary_paths[@]}"; do
    case "$path" in /var/lib/my-vpn/.awg-server.*|/var/lib/my-vpn/.awg-client.*) rm -rf -- "$path" ;; esac
  done
}
fail() {
  status=$?
  echo "AmneziaWG helper failed action=$action line=$LINENO status=$status" >&2
  cleanup_temporary
  exit "$status"
}
trap fail ERR
trap cleanup_temporary EXIT
state_dir=/var/lib/my-vpn/amneziawg
settings=/etc/my-vpn/amneziawg.env
lock=/run/lock/my-vpn-amneziawg.lock
request="$(head -c 65537)"
(( ${#request} <= 65536 )) || exit 2
jq -e 'type == "object" and .version == 1' <<<"$request" >/dev/null || exit 2

get_setting() {
  local name="$1" value
  value="$(sed -n "s/^${name}=//p" "$settings")"
  [[ -n "$value" && "$value" != *$'\n'* ]] || exit 1
  printf '%s' "$value"
}

container="$(get_setting AMNEZIAWG_CONTAINER)"
interface="$(get_setting AMNEZIAWG_INTERFACE)"
server_config="$(get_setting AMNEZIAWG_SERVER_CONFIG)"
endpoint="$(get_setting AMNEZIAWG_ENDPOINT)"
[[ "$container" =~ ^[A-Za-z0-9_.-]+$ && "$interface" =~ ^[A-Za-z0-9_.-]+$ ]]
[[ "$server_config" == /opt/amnezia/awg/awg0.conf ]]
[[ "$endpoint" =~ ^[A-Za-z0-9.-]+:[0-9]{1,5}$ ]]

device_from_credential() {
  local credential="$1"
  [[ "$credential" =~ ^amneziawg:([0-9a-f]{32})$ ]] || exit 2
  printf '%s' "${BASH_REMATCH[1]}"
}

require_data_plane() {
  docker inspect "$container" >/dev/null 2>&1
  [[ "$(docker inspect -f '{{.State.Running}}' "$container")" == true ]]
  docker exec "$container" awg show "$interface" >/dev/null
  docker exec "$container" test -f "$server_config"
}

profile_public_key() { sed -n 's/^PublicKey = //p' "$1" | head -n 1; }
profile_psk() { sed -n 's/^PresharedKey = //p' "$1" | head -n 1; }
profile_address() { sed -n 's/^Address = //p' "$1" | head -n 1; }

validate_key() { [[ "$1" =~ ^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$ ]]; }

apply_runtime_peer() {
  local profile="$1" public_key psk address psk_path
  public_key="$(profile_public_key "$profile")"
  psk="$(profile_psk "$profile")"
  address="$(profile_address "$profile")"
  validate_key "$public_key"
  validate_key "$psk"
  [[ "$address" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/32$ ]]
  psk_path="/tmp/my-vpn-psk-${device_id}"
  printf '%s\n' "$psk" | docker exec -i "$container" sh -c \
    'umask 077; cat > "$1"' _ "$psk_path"
  if ! docker exec "$container" awg set "$interface" peer "$public_key" \
    preshared-key "$psk_path" allowed-ips "$address"; then
    docker exec "$container" rm -f "$psk_path" >/dev/null 2>&1 || true
    return 1
  fi
  docker exec "$container" rm -f "$psk_path"
}

rewrite_server_peer() {
  local mode="$1" profile="${2:-}" public_key="" psk="" address=""
  local work original candidate marker
  work="$(mktemp -d /var/lib/my-vpn/.awg-server.XXXXXX)"
  temporary_paths+=("$work")
  chmod 0700 "$work"
  original="$work/original.conf"
  candidate="$work/candidate.conf"
  docker cp "$container:$server_config" "$original" >/dev/null
  chmod 0600 "$original"
  marker="# my-vpn-device:${device_id}"
  awk -v marker="$marker" '
    $0 == marker {skip=4; next}
    skip > 0 {skip--; next}
    {print}
  ' "$original" > "$candidate"
  if [[ "$mode" == add ]]; then
    public_key="$(profile_public_key "$profile")"
    psk="$(profile_psk "$profile")"
    address="$(profile_address "$profile")"
    validate_key "$public_key"
    validate_key "$psk"
    [[ "$address" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/32$ ]]
    {
      printf '\n%s\n' "$marker"
      printf '[Peer]\n'
      printf 'PublicKey = %s\n' "$public_key"
      printf 'PresharedKey = %s\n' "$psk"
      printf 'AllowedIPs = %s\n' "$address"
    } >> "$candidate"
  fi
  chmod 0600 "$candidate"
  docker cp "$candidate" "$container:${server_config}.my-vpn-new" >/dev/null
  docker exec "$container" sh -c \
    'chmod 600 "$1" && mv -f "$1" "$2"' _ "${server_config}.my-vpn-new" "$server_config"
  rm -rf "$work"
}

allocate_address() {
  local cidr address prefix server_host used candidate host
  cidr="$(docker exec "$container" ip -4 -o addr show dev "$interface" | awk 'NR == 1 {print $4}')"
  [[ "$cidr" =~ ^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\.([0-9]{1,3})/24$ ]]
  prefix="${BASH_REMATCH[1]}"
  server_host="${BASH_REMATCH[2]}"
  used="$(docker exec "$container" awg show "$interface" allowed-ips)"
  for host in $(seq 2 254); do
    [[ "$host" == "$server_host" ]] && continue
    candidate="${prefix}.${host}/32"
    if ! grep -Fqw "$candidate" <<<"$used"; then
      printf '%s' "$candidate"
      return 0
    fi
  done
  return 1
}

create_profile() {
  local profile="$1" work server_copy private_key public_key psk server_public address
  local jc jmin jmax s1 s2 h1 h2 h3 h4
  work="$(mktemp -d /var/lib/my-vpn/.awg-client.XXXXXX)"
  temporary_paths+=("$work")
  chmod 0700 "$work"
  server_copy="$work/server.conf"
  docker cp "$container:$server_config" "$server_copy" >/dev/null
  chmod 0600 "$server_copy"
  private_key="$(docker exec "$container" awg genkey)"
  public_key="$(printf '%s\n' "$private_key" | docker exec -i "$container" awg pubkey)"
  psk="$(docker exec "$container" awg genpsk)"
  server_public="$(docker exec "$container" awg show "$interface" public-key)"
  address="$(allocate_address)"
  for name in Jc Jmin Jmax S1 S2 H1 H2 H3 H4; do
    value="$(sed -n "s/^${name}[[:space:]]*=[[:space:]]*//p" "$server_copy" | head -n 1)"
    [[ "$value" =~ ^-?[0-9]+$ ]]
    printf -v "${name,,}" '%s' "$value"
  done
  validate_key "$private_key"
  validate_key "$public_key"
  validate_key "$psk"
  validate_key "$server_public"
  cat > "$work/profile.conf" <<EOF
[Interface]
PrivateKey = $private_key
Address = $address
DNS = 1.1.1.1, 8.8.8.8
Jc = $jc
Jmin = $jmin
Jmax = $jmax
S1 = $s1
S2 = $s2
H1 = $h1
H2 = $h2
H3 = $h3
H4 = $h4

[Peer]
PublicKey = $server_public
PresharedKey = $psk
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = $endpoint
PersistentKeepalive = 25
EOF
  install -m 0600 -o root -g root "$work/profile.conf" "$profile"
  rm -rf "$work"
}

install -d -m 0700 -o root -g root "$state_dir"
install -d -m 0755 -o root -g root /run/lock
exec 9>"$lock"
flock -w 30 9
require_data_plane

case "$action" in
  provision)
    device_id="$(jq -r '.device_id // empty' <<<"$request")"
    [[ "$device_id" =~ ^[0-9a-f]{32}$ ]]
    jq -e '
      (.relative_name | type == "string" and length > 0 and length <= 100) and
      (.device_name | type == "string" and length > 0 and length <= 100) and
      (.platform | IN("android", "ios", "ipad", "windows", "macos", "linux"))
    ' <<<"$request" >/dev/null
    profile="$state_dir/$device_id.conf"
    if [[ ! -f "$profile" ]]; then
      create_profile "$profile"
    fi
    rewrite_server_peer add "$profile"
    apply_runtime_peer "$profile"
    jq -cn --arg path "/api/v1/devices/$device_id/config" \
      '{version:1,state:"active",config_path:$path}'
    ;;
  config)
    credential="$(jq -r '.credential_ref // empty' <<<"$request")"
    device_id="$(device_from_credential "$credential")"
    profile="$state_dir/$device_id.conf"
    [[ -f "$profile" && ! -L "$profile" ]]
    apply_runtime_peer "$profile"
    jq -cn --rawfile config "$profile" '{version:1,config:$config}'
    ;;
  revoke)
    credential="$(jq -r '.credential_ref // empty' <<<"$request")"
    device_id="$(device_from_credential "$credential")"
    profile="$state_dir/$device_id.conf"
    if [[ ! -f "$profile" ]]; then
      jq -cn '{version:1,state:"absent"}'
      exit 0
    fi
    public_key="$(profile_public_key "$profile")"
    validate_key "$public_key"
    rewrite_server_peer remove
    docker exec "$container" awg set "$interface" peer "$public_key" remove
    rm -f "$profile"
    jq -cn '{version:1,state:"revoked"}'
    ;;
esac
