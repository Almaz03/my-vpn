#!/usr/bin/env bash
set -euo pipefail

[[ "${EUID}" -eq 0 ]] || { echo 'reset-test-data must run as root' >&2; exit 1; }
[[ "${1:-}" == 'RESET-ALL-CLIENTS' && $# -eq 1 ]] || {
  echo 'usage: reset-test-data.sh RESET-ALL-CLIENTS' >&2
  exit 2
}

database=/var/lib/my-vpn/my-vpn.db
state_dir=/var/lib/my-vpn/reality/devices
helper=/usr/local/libexec/my-vpn/reality-helper

test -f "$database"
test -x "$helper"
/usr/local/libexec/my-vpn/backup.sh >/dev/null

systemctl stop my-vpn.service
restart_required=true
# shellcheck disable=SC2317 # cleanup is invoked by EXIT trap
cleanup() {
  if [[ "$restart_required" == true ]]; then systemctl start my-vpn.service || true; fi
}
trap cleanup EXIT

declare -A device_ids=()
while IFS= read -r device_id; do
  [[ "$device_id" =~ ^[0-9a-f]{32}$ ]] || { echo 'invalid device id in database' >&2; exit 1; }
  device_ids["$device_id"]=1
done < <(sqlite3 "$database" "SELECT id FROM devices;")

if [[ -d "$state_dir" ]]; then
  while IFS= read -r state_file; do
    device_id="$(basename "$state_file" .json)"
    [[ "$device_id" =~ ^[0-9a-f]{32}$ ]] || { echo 'invalid device state filename' >&2; exit 1; }
    device_ids["$device_id"]=1
  done < <(find "$state_dir" -maxdepth 1 -type f -name '*.json' -print)
fi

for device_id in "${!device_ids[@]}"; do
  jq -cn --arg credential "vless-reality:$device_id" \
    '{version:1,credential_ref:$credential}' | "$helper" revoke >/dev/null
done

sqlite3 "$database" <<'SQL'
PRAGMA foreign_keys = ON;
BEGIN IMMEDIATE;
DELETE FROM subscription_tokens;
DELETE FROM devices;
DELETE FROM access_requests;
DELETE FROM invitations;
DELETE FROM activation_attempts;
DELETE FROM rate_limit_state;
DELETE FROM code_attempts;
DELETE FROM admin_invitation_creations;
COMMIT;
SQL

remaining="$(sqlite3 "$database" "SELECT (SELECT count(*) FROM devices) + (SELECT count(*) FROM invitations) + (SELECT count(*) FROM access_requests) + (SELECT count(*) FROM subscription_tokens);")"
[[ "$remaining" == 0 ]]

systemctl start my-vpn.service
restart_required=false
for _ in {1..20}; do
  if curl --fail --silent --show-error --max-time 2 http://127.0.0.1:8080/healthz >/dev/null; then
    printf '{"devices":0,"invitations":0,"access_requests":0,"rate_limits":0}\n'
    exit 0
  fi
  sleep 1
done
echo 'application did not become healthy after reset' >&2
exit 1
