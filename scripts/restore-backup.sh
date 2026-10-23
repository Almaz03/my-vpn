#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: restore-backup.sh BACKUP.age AGE_IDENTITY_FILE" >&2
  exit 2
fi
if [[ "$EUID" -ne 0 ]]; then
  echo "restore-backup.sh must run as root" >&2
  exit 1
fi

backup="$(realpath "$1")"
identity="$(realpath "$2")"
case "$backup" in
  /var/backups/my-vpn/20??????T??????Z.age) ;;
  *) echo "backup must be an encrypted timestamped archive below /var/backups/my-vpn" >&2; exit 2 ;;
esac
test -f "$identity" -a ! -L "$identity"
test -f "$backup.sha256"
command -v age >/dev/null
command -v sqlite3 >/dev/null
(
  cd "$(dirname "$backup")"
  sha256sum --check "$(basename "$backup").sha256"
)

install -d -m 0755 -o root -g root /run/lock
exec 9>/run/lock/my-vpn-backup.lock
flock -w 30 9
work="$(mktemp -d /var/lib/my-vpn/.restore.XXXXXX)"
plain_archive="$work/backup.tar"
payload="$work/payload"
rescue="$work/rescue"
mkdir -m 0700 "$payload" "$rescue"
trap 'rm -rf "$work"' EXIT
age --decrypt --identity "$identity" --output "$plain_archive" "$backup"
tar -xf "$plain_archive" -C "$payload" --no-same-owner --no-same-permissions
(
  cd "$payload"
  sha256sum --check SHA256SUMS
)
sqlite3 "$payload/my-vpn.db" 'PRAGMA integrity_check;' | grep -Fxq ok
jq -e '([.inbounds[] | select(.tag == "my-vpn-reality")] | length) == 1' "$payload/xray-config.json" >/dev/null
xray run -test -config "$payload/xray-config.json" >/dev/null

db=/var/lib/my-vpn/my-vpn.db
config=/etc/my-vpn/my-vpn.env
xray_config=/etc/xray/config.json
xray_client_env=/etc/my-vpn/xray-client.env
for path in "$db" "$config" "$xray_config" "$xray_client_env"; do test -f "$path"; done
service_stopped=false
restart_on_error() {
  status=$?
  trap - EXIT
  if [[ "$status" -ne 0 && "$service_stopped" == true ]]; then
    systemctl start xray.service my-vpn.service || true
  fi
  rm -rf "$work"
  exit "$status"
}
trap restart_on_error EXIT

systemctl stop my-vpn.service xray.service
service_stopped=true
sqlite3 "$db" ".timeout 10000" ".backup '$rescue/my-vpn.db'"
install -m 0600 -o root -g root "$config" "$rescue/my-vpn.env"
install -m 0600 -o root -g root "$xray_config" "$rescue/xray-config.json"
install -m 0600 -o root -g root "$xray_client_env" "$rescue/xray-client.env"

rm -f "$db-wal" "$db-shm"
install -m 0600 -o my-vpn -g my-vpn "$payload/my-vpn.db" "$db"
install -m 0640 -o root -g my-vpn "$payload/my-vpn.env" "$config"
install -m 0640 -o xray -g xray "$payload/xray-config.json" "$xray_config"
install -m 0640 -o root -g my-vpn "$payload/xray-client.env" "$xray_client_env"
systemctl start xray.service my-vpn.service
service_stopped=false

healthy=false
for _ in {1..20}; do
  if systemctl is-active --quiet xray.service && \
     curl --fail --silent --show-error --max-time 2 http://127.0.0.1:8080/healthz >/dev/null; then
    healthy=true
    break
  fi
  sleep 1
done
if [[ "$healthy" == true ]]; then
  trap - EXIT
  rm -rf "$work"
  echo "restored encrypted backup: $backup"
  exit 0
fi

echo "restored backup failed health check; restoring pre-restore state" >&2
systemctl stop my-vpn.service xray.service
service_stopped=true
rm -f "$db-wal" "$db-shm"
install -m 0600 -o my-vpn -g my-vpn "$rescue/my-vpn.db" "$db"
install -m 0640 -o root -g my-vpn "$rescue/my-vpn.env" "$config"
install -m 0640 -o xray -g xray "$rescue/xray-config.json" "$xray_config"
install -m 0640 -o root -g my-vpn "$rescue/xray-client.env" "$xray_client_env"
systemctl start xray.service my-vpn.service
service_stopped=false
trap - EXIT
rm -rf "$work"
exit 1
