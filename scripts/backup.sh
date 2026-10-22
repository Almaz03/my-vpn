#!/usr/bin/env bash
set -euo pipefail

if [[ "$EUID" -ne 0 ]]; then
  echo "backup.sh must run as root" >&2
  exit 1
fi

db=/var/lib/my-vpn/my-vpn.db
config=/etc/my-vpn/my-vpn.env
xray_config=/etc/xray/config.json
xray_client_env=/etc/my-vpn/xray-client.env
recipient_file=/etc/my-vpn/backup-age-recipient
backup_dir=/var/backups/my-vpn
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"

command -v age >/dev/null
command -v sqlite3 >/dev/null
for path in "$db" "$config" "$xray_config" "$xray_client_env" "$recipient_file"; do test -f "$path"; done
recipient="$(tr -d '\r\n' < "$recipient_file")"
[[ "$recipient" =~ ^(ssh-ed25519|ssh-rsa)[[:space:]][A-Za-z0-9+/=]+$ ]]
install -d -m 0750 -o root -g my-vpn-deploy "$backup_dir"
install -d -m 0755 -o root -g root /run/lock
exec 9>/run/lock/my-vpn-backup.lock
flock -w 30 9

while [[ -e "$backup_dir/$timestamp.age" ]]; do
  sleep 1
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
done
staging="$(mktemp -d /var/lib/my-vpn/.backup.XXXXXX)"
plain_archive="$(mktemp /var/lib/my-vpn/.backup.XXXXXX.tar)"
trap 'rm -rf "$staging" "$plain_archive"' EXIT

sqlite3 "$db" ".timeout 10000" ".backup '$staging/my-vpn.db'"
sqlite3 "$staging/my-vpn.db" 'PRAGMA integrity_check;' | grep -Fxq ok
install -m 0600 -o root -g root "$config" "$staging/my-vpn.env"
install -m 0600 -o root -g root "$xray_config" "$staging/xray-config.json"
install -m 0600 -o root -g root "$xray_client_env" "$staging/xray-client.env"
if [[ -L /opt/my-vpn/current ]]; then
  basename "$(readlink -f /opt/my-vpn/current)" > "$staging/RELEASE"
fi
(
  cd "$staging"
  sha256sum my-vpn.db my-vpn.env xray-config.json xray-client.env > SHA256SUMS
  tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
    -cf "$plain_archive" .
)
age --encrypt --recipient "$recipient" --output "$backup_dir/$timestamp.age" "$plain_archive"
(
  cd "$backup_dir"
  sha256sum "$timestamp.age" > "$timestamp.age.sha256"
)
chown root:my-vpn-deploy "$backup_dir/$timestamp.age" "$backup_dir/$timestamp.age.sha256"
chmod 0640 "$backup_dir/$timestamp.age" "$backup_dir/$timestamp.age.sha256"

find "$backup_dir" -maxdepth 1 -type f \
  \( -name '20??????T??????Z.age' -o -name '20??????T??????Z.age.sha256' \) \
  -mtime +14 -delete
echo "$backup_dir/$timestamp.age"
