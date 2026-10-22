#!/usr/bin/env bash
set -euo pipefail

if [[ "$EUID" -ne 0 ]]; then
  echo "backup.sh must run as root" >&2
  exit 1
fi

db=/var/lib/my-vpn/my-vpn.db
config=/etc/my-vpn/my-vpn.env
backup_dir=/var/backups/my-vpn
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"

command -v sqlite3 >/dev/null
test -f "$db"
test -f "$config"
install -d -m 0700 -o root -g root "$backup_dir"
install -d -m 0755 -o root -g root /run/lock
exec 9>/run/lock/my-vpn-backup.lock
flock -w 30 9

while [[ -e "$backup_dir/$timestamp" ]]; do
  sleep 1
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
done
staging="$(mktemp -d "$backup_dir/.incoming.XXXXXX")"
trap 'rm -rf "$staging"' EXIT

sqlite3 "$db" ".timeout 10000" ".backup '$staging/my-vpn.db'"
sqlite3 "$staging/my-vpn.db" 'PRAGMA integrity_check;' | grep -Fxq ok
install -m 0600 -o root -g root "$config" "$staging/my-vpn.env"
(
  cd "$staging"
  sha256sum my-vpn.db my-vpn.env > SHA256SUMS
)
chmod 0600 "$staging/my-vpn.db" "$staging/SHA256SUMS"
mv "$staging" "$backup_dir/$timestamp"
trap - EXIT

find "$backup_dir" -mindepth 1 -maxdepth 1 -type d -name '20??????T??????Z' -mtime +14 -exec rm -rf -- {} +
echo "backup created: $backup_dir/$timestamp"
