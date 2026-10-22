#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 /var/backups/my-vpn/TIMESTAMP" >&2
  exit 2
fi
if [[ "$EUID" -ne 0 ]]; then
  echo "restore-backup.sh must run as root" >&2
  exit 1
fi

backup_dir="$(realpath "$1")"
case "$backup_dir" in
  /var/backups/my-vpn/20??????T??????Z) ;;
  *) echo "backup must be a timestamped directory below /var/backups/my-vpn" >&2; exit 2 ;;
esac

command -v sqlite3 >/dev/null
command -v flock >/dev/null
install -d -m 0755 -o root -g root /run/lock
exec 9>/run/lock/my-vpn-backup.lock
flock -w 30 9

(
  cd "$backup_dir"
  sha256sum --check SHA256SUMS
)
sqlite3 "$backup_dir/my-vpn.db" 'PRAGMA integrity_check;' | grep -Fxq ok

state_dir=/var/lib/my-vpn
config_dir=/etc/my-vpn
db="$state_dir/my-vpn.db"
config="$config_dir/my-vpn.env"
test -f "$db"
test -f "$config"
rescue="$(mktemp -d /var/backups/my-vpn/.pre-restore.XXXXXX)"
service_stopped=false
restart_on_error() {
  local status=$?
  trap - EXIT
  if [[ "$status" -ne 0 && "$service_stopped" == true ]]; then
    systemctl start my-vpn.service || true
  fi
  exit "$status"
}
trap restart_on_error EXIT

# Stop the sole writer before taking the rescue snapshot. sqlite3 .backup folds any
# remaining WAL state into a self-contained database, unlike copying the main file.
systemctl stop my-vpn.service
service_stopped=true
sqlite3 "$db" ".timeout 10000" ".backup '$rescue/my-vpn.db'"
sqlite3 "$rescue/my-vpn.db" 'PRAGMA integrity_check;' | grep -Fxq ok
install -m 0600 -o root -g my-vpn "$config" "$rescue/my-vpn.env"
chmod 0600 "$rescue/my-vpn.db"

# Never attach a WAL from a different database generation to the restored file.
rm -f "$db-wal" "$db-shm"
install -m 0600 -o my-vpn -g my-vpn "$backup_dir/my-vpn.db" "$db"
install -m 0600 -o root -g my-vpn "$backup_dir/my-vpn.env" "$config"
systemctl start my-vpn.service
service_stopped=false

for _ in {1..20}; do
  if curl --fail --silent --show-error --max-time 2 http://127.0.0.1:8080/healthz >/dev/null; then
    trap - EXIT
    echo "restored backup: $backup_dir (rescue snapshot: $rescue)"
    exit 0
  fi
  sleep 1
done

echo "restored backup failed health check; restoring pre-restore state" >&2
systemctl stop my-vpn.service
service_stopped=true
rm -f "$db-wal" "$db-shm"
install -m 0600 -o my-vpn -g my-vpn "$rescue/my-vpn.db" "$db"
install -m 0600 -o root -g my-vpn "$rescue/my-vpn.env" "$config"
systemctl start my-vpn.service
service_stopped=false
trap - EXIT
exit 1
