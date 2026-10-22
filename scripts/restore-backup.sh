#!/usr/bin/env bash
set -euo pipefail
[[ "$EUID" -eq 0 ]] || exit 1
[[ $# -eq 2 ]] || { echo "usage: restore-backup.sh BACKUP.age AGE_IDENTITY_FILE" >&2; exit 2; }

backup="$(realpath "$1")"
identity="$(realpath "$2")"
case "$backup" in /var/backups/my-vpn/20??????T??????Z.age) ;; *) exit 2 ;; esac
test -f "$identity" -a ! -L "$identity" -a -f "$backup.sha256"
for command_name in age sqlite3 docker; do command -v "$command_name" >/dev/null; done
(cd "$(dirname "$backup")" && sha256sum --check "$(basename "$backup").sha256")

install -d -m 0755 -o root -g root /run/lock
exec 9>/run/lock/my-vpn-backup.lock
flock -w 30 9
work="$(mktemp -d /var/lib/my-vpn/.restore.XXXXXX)"
payload="$work/payload"
rescue="$work/rescue"
mkdir -m 0700 "$payload" "$rescue"
trap 'rm -rf "$work"' EXIT
age --decrypt --identity "$identity" --output "$work/backup.tar" "$backup"
tar -xf "$work/backup.tar" -C "$payload" --no-same-owner --no-same-permissions
(cd "$payload" && sha256sum --check SHA256SUMS)
sqlite3 "$payload/my-vpn.db" 'PRAGMA integrity_check;' | grep -Fxq ok
grep -Fxq '[Interface]' "$payload/awg0.conf"
grep -Eq '^PrivateKey[[:space:]]*=' "$payload/awg0.conf"

db=/var/lib/my-vpn/my-vpn.db
config=/etc/my-vpn/my-vpn.env
awg_state=/var/lib/my-vpn/amneziawg
test -f "$db" -a -f "$config" -a -d "$awg_state"
test "$(docker inspect -f '{{.State.Running}}' amnezia-awg2)" = true
service_stopped=false
restart_on_error() {
  status=$?
  trap - EXIT
  if [[ "$status" -ne 0 && "$service_stopped" == true ]]; then systemctl start my-vpn.service || true; fi
  rm -rf "$work"
  exit "$status"
}
trap restart_on_error EXIT

systemctl stop my-vpn.service
service_stopped=true
sqlite3 "$db" ".timeout 10000" ".backup '$rescue/my-vpn.db'"
install -m 0600 "$config" "$rescue/my-vpn.env"
cp -a "$awg_state" "$rescue/amneziawg"
docker cp amnezia-awg2:/opt/amnezia/awg/awg0.conf "$rescue/awg0.conf" >/dev/null

rm -f "$db-wal" "$db-shm"
install -m 0600 -o my-vpn -g my-vpn "$payload/my-vpn.db" "$db"
install -m 0640 -o root -g my-vpn "$payload/my-vpn.env" "$config"
find "$awg_state" -maxdepth 1 -type f -name '*.conf' -delete
find "$payload/amneziawg" -maxdepth 1 -type f -name '*.conf' -exec install -m 0600 -o root -g root {} "$awg_state/" \;
docker cp "$payload/awg0.conf" amnezia-awg2:/opt/amnezia/awg/awg0.conf >/dev/null
docker restart amnezia-awg2 >/dev/null
systemctl start my-vpn.service
service_stopped=false

healthy=false
for _ in {1..20}; do
  if docker exec amnezia-awg2 awg show awg0 >/dev/null 2>&1 && \
     curl --fail --silent --max-time 2 http://127.0.0.1:8080/healthz >/dev/null; then healthy=true; break; fi
  sleep 1
done
if [[ "$healthy" == true ]]; then
  trap - EXIT
  rm -rf "$work"
  echo "restored encrypted backup: $backup"
  exit 0
fi

systemctl stop my-vpn.service
service_stopped=true
rm -f "$db-wal" "$db-shm"
install -m 0600 -o my-vpn -g my-vpn "$rescue/my-vpn.db" "$db"
install -m 0640 -o root -g my-vpn "$rescue/my-vpn.env" "$config"
find "$awg_state" -maxdepth 1 -type f -name '*.conf' -delete
find "$rescue/amneziawg" -maxdepth 1 -type f -name '*.conf' -exec install -m 0600 -o root -g root {} "$awg_state/" \;
docker cp "$rescue/awg0.conf" amnezia-awg2:/opt/amnezia/awg/awg0.conf >/dev/null
docker restart amnezia-awg2 >/dev/null
systemctl start my-vpn.service
service_stopped=false
exit 1
