#!/usr/bin/env bash
set -euo pipefail
[[ "$EUID" -eq 0 ]] || exit 1

db=/var/lib/my-vpn/my-vpn.db
config=/etc/my-vpn/my-vpn.env
awg_state=/var/lib/my-vpn/amneziawg
recipient_file=/etc/my-vpn/backup-age-recipient
backup_dir=/var/backups/my-vpn
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
for command_name in age sqlite3 docker; do command -v "$command_name" >/dev/null; done
for path in "$db" "$config" "$awg_state" "$recipient_file"; do test -e "$path"; done
test "$(docker inspect -f '{{.State.Running}}' amnezia-awg2)" = true
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
install -d -m 0700 "$staging/amneziawg"
find "$awg_state" -maxdepth 1 -type f -name '*.conf' -exec cp --preserve=mode {} "$staging/amneziawg/" \;
docker cp amnezia-awg2:/opt/amnezia/awg/awg0.conf "$staging/awg0.conf" >/dev/null
chmod 0600 "$staging/awg0.conf" "$staging"/amneziawg/*.conf 2>/dev/null || true
if [[ -L /opt/my-vpn/current ]]; then
  basename "$(readlink -f /opt/my-vpn/current)" > "$staging/RELEASE"
fi
(
  cd "$staging"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
  tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner -cf "$plain_archive" .
)
age --encrypt --recipient "$recipient" --output "$backup_dir/$timestamp.age" "$plain_archive"
(
  cd "$backup_dir"
  sha256sum "$timestamp.age" > "$timestamp.age.sha256"
)
chown root:my-vpn-deploy "$backup_dir/$timestamp.age" "$backup_dir/$timestamp.age.sha256"
chmod 0640 "$backup_dir/$timestamp.age" "$backup_dir/$timestamp.age.sha256"
find "$backup_dir" -maxdepth 1 -type f \
  \( -name '20??????T??????Z.age' -o -name '20??????T??????Z.age.sha256' \) -mtime +14 -delete
echo "$backup_dir/$timestamp.age"
