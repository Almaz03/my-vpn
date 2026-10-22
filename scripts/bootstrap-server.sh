#!/usr/bin/env bash
set -euo pipefail
trap 'status=$?; echo "bootstrap failed at line $LINENO" >&2; exit "$status"' ERR

[[ "$EUID" -eq 0 ]] || exit 1
[[ $# -eq 1 ]] || exit 2
ssh_port="$1"
deploy_user=my-vpn-deploy
app_user=my-vpn
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bundle_root="$(cd "$script_dir/.." && pwd)"
[[ "$ssh_port" =~ ^[0-9]{1,5}$ ]] && (( ssh_port >= 1 && ssh_port <= 65535 )) || exit 2

for required in \
  "$bundle_root/deploy/Caddyfile" "$bundle_root/deploy/my-vpn.service" \
  "$bundle_root/deploy/my-vpn-backup.service" "$bundle_root/deploy/my-vpn-backup.timer" \
  "$bundle_root/deploy/my-vpn.sudoers" "$bundle_root/scripts/install-release.sh" \
  "$bundle_root/scripts/rollback.sh" "$bundle_root/scripts/deactivate-release.sh" \
  "$bundle_root/scripts/backup.sh" "$bundle_root/scripts/restore-backup.sh" \
  "$bundle_root/scripts/release-helper.sh" "$bundle_root/scripts/amneziawg-helper.sh" \
  "$bundle_root/scripts/application-canary.sh"; do
  test -f "$required"
done

deploy_public_key="$bundle_root/deploy-authorized-key.pub"
test -s "$deploy_public_key"
test "$(awk 'NF {count++} END {print count+0}' "$deploy_public_key")" -eq 1
ssh-keygen -lf "$deploy_public_key" >/dev/null

# Refuse to touch networking unless the existing working Amnezia data plane is healthy.
command -v docker >/dev/null
test "$(docker inspect -f '{{.State.Running}}' amnezia-awg2)" = true
docker exec amnezia-awg2 test -f /opt/amnezia/awg/awg0.conf
docker exec amnezia-awg2 awg show awg0 >/dev/null
ss -H -lun | awk '{print $4}' | grep -Eq '(^|:)35473$'

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install --yes --no-install-recommends age ca-certificates caddy curl jq openssl sqlite3 sudo ufw

if ! id "$app_user" >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/my-vpn --shell /usr/sbin/nologin "$app_user"
fi
if ! id "$deploy_user" >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash "$deploy_user"
fi
passwd --lock "$deploy_user" >/dev/null
deploy_home="$(getent passwd "$deploy_user" | cut -d: -f6)"
install -d -m 0700 -o "$deploy_user" -g "$deploy_user" "$deploy_home/.ssh"
install -m 0600 -o "$deploy_user" -g "$deploy_user" "$deploy_public_key" "$deploy_home/.ssh/authorized_keys"

install -d -m 0755 -o root -g root /opt/my-vpn /opt/my-vpn/releases /usr/local/libexec/my-vpn
install -d -m 0750 -o "$app_user" -g "$app_user" /var/lib/my-vpn
install -d -m 0700 -o root -g root /var/lib/my-vpn/amneziawg
install -d -m 0750 -o "$deploy_user" -g "$deploy_user" /var/lib/my-vpn-deploy /var/lib/my-vpn-deploy/incoming
install -d -m 0750 -o root -g "$app_user" /etc/my-vpn /etc/my-vpn/releases
install -d -m 0750 -o root -g "$deploy_user" /var/backups/my-vpn

install -m 0755 -o root -g root "$bundle_root/scripts/install-release.sh" /usr/local/libexec/my-vpn/install-release.sh
install -m 0755 -o root -g root "$bundle_root/scripts/rollback.sh" /usr/local/libexec/my-vpn/rollback.sh
install -m 0755 -o root -g root "$bundle_root/scripts/deactivate-release.sh" /usr/local/libexec/my-vpn/deactivate-release.sh
install -m 0755 -o root -g root "$bundle_root/scripts/backup.sh" /usr/local/libexec/my-vpn/backup.sh
install -m 0755 -o root -g root "$bundle_root/scripts/restore-backup.sh" /usr/local/libexec/my-vpn/restore-backup.sh
install -m 0755 -o root -g root "$bundle_root/scripts/release-helper.sh" /usr/local/sbin/my-vpn-release
install -m 0755 -o root -g root "$bundle_root/scripts/amneziawg-helper.sh" /usr/local/libexec/my-vpn/amneziawg-helper
install -m 0755 -o root -g root "$bundle_root/scripts/application-canary.sh" /usr/local/libexec/my-vpn/application-canary.sh
install -m 0644 -o root -g root "$bundle_root/deploy/my-vpn.service" /etc/systemd/system/my-vpn.service
install -m 0644 -o root -g root "$bundle_root/deploy/my-vpn-backup.service" /etc/systemd/system/my-vpn-backup.service
install -m 0644 -o root -g root "$bundle_root/deploy/my-vpn-backup.timer" /etc/systemd/system/my-vpn-backup.timer
install -m 0440 -o root -g root "$bundle_root/deploy/my-vpn.sudoers" /etc/sudoers.d/my-vpn
visudo -cf /etc/sudoers.d/my-vpn

{
  printf 'AMNEZIAWG_CONTAINER=amnezia-awg2\n'
  printf 'AMNEZIAWG_INTERFACE=awg0\n'
  printf 'AMNEZIAWG_SERVER_CONFIG=/opt/amnezia/awg/awg0.conf\n'
  printf 'AMNEZIAWG_ENDPOINT=vpn.akalmaz.tech:35473\n'
} > /etc/my-vpn/amneziawg.env
chown root:root /etc/my-vpn/amneziawg.env
chmod 0600 /etc/my-vpn/amneziawg.env
awk '{print $1, $2}' "$deploy_public_key" > /etc/my-vpn/backup-age-recipient
chmod 0644 /etc/my-vpn/backup-age-recipient

# Reconcile every portal-issued profile after installing a new helper. This
# also repairs profiles created by an older helper without changing the client
# keys that users have already imported into AmneziaVPN.
reconciled_profiles=0
while IFS= read -r -d '' profile; do
  device_id="$(basename "$profile" .conf)"
  [[ "$device_id" =~ ^[0-9a-f]{32}$ ]] || exit 1
  jq -cn --arg credential_ref "amneziawg:$device_id" \
    '{version:1,credential_ref:$credential_ref}' | \
    /usr/local/libexec/my-vpn/amneziawg-helper config >/dev/null
  ((reconciled_profiles += 1))
done < <(find /var/lib/my-vpn/amneziawg -maxdepth 1 -type f -name '*.conf' -print0)
printf 'reconciled AmneziaWG profiles: %d\n' "$reconciled_profiles"

install -d -m 0755 -o root -g root /etc/caddy/conf.d
if ! grep -Eq '^[[:space:]]*import[[:space:]]+conf\.d/\*' /etc/caddy/Caddyfile; then
  install -m 0644 -o root -g root /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.pre-my-vpn.$(date -u +%Y%m%dT%H%M%SZ)"
  printf 'import conf.d/*\n' > /etc/caddy/Caddyfile
fi
install -m 0644 -o root -g root "$bundle_root/deploy/Caddyfile" /etc/caddy/conf.d/my-vpn.caddy
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile

ufw allow "$ssh_port/tcp" comment 'SSH managed outside my-vpn'
ufw allow 80/tcp comment 'my-vpn ACME HTTP challenge and redirect'
ufw allow 443/tcp comment 'my-vpn HTTPS'
ufw allow 35473/udp comment 'AmneziaWG'
ufw --force delete allow 8443/tcp >/dev/null 2>&1 || true
ufw --force delete allow 8444/tcp >/dev/null 2>&1 || true
if ip link show tailscale0 >/dev/null 2>&1; then
  ufw allow in on tailscale0 comment 'Tailscale management'
fi
ufw default deny incoming
ufw default allow outgoing
ufw --force enable

# Retire the old data plane before Caddy reclaims public TCP/443.
systemctl disable --now xray.service >/dev/null 2>&1 || true
rm -f /etc/systemd/system/xray.service /usr/local/bin/xray \
  /usr/local/libexec/my-vpn/reality-helper /usr/local/libexec/my-vpn/reality-canary.sh \
  /etc/my-vpn/xray-client.env
rm -rf -- /etc/xray /var/lib/xray /usr/local/share/xray /var/lib/my-vpn-routing
if id xray >/dev/null 2>&1; then userdel xray; fi

systemctl daemon-reload
systemctl enable caddy.service
systemctl restart caddy.service
systemctl enable --now my-vpn-backup.timer
systemctl is-active --quiet caddy.service
ss -H -ltn | awk '{print $4}' | grep -Eq '(^|:)443$'
! systemctl is-active --quiet xray.service 2>/dev/null
test "$(docker inspect -f '{{.State.Running}}' amnezia-awg2)" = true
docker exec amnezia-awg2 awg show awg0 >/dev/null
ss -H -lun | awk '{print $4}' | grep -Eq '(^|:)35473$'
echo "bootstrap complete; AmneziaWG is the only VPN data plane"
