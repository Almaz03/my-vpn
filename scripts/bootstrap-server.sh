#!/usr/bin/env bash
set -euo pipefail
trap 'status=$?; echo "bootstrap failed at line $LINENO" >&2; exit "$status"' ERR

if [[ "$EUID" -ne 0 ]]; then
  echo "bootstrap-server.sh must run as root" >&2
  exit 1
fi
if [[ $# -ne 1 ]]; then
  echo "usage: bootstrap-server.sh SSH_PORT" >&2
  exit 2
fi

ssh_port="$1"
deploy_user=my-vpn-deploy
app_user=my-vpn
xray_user=xray
xray_version=26.3.27
xray_sha256=23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae
xray_url="https://github.com/XTLS/Xray-core/releases/download/v${xray_version}/Xray-linux-64.zip"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bundle_root="$(cd "$script_dir/.." && pwd)"

[[ "$ssh_port" =~ ^[0-9]{1,5}$ ]] && (( ssh_port >= 1 && ssh_port <= 65535 )) || {
  echo "invalid SSH port" >&2
  exit 2
}
for required in \
  "$bundle_root/deploy/Caddyfile" \
  "$bundle_root/deploy/my-vpn.service" \
  "$bundle_root/deploy/my-vpn-backup.service" \
  "$bundle_root/deploy/my-vpn-backup.timer" \
  "$bundle_root/deploy/xray.service" \
  "$bundle_root/deploy/my-vpn.sudoers" \
  "$bundle_root/scripts/install-release.sh" \
  "$bundle_root/scripts/rollback.sh" \
  "$bundle_root/scripts/deactivate-release.sh" \
  "$bundle_root/scripts/backup.sh" \
  "$bundle_root/scripts/restore-backup.sh" \
  "$bundle_root/scripts/release-helper.sh" \
  "$bundle_root/scripts/reality-helper.sh" \
  "$bundle_root/scripts/application-canary.sh" \
  "$bundle_root/scripts/reality-canary.sh"; do
  test -f "$required"
done

deploy_public_key="$bundle_root/deploy-authorized-key.pub"
test -s "$deploy_public_key"
test "$(awk 'NF {count++} END {print count+0}' "$deploy_public_key")" -eq 1
awk 'NF >= 2 && ($1 == "ssh-ed25519" || $1 == "ssh-rsa") && $2 ~ /^[A-Za-z0-9+\/=]+$/ {ok=1} END {exit !ok}' "$deploy_public_key"
ssh-keygen -lf "$deploy_public_key" >/dev/null
echo "bootstrap phase: inputs validated"

had_caddy=false
if command -v caddy >/dev/null 2>&1; then
  had_caddy=true
  if systemctl is-active --quiet caddy.service 2>/dev/null && \
     ! grep -Eq '^[[:space:]]*import[[:space:]]+conf\.d/\*' /etc/caddy/Caddyfile; then
    echo "active unmanaged Caddy configuration found; refusing to overwrite it" >&2
    exit 1
  fi
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install --yes --no-install-recommends \
  age ca-certificates caddy curl jq openssl sqlite3 sudo ufw unzip
echo "bootstrap phase: packages installed"

for user_spec in "$app_user:/var/lib/my-vpn:/usr/sbin/nologin" "$xray_user:/var/lib/xray:/usr/sbin/nologin"; do
  user_name="${user_spec%%:*}"
  rest="${user_spec#*:}"
  user_home="${rest%%:*}"
  user_shell="${rest##*:}"
  if ! id "$user_name" >/dev/null 2>&1; then
    useradd --system --home-dir "$user_home" --shell "$user_shell" "$user_name"
  fi
done
if ! id "$deploy_user" >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash "$deploy_user"
fi
passwd --lock "$deploy_user" >/dev/null
deploy_home="$(getent passwd "$deploy_user" | cut -d: -f6)"
install -d -m 0700 -o "$deploy_user" -g "$deploy_user" "$deploy_home/.ssh"
install -m 0600 -o "$deploy_user" -g "$deploy_user" \
  "$deploy_public_key" "$deploy_home/.ssh/authorized_keys"

install_tmp="$(mktemp -d /tmp/my-vpn-bootstrap.XXXXXX)"
trap 'rm -rf "$install_tmp"' EXIT
curl --fail --location --proto '=https' --tlsv1.2 -o "$install_tmp/xray.zip" "$xray_url"
printf '%s  %s\n' "$xray_sha256" "$install_tmp/xray.zip" | sha256sum --check -
unzip -q "$install_tmp/xray.zip" xray geoip.dat geosite.dat -d "$install_tmp"
install -m 0755 -o root -g root "$install_tmp/xray" /usr/local/bin/xray
/usr/local/bin/xray version | head -n 1 | grep -Fq "Xray ${xray_version}"

install -d -m 0755 -o root -g root /opt/my-vpn /opt/my-vpn/releases
install -d -m 0750 -o "$app_user" -g "$app_user" /var/lib/my-vpn
install -d -m 0750 -o "$xray_user" -g "$xray_user" /var/lib/xray
install -d -m 0750 -o "$deploy_user" -g "$deploy_user" /var/lib/my-vpn-deploy /var/lib/my-vpn-deploy/incoming
install -d -m 0750 -o root -g "$app_user" /etc/my-vpn /etc/my-vpn/releases
install -d -m 0750 -o "$xray_user" -g "$xray_user" /etc/xray
install -d -m 0750 -o root -g "$deploy_user" /var/backups/my-vpn
install -d -m 0750 -o root -g caddy /var/lib/my-vpn-routing /var/lib/my-vpn-routing/routing
install -d -m 0755 -o root -g root /usr/local/libexec/my-vpn
install -d -m 0755 -o root -g root /usr/local/share/xray
install -m 0644 -o root -g root "$install_tmp/geoip.dat" /usr/local/share/xray/geoip.dat
install -m 0644 -o root -g root "$install_tmp/geosite.dat" /usr/local/share/xray/geosite.dat

install -m 0755 -o root -g root "$bundle_root/scripts/install-release.sh" /usr/local/libexec/my-vpn/install-release.sh
install -m 0755 -o root -g root "$bundle_root/scripts/rollback.sh" /usr/local/libexec/my-vpn/rollback.sh
install -m 0755 -o root -g root "$bundle_root/scripts/deactivate-release.sh" /usr/local/libexec/my-vpn/deactivate-release.sh
install -m 0755 -o root -g root "$bundle_root/scripts/backup.sh" /usr/local/libexec/my-vpn/backup.sh
install -m 0755 -o root -g root "$bundle_root/scripts/restore-backup.sh" /usr/local/libexec/my-vpn/restore-backup.sh
install -m 0755 -o root -g root "$bundle_root/scripts/release-helper.sh" /usr/local/sbin/my-vpn-release
install -m 0755 -o root -g root "$bundle_root/scripts/reality-helper.sh" /usr/local/libexec/my-vpn/reality-helper
install -m 0755 -o root -g root "$bundle_root/scripts/application-canary.sh" /usr/local/libexec/my-vpn/application-canary.sh
install -m 0755 -o root -g root "$bundle_root/scripts/reality-canary.sh" /usr/local/libexec/my-vpn/reality-canary.sh
install -m 0644 -o root -g root "$bundle_root/deploy/my-vpn.service" /etc/systemd/system/my-vpn.service
install -m 0644 -o root -g root "$bundle_root/deploy/my-vpn-backup.service" /etc/systemd/system/my-vpn-backup.service
install -m 0644 -o root -g root "$bundle_root/deploy/my-vpn-backup.timer" /etc/systemd/system/my-vpn-backup.timer
install -m 0644 -o root -g root "$bundle_root/deploy/xray.service" /etc/systemd/system/xray.service
install -m 0440 -o root -g root "$bundle_root/deploy/my-vpn.sudoers" /etc/sudoers.d/my-vpn
visudo -cf /etc/sudoers.d/my-vpn
echo "bootstrap phase: users and root-owned helpers installed"

awk '{print $1, $2}' "$deploy_public_key" > /etc/my-vpn/backup-age-recipient
chown root:root /etc/my-vpn/backup-age-recipient
chmod 0644 /etc/my-vpn/backup-age-recipient

install -m 0644 -o root -g caddy "$install_tmp/geoip.dat" /var/lib/my-vpn-routing/routing/geoip.dat
install -m 0644 -o root -g caddy "$install_tmp/geosite.dat" /var/lib/my-vpn-routing/routing/geosite.dat
sha256sum /var/lib/my-vpn-routing/routing/geoip.dat | awk '{print $1}' > /var/lib/my-vpn-routing/routing/geoip.dat.sha256
sha256sum /var/lib/my-vpn-routing/routing/geosite.dat | awk '{print $1}' > /var/lib/my-vpn-routing/routing/geosite.dat.sha256
chown root:caddy /var/lib/my-vpn-routing/routing/*.sha256
chmod 0644 /var/lib/my-vpn-routing/routing/*.sha256

if [[ ! -f /etc/xray/.managed-by-my-vpn ]]; then
  if [[ -e /etc/xray/config.json ]]; then
    echo "unmanaged Xray configuration found; refusing to overwrite it" >&2
    exit 1
  fi
  key_output="$(/usr/local/bin/xray x25519)"
  private_key="$(sed -n 's/^PrivateKey: //p' <<<"$key_output")"
  public_key="$(sed -n 's/^Password (PublicKey): //p' <<<"$key_output")"
  short_id="$(openssl rand -hex 8)"
  [[ "$private_key" =~ ^[A-Za-z0-9_-]{43}$ && "$public_key" =~ ^[A-Za-z0-9_-]{43}$ ]]
  [[ "$short_id" =~ ^[0-9a-f]{16}$ ]]
  jq -n --arg private_key "$private_key" --arg short_id "$short_id" '{
    log: {loglevel: "warning"},
    inbounds: [{
      tag: "my-vpn-reality",
      listen: "0.0.0.0",
      port: 8443,
      protocol: "vless",
      settings: {clients: [], decryption: "none"},
      streamSettings: {
        network: "raw",
        security: "reality",
        realitySettings: {
          show: false,
          dest: "127.0.0.1:443",
          xver: 0,
          serverNames: ["vpn.akalmaz.tech"],
          privateKey: $private_key,
          shortIds: [$short_id]
        }
      },
      sniffing: {enabled: true, destOverride: ["http", "tls", "quic"], routeOnly: true}
    }],
    outbounds: [
      {tag: "direct", protocol: "freedom"},
      {tag: "blocked", protocol: "blackhole"}
    ],
    routing: {
      domainStrategy: "IPIfNonMatch",
      rules: [
        {type: "field", ip: ["geoip:private"], outboundTag: "blocked"},
        {type: "field", protocol: ["bittorrent"], outboundTag: "blocked"}
      ]
    }
  }' > /etc/xray/config.json
  chown "$xray_user:$xray_user" /etc/xray/config.json
  chmod 0640 /etc/xray/config.json
  touch /etc/xray/.managed-by-my-vpn
  chown root:root /etc/xray/.managed-by-my-vpn
  chmod 0644 /etc/xray/.managed-by-my-vpn
  {
    printf 'XRAY_SERVER=vpn.akalmaz.tech\n'
    printf 'XRAY_PORT=8443\n'
    printf 'XRAY_PUBLIC_KEY=%s\n' "$public_key"
    printf 'XRAY_SHORT_ID=%s\n' "$short_id"
    printf 'XRAY_SNI=vpn.akalmaz.tech\n'
    printf 'XRAY_FLOW=xtls-rprx-vision\n'
    printf 'XRAY_CLIENT_HELPER=/usr/local/libexec/my-vpn/reality-helper\n'
  } > /etc/my-vpn/xray-client.env
  chown root:"$app_user" /etc/my-vpn/xray-client.env
  chmod 0640 /etc/my-vpn/xray-client.env
fi
test -f /etc/my-vpn/xray-client.env
/usr/local/bin/xray run -test -config /etc/xray/config.json >/dev/null
echo "bootstrap phase: Xray configured"

install -d -m 0755 -o root -g root /etc/caddy/conf.d
install -d -m 0750 -o caddy -g caddy /var/log/caddy
if ! grep -Eq '^[[:space:]]*import[[:space:]]+conf\.d/\*' /etc/caddy/Caddyfile; then
  if [[ "$had_caddy" == true ]]; then
    echo "existing Caddy installation lacks the managed import; refusing to replace it" >&2
    exit 1
  fi
  install -m 0644 -o root -g root /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.pre-my-vpn.$(date -u +%Y%m%dT%H%M%SZ)"
  printf 'import conf.d/*\n' > /etc/caddy/Caddyfile
fi
install -m 0644 -o root -g root "$bundle_root/deploy/Caddyfile" /etc/caddy/conf.d/my-vpn.caddy
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
echo "bootstrap phase: Caddy configured"

awg_was_running=false
if command -v docker >/dev/null 2>&1 && \
   [[ "$(docker inspect -f '{{.State.Running}}' amnezia-awg2 2>/dev/null || true)" == true ]]; then
  awg_was_running=true
  ss -H -lun | awk '{print $4}' | grep -Eq '(^|:)35473$'
  docker exec amnezia-awg2 sh -c \
    'if command -v awg >/dev/null; then awg show; elif command -v wg >/dev/null; then wg show; else exit 127; fi' \
    >/dev/null
fi

ufw allow "$ssh_port/tcp" comment 'SSH managed outside my-vpn'
ufw allow 80/tcp comment 'my-vpn ACME HTTP challenge and redirect'
ufw allow 443/tcp comment 'my-vpn HTTPS portal'
ufw allow 8443/tcp comment 'my-vpn VLESS Reality'
ufw allow 35473/udp comment 'existing AmneziaWG - do not remove'
if ip link show tailscale0 >/dev/null 2>&1; then
  ufw allow in on tailscale0 comment 'Tailscale management'
fi
ufw default deny incoming
ufw default allow outgoing
ufw --force enable
echo "bootstrap phase: firewall enabled"

systemctl daemon-reload
systemctl enable --now xray.service
systemctl enable --now caddy.service
systemctl enable --now my-vpn-backup.timer
systemctl is-active --quiet xray.service
systemctl is-active --quiet caddy.service
ss -H -ltn | awk '{print $4}' | grep -Eq '(^|:)8443$'
if [[ "$awg_was_running" == true ]]; then
  [[ "$(docker inspect -f '{{.State.Running}}' amnezia-awg2)" == true ]]
  ss -H -lun | awk '{print $4}' | grep -Eq '(^|:)35473$'
  docker exec amnezia-awg2 sh -c \
    'if command -v awg >/dev/null; then awg show; elif command -v wg >/dev/null; then wg show; else exit 127; fi' \
    >/dev/null
else
  echo "warning: pre-existing amnezia-awg2 container was not observed; bootstrap did not modify it" >&2
fi

echo "bootstrap complete; ordinary deploys use the fixed SSH user $deploy_user"
