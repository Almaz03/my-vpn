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
caddy_config_is_pristine=false
if command -v caddy >/dev/null 2>&1; then
  had_caddy=true
  packaged_caddy_md5="$(dpkg-query -W -f='${Conffiles}\n' caddy 2>/dev/null | awk '$1 == "/etc/caddy/Caddyfile" {print $2}')"
  if [[ -n "$packaged_caddy_md5" && -f /etc/caddy/Caddyfile ]] && \
     [[ "$(md5sum /etc/caddy/Caddyfile | awk '{print $1}')" == "$packaged_caddy_md5" ]]; then
    caddy_config_is_pristine=true
  fi
  if systemctl is-active --quiet caddy.service 2>/dev/null && \
     ! grep -Eq '^[[:space:]]*import[[:space:]]+conf\.d/\*' /etc/caddy/Caddyfile && \
     [[ "$caddy_config_is_pristine" != true ]]; then
    echo "active unmanaged Caddy configuration found; refusing to overwrite it" >&2
    exit 1
  fi
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install --yes --no-install-recommends \
  age ca-certificates caddy curl jq openssl sqlite3 sudo ufw unzip
echo "bootstrap phase: packages installed"

# One-time destructive migration requested by the owner: retain a root-only
# recovery copy, then remove the complete AmneziaWG data plane and old portal
# state so every INCY device is provisioned from scratch.
migration_marker=/etc/my-vpn/.fresh-incy-vless-v1
migration_backup=/var/backups/my-vpn/pre-incy-vless-v1
if [[ ! -f "$migration_marker" ]]; then
  install -d -m 0700 -o root -g root "$migration_backup"
  systemctl stop my-vpn.service >/dev/null 2>&1 || true
  if [[ -d /var/lib/my-vpn && ! -f "$migration_backup/my-vpn-state.tar.gz" ]]; then
    tar -C /var/lib -czf "$migration_backup/my-vpn-state.tar.gz" my-vpn
    chmod 0600 "$migration_backup/my-vpn-state.tar.gz"
  fi
  if command -v docker >/dev/null 2>&1 && docker inspect amnezia-awg2 >/dev/null 2>&1; then
    docker inspect amnezia-awg2 > "$migration_backup/amnezia-awg2.inspect.json"
    docker cp amnezia-awg2:/opt/amnezia/awg/awg0.conf "$migration_backup/awg0.conf" >/dev/null 2>&1 || true
    chmod 0600 "$migration_backup"/*
    docker rm --force amnezia-awg2 >/dev/null
  fi
  rm -rf -- /var/lib/my-vpn/amneziawg
  rm -f -- /var/lib/my-vpn/my-vpn.db /var/lib/my-vpn/my-vpn.db-shm /var/lib/my-vpn/my-vpn.db-wal
  rm -f -- /etc/my-vpn/amneziawg.env /usr/local/libexec/my-vpn/amneziawg-helper
  ufw --force delete allow 35473/udp >/dev/null 2>&1 || true
  echo "bootstrap phase: AmneziaWG removed and recovery backup retained"
fi

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
xray_version_output="$(/usr/local/bin/xray version)"
grep -Fq "Xray ${xray_version}" <<<"$xray_version_output"

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
    api: {tag: "api", services: ["HandlerService"]},
    inbounds: [{
      tag: "my-vpn-reality",
      listen: "0.0.0.0",
      port: 443,
      protocol: "vless",
      settings: {clients: [], decryption: "none"},
      streamSettings: {
        network: "raw",
        security: "reality",
        realitySettings: {
          show: false,
          dest: "127.0.0.1:8444",
          xver: 0,
          serverNames: ["tcp.vpn.akalmaz.tech"],
          privateKey: $private_key,
          shortIds: [$short_id]
        }
      },
      sniffing: {enabled: true, destOverride: ["http", "tls", "quic"], routeOnly: true}
    }, {
      tag: "api-in",
      listen: "127.0.0.1",
      port: 10085,
      protocol: "dokodemo-door",
      settings: {address: "127.0.0.1"}
    }],
    outbounds: [
      {tag: "direct", protocol: "freedom"},
      {tag: "blocked", protocol: "blackhole"}
    ],
    routing: {
      domainStrategy: "IPIfNonMatch",
      rules: [
        {type: "field", inboundTag: ["api-in"], outboundTag: "api"},
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
    printf 'XRAY_SERVER=tcp.vpn.akalmaz.tech\n'
    printf 'XRAY_PORT=443\n'
    printf 'XRAY_PUBLIC_KEY=%s\n' "$public_key"
    printf 'XRAY_SHORT_ID=%s\n' "$short_id"
    printf 'XRAY_SNI=tcp.vpn.akalmaz.tech\n'
    printf 'XRAY_FLOW=xtls-rprx-vision\n'
    printf 'XRAY_CLIENT_HELPER=/usr/local/libexec/my-vpn/reality-helper\n'
  } > /etc/my-vpn/xray-client.env
  chown root:"$app_user" /etc/my-vpn/xray-client.env
  chmod 0640 /etc/my-vpn/xray-client.env
else
  # Migrate the managed data plane from the frequently filtered high port to
  # TCP/443 without rotating Reality keys or existing device UUIDs.
  current_port="$(jq -r '.inbounds[] | select(.tag == "my-vpn-reality") | .port' /etc/xray/config.json)"
  if [[ "$current_port" == 8443 ]]; then
    cp -a /etc/xray/config.json "/etc/xray/config.json.pre-443.$(date -u +%Y%m%dT%H%M%SZ)"
    jq '
      (.inbounds[] | select(.tag == "my-vpn-reality") | .port) = 443 |
      (.inbounds[] | select(.tag == "my-vpn-reality") | .streamSettings.realitySettings.dest) = "127.0.0.1:8444"
    ' /etc/xray/config.json > "$install_tmp/xray-config.json"
    install -m 0640 -o "$xray_user" -g "$xray_user" \
      "$install_tmp/xray-config.json" /etc/xray/config.json
    sed -i 's/^XRAY_PORT=8443$/XRAY_PORT=443/' /etc/my-vpn/xray-client.env
  fi
fi

# The Reality transport connects to the server IP directly, while the owned
# domain remains the SNI. This mirrors the known-good INCY configuration and
# avoids depending on a mobile carrier's DNS before the tunnel is established.
reality_server_ipv4="$(getent ahostsv4 tcp.vpn.akalmaz.tech | awk '$2 == "STREAM" {print $1; exit}')"
[[ "$reality_server_ipv4" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
sed -i -E "s/^XRAY_SERVER=.*/XRAY_SERVER=${reality_server_ipv4}/" /etc/my-vpn/xray-client.env

# Add the loopback-only HandlerService API to installations created before the
# no-restart provisioning path. Public traffic never reaches this listener.
if ! jq -e '
  .api.tag == "api" and
  ([.inbounds[] | select(.tag == "api-in" and .listen == "127.0.0.1" and .port == 10085)] | length) == 1 and
  ([.outbounds[] | select(.tag == "api")] | length) == 0 and
  ([.routing.rules[] | select(.outboundTag == "api" and ((.inboundTag // []) | index("api-in")))] | length) == 1
' /etc/xray/config.json >/dev/null; then
  cp -a /etc/xray/config.json "/etc/xray/config.json.pre-runtime-api.$(date -u +%Y%m%dT%H%M%SZ)"
  jq '
    .api = {tag: "api", services: ["HandlerService"]} |
    .inbounds = ([.inbounds[] | select(.tag != "api-in")] + [{
      tag: "api-in", listen: "127.0.0.1", port: 10085,
      protocol: "dokodemo-door", settings: {address: "127.0.0.1"}
    }]) |
    .outbounds = [.outbounds[] | select(.tag != "api")] |
    .routing.rules = [{type: "field", inboundTag: ["api-in"], outboundTag: "api"}] +
      [.routing.rules[] | select(((.inboundTag // []) | index("api-in")) | not)]
  ' /etc/xray/config.json > "$install_tmp/xray-runtime-api.json"
  /usr/local/bin/xray run -test -config "$install_tmp/xray-runtime-api.json" >/dev/null
  install -m 0640 -o "$xray_user" -g "$xray_user" \
    "$install_tmp/xray-runtime-api.json" /etc/xray/config.json
fi
test -f /etc/my-vpn/xray-client.env
test "$(jq -r '.inbounds[] | select(.tag == "my-vpn-reality") | .port' /etc/xray/config.json)" = 443
test "$(jq -r '.inbounds[] | select(.tag == "my-vpn-reality") | .streamSettings.realitySettings.dest' /etc/xray/config.json)" = 127.0.0.1:8444
grep -Fxq 'XRAY_PORT=443' /etc/my-vpn/xray-client.env
/usr/local/bin/xray run -test -config /etc/xray/config.json >/dev/null
echo "bootstrap phase: Xray configured"

install -d -m 0755 -o root -g root /etc/caddy/conf.d
install -d -m 0750 -o caddy -g caddy /var/log/caddy
if ! grep -Eq '^[[:space:]]*import[[:space:]]+conf\.d/\*' /etc/caddy/Caddyfile; then
  if [[ "$had_caddy" == true && "$caddy_config_is_pristine" != true ]]; then
    echo "existing Caddy installation lacks the managed import; refusing to replace it" >&2
    exit 1
  fi
  install -m 0644 -o root -g root /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.pre-my-vpn.$(date -u +%Y%m%dT%H%M%SZ)"
  printf 'import conf.d/*\n' > /etc/caddy/Caddyfile
fi
install -m 0644 -o root -g root "$bundle_root/deploy/Caddyfile" /etc/caddy/conf.d/my-vpn.caddy
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
echo "bootstrap phase: Caddy configured"

ufw allow "$ssh_port/tcp" comment 'SSH managed outside my-vpn'
ufw allow 80/tcp comment 'my-vpn ACME HTTP challenge and redirect'
ufw allow 443/tcp comment 'my-vpn HTTPS and VLESS Reality'
ufw --force delete allow 8443/tcp >/dev/null 2>&1 || true
if ip link show tailscale0 >/dev/null 2>&1; then
  ufw allow in on tailscale0 comment 'Tailscale management'
fi
ufw default deny incoming
ufw default allow outgoing
ufw --force enable
echo "bootstrap phase: firewall enabled"

systemctl daemon-reload
systemctl enable caddy.service xray.service
# Caddy must release public 443 and start its internal TLS listener before
# Xray takes ownership of public 443 and forwards ordinary HTTPS to Caddy.
systemctl restart caddy.service
systemctl restart xray.service
systemctl enable --now my-vpn-backup.timer
systemctl is-active --quiet xray.service
systemctl is-active --quiet caddy.service
for _ in {1..30}; do
  if bash -c 'exec 3<>/dev/tcp/127.0.0.1/10085' 2>/dev/null &&
    ss -H -ltn | awk '{print $4}' | grep -Eq '(^|:)443$' &&
    ss -H -ltn | awk '{print $4}' | grep -Eq '(^|:)8444$'; then
    listeners_ready=true
    break
  fi
  sleep 1
done
if [[ "${listeners_ready:-false}" != true ]]; then
  systemctl --no-pager --full status xray.service caddy.service >&2 || true
  journalctl --no-pager -n 80 -u xray.service -u caddy.service >&2 || true
  exit 1
fi
! command -v docker >/dev/null 2>&1 || ! docker inspect amnezia-awg2 >/dev/null 2>&1
install -m 0600 -o root -g root /dev/null "$migration_marker"

echo "bootstrap complete; ordinary deploys use the fixed SSH user $deploy_user"
