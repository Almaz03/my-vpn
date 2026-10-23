#!/usr/bin/env bash
set -euo pipefail

reset_marker=/etc/my-vpn/.fresh-hiddify-dual-edge-v1
bootstrap_error() {
  local exit_code=$?
  printf 'edge bootstrap failed at line %s status=%s\n' "${BASH_LINENO[0]}" "$exit_code" >&2
  exit "$exit_code"
}
trap bootstrap_error ERR

[[ "$EUID" -eq 0 ]] || exit 1
[[ $# -eq 3 ]] || { echo "usage: bootstrap-edge-server.sh SSH_PORT EDGE_IP EDGE_SNI" >&2; exit 2; }
ssh_port="$1"
edge_ip="$2"
edge_sni="$3"
[[ "$ssh_port" =~ ^[0-9]{1,5}$ ]] && ((ssh_port >= 1 && ssh_port <= 65535)) || exit 2
[[ "$edge_ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || exit 2
[[ "$edge_sni" =~ ^[a-z0-9.-]+$ && "$edge_sni" == *.* ]] || exit 2

xray_version=26.3.27
xray_sha256=23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae
bundle_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
deploy_key="$bundle_root/deploy-authorized-key.pub"
for path in "$deploy_key" "$bundle_root/deploy/xray.service" "$bundle_root/deploy/edge.Caddyfile" "$bundle_root/deploy/my-vpn-edge.sudoers" "$bundle_root/scripts/edge-user-helper.sh"; do test -f "$path"; done
ssh-keygen -lf "$deploy_key" >/dev/null

caddy_preexisting=false
if command -v caddy >/dev/null 2>&1; then
  caddy_preexisting=true
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install --yes --no-install-recommends ca-certificates caddy curl jq openssl sudo ufw unzip

id xray >/dev/null 2>&1 || useradd --system --home-dir /var/lib/xray --shell /usr/sbin/nologin xray
id my-vpn-deploy >/dev/null 2>&1 || useradd --create-home --shell /bin/bash my-vpn-deploy
passwd --lock my-vpn-deploy >/dev/null
deploy_home="$(getent passwd my-vpn-deploy | cut -d: -f6)"
install -d -m 0700 -o my-vpn-deploy -g my-vpn-deploy "$deploy_home/.ssh"
install -m 0600 -o my-vpn-deploy -g my-vpn-deploy "$deploy_key" "$deploy_home/.ssh/authorized_keys"

work="$(mktemp -d /tmp/my-vpn-edge.XXXXXX)"
trap 'rm -rf "$work"' EXIT
curl --fail --location --proto '=https' --tlsv1.2 -o "$work/xray.zip" "https://github.com/XTLS/Xray-core/releases/download/v${xray_version}/Xray-linux-64.zip"
printf '%s  %s\n' "$xray_sha256" "$work/xray.zip" | sha256sum --check -
unzip -q "$work/xray.zip" xray geoip.dat geosite.dat -d "$work"
install -m 0755 -o root -g root "$work/xray" /usr/local/bin/xray
grep -Fq "Xray ${xray_version}" <<<"$(xray version)"

install -d -m 0750 -o xray -g xray /etc/xray /var/lib/xray
install -d -m 0750 -o root -g root /etc/my-vpn
install -d -m 0755 -o root -g root /usr/local/libexec/my-vpn /usr/local/share/xray
install -m 0644 "$work/geoip.dat" "$work/geosite.dat" /usr/local/share/xray/
install -m 0755 "$bundle_root/scripts/edge-user-helper.sh" /usr/local/libexec/my-vpn/edge-user-helper
install -m 0644 "$bundle_root/deploy/xray.service" /etc/systemd/system/xray.service
install -m 0440 "$bundle_root/deploy/my-vpn-edge.sudoers" /etc/sudoers.d/my-vpn-edge
visudo -cf /etc/sudoers.d/my-vpn-edge

if [[ ! -f /etc/xray/.managed-by-my-vpn-edge ]]; then
  [[ ! -e /etc/xray/config.json ]] || { echo 'unmanaged Xray configuration exists' >&2; exit 1; }
  key_output="$(xray x25519)"
  private_key="$(sed -n 's/^PrivateKey: //p' <<<"$key_output")"
  public_key="$(sed -n 's/^Password (PublicKey): //p' <<<"$key_output")"
  short_id="$(openssl rand -hex 8)"
  jq -n --arg private_key "$private_key" --arg short_id "$short_id" --arg sni "$edge_sni" '{
    log:{loglevel:"warning"},api:{tag:"api",services:["HandlerService"]},
    inbounds:[
      {tag:"my-vpn-reality",listen:"0.0.0.0",port:443,protocol:"vless",settings:{clients:[],decryption:"none"},streamSettings:{network:"raw",security:"reality",realitySettings:{show:false,dest:"127.0.0.1:8444",xver:0,serverNames:[$sni],privateKey:$private_key,shortIds:[$short_id]}}},
      {tag:"api-in",listen:"127.0.0.1",port:10085,protocol:"dokodemo-door",settings:{address:"127.0.0.1"}}
    ],
    outbounds:[{tag:"direct",protocol:"freedom"},{tag:"blocked",protocol:"blackhole"}],
    routing:{domainStrategy:"IPIfNonMatch",rules:[{type:"field",inboundTag:["api-in"],outboundTag:"api"},{type:"field",ip:["geoip:private"],outboundTag:"blocked"},{type:"field",protocol:["bittorrent"],outboundTag:"blocked"}]}
  }' > /etc/xray/config.json
  chown xray:xray /etc/xray/config.json
  chmod 0640 /etc/xray/config.json
  printf 'XRAY_SERVER=%s\nXRAY_PORT=443\nXRAY_PUBLIC_KEY=%s\nXRAY_SHORT_ID=%s\nXRAY_SNI=%s\n' "$edge_ip" "$public_key" "$short_id" "$edge_sni" > /etc/my-vpn/edge.env
  chmod 0640 /etc/my-vpn/edge.env
  touch /etc/xray/.managed-by-my-vpn-edge
else
  grep -Fxq "XRAY_SERVER=$edge_ip" /etc/my-vpn/edge.env
  grep -Fxq "XRAY_SNI=$edge_sni" /etc/my-vpn/edge.env
fi

if [[ ! -f "$reset_marker" ]]; then
  install -d -m 0700 -o root -g root /var/backups/my-vpn-edge/pre-hiddify-dual-edge-v1
  cp -a /etc/xray/config.json /var/backups/my-vpn-edge/pre-hiddify-dual-edge-v1/xray-config.json
  reset_candidate="$(mktemp --suffix=.json /etc/xray/.reset-config.XXXXXX)"
  jq '(.inbounds[] | select(.tag == "my-vpn-reality") | .settings.clients) = []' \
    /etc/xray/config.json > "$reset_candidate"
  chown xray:xray "$reset_candidate"
  chmod 0640 "$reset_candidate"
  xray run -test -config "$reset_candidate" >/dev/null
  mv -f "$reset_candidate" /etc/xray/config.json
  install -m 0600 -o root -g root /dev/null "$reset_marker"
fi
# Keep public egress on IPv4. This avoids clients receiving an IPv6 route that
# the edge or the mobile network cannot carry consistently.
ipv4_candidate="$(mktemp --suffix=.json /etc/xray/.ipv4-config.XXXXXX)"
jq '(.outbounds[] | select(.tag == "direct") | .streamSettings.sockopt.domainStrategy) = "ForceIPv4"' \
  /etc/xray/config.json > "$ipv4_candidate"
chown xray:xray "$ipv4_candidate"
chmod 0640 "$ipv4_candidate"
xray run -test -config "$ipv4_candidate" >/dev/null
mv -f "$ipv4_candidate" /etc/xray/config.json
xray run -test -config /etc/xray/config.json >/dev/null

install -d -m 0755 /etc/caddy/conf.d
if ! grep -Eq '^[[:space:]]*import[[:space:]]+conf\.d/\*' /etc/caddy/Caddyfile; then
  if [[ "$caddy_preexisting" == true ]] && systemctl is-active --quiet caddy.service; then
    echo 'active unmanaged Caddy configuration found' >&2
    exit 1
  fi
  systemctl stop caddy.service >/dev/null 2>&1 || true
  printf 'import conf.d/*\n' > /etc/caddy/Caddyfile
fi
sed "s/{\$EDGE_SNI}/$edge_sni/g" "$bundle_root/deploy/edge.Caddyfile" > /etc/caddy/conf.d/my-vpn-edge.caddy
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile

ufw allow "$ssh_port/tcp" comment 'SSH'
ufw allow 80/tcp comment 'ACME'
ufw allow 443/tcp comment 'VLESS Reality'
ufw default deny incoming
ufw default allow outgoing
ufw --force enable
systemctl daemon-reload
systemctl enable caddy.service xray.service
systemctl restart caddy.service xray.service
systemctl is-active --quiet caddy.service
systemctl is-active --quiet xray.service
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
echo 'edge bootstrap complete'
