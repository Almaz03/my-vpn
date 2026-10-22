#!/usr/bin/env bash
set -euo pipefail

if [[ "$EUID" -ne 0 ]]; then
  echo "bootstrap-server.sh must run as root" >&2
  exit 1
fi

# This script deliberately does not alter SSH or firewall rules. Review it before
# its one-time execution on a new Ubuntu host.
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install --yes --no-install-recommends ca-certificates caddy curl openssl sqlite3

install -d -m 0755 -o root -g root /etc/caddy/conf.d
install -d -m 0750 -o caddy -g caddy /var/log/caddy
if ! grep -Eq '^[[:space:]]*import[[:space:]]+conf\.d/\*' /etc/caddy/Caddyfile; then
  printf '\nimport conf.d/*\n' >> /etc/caddy/Caddyfile
fi
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
systemctl enable --now caddy.service

echo "Bootstrap complete. SSH and firewall settings were left unchanged."
