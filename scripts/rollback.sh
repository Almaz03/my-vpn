#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 VERSION" >&2
  exit 2
fi
if [[ "$EUID" -ne 0 ]]; then
  echo "rollback.sh must run as root" >&2
  exit 1
fi

version="$1"
if [[ ! "$version" =~ ^[0-9a-f]{40}$ ]]; then
  echo "invalid release version" >&2
  exit 2
fi

base=/opt/my-vpn
target="$base/releases/$version"
config_file=/etc/my-vpn/my-vpn.env
config_history=/etc/my-vpn/releases

verify_release() {
  local dir="$1"
  local expected_version="$2"
  test -x "$dir/my-vpn"
  test "$(tr -d '\n' < "$dir/VERSION")" = "$expected_version"
  grep -Eq '^[0-9a-f]{64}$' "$dir/.artifact-sha256"
  (
    cd "$dir"
    sha256sum --check MANIFEST.sha256
  )
}

install_caddy() {
  local dir="$1"
  install -m 0644 -o root -g root "$dir/deploy/Caddyfile" /etc/caddy/conf.d/my-vpn.caddy
  caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
}

install_operational_assets() {
  local dir="$1"
  install -m 0644 -o root -g root "$dir/deploy/my-vpn.service" /etc/systemd/system/my-vpn.service
  install -d -m 0755 -o root -g root /usr/local/libexec/my-vpn
  install -m 0755 -o root -g root "$dir/scripts/backup.sh" /usr/local/libexec/my-vpn/backup.sh
  install -m 0755 -o root -g root "$dir/scripts/restore-backup.sh" /usr/local/libexec/my-vpn/restore-backup.sh
  install -m 0755 -o root -g root "$dir/scripts/rollback.sh" /usr/local/libexec/my-vpn/rollback.sh
  install -m 0755 -o root -g root "$dir/scripts/deactivate-release.sh" /usr/local/libexec/my-vpn/deactivate-release.sh
  install -m 0644 -o root -g root "$dir/deploy/my-vpn-backup.service" /etc/systemd/system/my-vpn-backup.service
  install -m 0644 -o root -g root "$dir/deploy/my-vpn-backup.timer" /etc/systemd/system/my-vpn-backup.timer
}

wait_healthy() {
  for _ in {1..20}; do
    if curl --fail --silent --show-error --max-time 2 http://127.0.0.1:8080/healthz >/dev/null; then
      return 0
    fi
    sleep 1
  done
  return 1
}

verify_release "$target" "$version"
test -f "$config_history/$version.env"

test -L "$base/current"
previous="$(readlink -f "$base/current" || true)"
test -n "$previous"
test -d "$previous"
previous_version="$(basename "$previous")"
if [[ ! "$previous_version" =~ ^[0-9a-f]{40}$ ]]; then
  echo "existing current release does not use a full commit SHA" >&2
  exit 1
fi
verify_release "$previous" "$previous_version"
install -m 0600 -o root -g my-vpn "$config_file" "$config_history/$previous_version.env"

if ! install_caddy "$target"; then
  install_caddy "$previous"
  echo "rollback target Caddy configuration failed validation" >&2
  exit 1
fi
install_operational_assets "$target"

next_link="$base/.rollback-$version"
rm -f "$next_link"
ln -s "$target" "$next_link"
mv -Tf "$next_link" "$base/current"
install -m 0600 -o root -g my-vpn "$config_history/$version.env" "$config_file"
systemctl daemon-reload
systemctl enable my-vpn.service my-vpn-backup.timer >/dev/null
systemctl reload caddy.service
systemctl restart my-vpn.service

if wait_healthy; then
  echo "rolled back to $version"
  exit 0
fi

echo "rollback target failed health check; restoring prior release" >&2
install_caddy "$previous"
install_operational_assets "$previous"
restore_link="$base/.restore-$previous_version"
rm -f "$restore_link"
ln -s "$previous" "$restore_link"
mv -Tf "$restore_link" "$base/current"
install -m 0600 -o root -g my-vpn "$config_history/$previous_version.env" "$config_file"
systemctl daemon-reload
systemctl reload caddy.service
systemctl restart my-vpn.service
wait_healthy || echo "prior release also failed health check" >&2
exit 1
