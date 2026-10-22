#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: rollback.sh VERSION" >&2
  exit 2
fi
if [[ "$EUID" -ne 0 ]]; then
  echo "rollback.sh must run as root" >&2
  exit 1
fi

version="$1"
[[ "$version" =~ ^[0-9a-f]{40}$ ]] || { echo "invalid release version" >&2; exit 2; }
base=/opt/my-vpn
target="$base/releases/$version"
config_file=/etc/my-vpn/my-vpn.env
config_history=/etc/my-vpn/releases

verify_release() {
  local dir="$1" expected_version="$2"
  test -x "$dir/my-vpn"
  test "$(tr -d '\n' < "$dir/VERSION")" = "$expected_version"
  grep -Eq '^[0-9a-f]{64}$' "$dir/.artifact-sha256"
  (cd "$dir" && sha256sum --check MANIFEST.sha256)
}
wait_healthy() {
  for _ in {1..20}; do
    curl --fail --silent --show-error --max-time 2 http://127.0.0.1:8080/healthz >/dev/null && return 0
    sleep 1
  done
  return 1
}

verify_release "$target" "$version"
test -f "$config_history/$version.env"
test -L "$base/current"
previous="$(readlink -f "$base/current")"
test -n "$previous" -a -d "$previous"
previous_version="$(basename "$previous")"
[[ "$previous_version" =~ ^[0-9a-f]{40}$ ]]
verify_release "$previous" "$previous_version"
install -m 0640 -o root -g my-vpn "$config_file" "$config_history/$previous_version.env"

next_link="$base/.rollback-$version"
rm -f "$next_link"
ln -s "$target" "$next_link"
mv -Tf "$next_link" "$base/current"
install -m 0640 -o root -g my-vpn "$config_history/$version.env" "$config_file"
systemctl restart my-vpn.service
if wait_healthy; then
  echo "rolled back to $version"
  exit 0
fi

echo "rollback target failed health check; restoring prior release" >&2
restore_link="$base/.restore-$previous_version"
rm -f "$restore_link"
ln -s "$previous" "$restore_link"
mv -Tf "$restore_link" "$base/current"
install -m 0640 -o root -g my-vpn "$config_history/$previous_version.env" "$config_file"
systemctl restart my-vpn.service
wait_healthy || echo "prior release also failed health check" >&2
exit 1
