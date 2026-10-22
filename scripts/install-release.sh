#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 5 ]]; then
  echo "usage: $0 VERSION ARTIFACT CHECKSUM RUNTIME_ENV" >&2
  exit 2
fi

version="$1"
artifact="$2"
checksum="$3"
runtime_env="$4"

if [[ "$EUID" -ne 0 ]]; then
  echo "install-release.sh must run as root" >&2
  exit 1
fi
if [[ ! "$version" =~ ^[0-9a-f]{40}$ ]]; then
  echo "invalid release version" >&2
  exit 2
fi

base=/opt/my-vpn
release_dir="$base/releases/$version"
incoming="$base/.incoming-$version"
config_dir=/etc/my-vpn
config_file="$config_dir/my-vpn.env"
config_history="$config_dir/releases"
state_dir=/var/lib/my-vpn
previous=""
previous_version=""

[[ -f "$artifact" && -f "$checksum" && -f "$runtime_env" ]]
(
  cd "$(dirname "$artifact")"
  sha256sum --check "$(basename "$checksum")"
)
artifact_sha="$(sha256sum "$artifact" | awk '{print $1}')"

if id my-vpn >/dev/null 2>&1; then
  :
else
  useradd --system --home-dir "$state_dir" --shell /usr/sbin/nologin my-vpn
fi

install -d -m 0755 -o root -g root "$base" "$base/releases"
install -d -m 0750 -o my-vpn -g my-vpn "$state_dir"
install -d -m 0750 -o root -g my-vpn "$config_dir" "$config_history"

if [[ -L "$base/current" ]]; then
  previous="$(readlink -f "$base/current" || true)"
  if [[ -z "$previous" || ! -d "$previous" ]]; then
    echo "existing current release link is dangling" >&2
    exit 1
  fi
  previous_version="$(basename "$previous")"
  if [[ ! "$previous_version" =~ ^[0-9a-f]{40}$ ]]; then
    echo "existing current release does not use a full commit SHA" >&2
    exit 1
  fi
  test -x "$previous/my-vpn"
  test "$(tr -d '\n' < "$previous/VERSION")" = "$previous_version"
  grep -Eq '^[0-9a-f]{64}$' "$previous/.artifact-sha256"
  (
    cd "$previous"
    sha256sum --check MANIFEST.sha256
  )
  if [[ -f "$config_file" ]]; then
    install -m 0600 -o root -g my-vpn "$config_file" "$config_history/$previous_version.env"
  fi
elif [[ -e "$base/current" ]]; then
  echo "existing current path is not a symbolic link" >&2
  exit 1
fi

rm -rf "$incoming"
install -d -m 0755 -o root -g root "$incoming"
tar -xzf "$artifact" -C "$incoming" --no-same-owner
test -x "$incoming/my-vpn"
test -s "$incoming/web/index.html"
test "$(tr -d '\n' < "$incoming/VERSION")" = "$version"
(
  cd "$incoming"
  sha256sum --check MANIFEST.sha256
)

if [[ -e "$release_dir" ]]; then
  test -d "$release_dir"
  test "$(tr -d '\n' < "$release_dir/.artifact-sha256")" = "$artifact_sha"
  (
    cd "$release_dir"
    sha256sum --check MANIFEST.sha256
  )
  rm -rf "$incoming"
else
  printf '%s\n' "$artifact_sha" > "$incoming/.artifact-sha256"
  mv "$incoming" "$release_dir"
fi
chown -R root:root "$release_dir"
chmod 0755 "$release_dir/my-vpn"

if [[ -f "$state_dir/my-vpn.db" && -f "$config_file" ]]; then
  bash "$release_dir/scripts/backup.sh"
fi

new_env="$(mktemp "$config_dir/.my-vpn.env.XXXXXX")"
trap 'rm -f "$new_env"' EXIT
install -m 0600 -o root -g my-vpn "$runtime_env" "$new_env"

preserve_or_generate() {
  local name="$1"
  local generated="$2"
  local value=""
  if [[ -f "$config_file" ]]; then
    value="$(sed -n "s/^${name}=//p" "$config_file" | tail -n 1)"
  fi
  if [[ -z "$value" ]]; then
    value="$generated"
  fi
  printf '%s=%s\n' "$name" "$value" >> "$new_env"
}

preserve_or_generate INVITE_HMAC_KEY "$(openssl rand -base64 48 | tr -d '\n')"
preserve_or_generate ADMIN_API_TOKEN "$(openssl rand -hex 32)"
chown root:my-vpn "$new_env"
chmod 0600 "$new_env"
mv -f "$new_env" "$config_file"
install -m 0600 -o root -g my-vpn "$config_file" "$config_history/$version.env"
trap - EXIT

install -d -m 0755 -o root -g root /etc/caddy/conf.d
install -d -m 0750 -o caddy -g caddy /var/log/caddy
install -m 0644 -o root -g root "$release_dir/deploy/Caddyfile" /etc/caddy/conf.d/my-vpn.caddy
if ! caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile; then
  if [[ -n "$previous" && -f "$previous/deploy/Caddyfile" ]]; then
    install -m 0644 -o root -g root "$previous/deploy/Caddyfile" /etc/caddy/conf.d/my-vpn.caddy
  else
    rm -f /etc/caddy/conf.d/my-vpn.caddy
  fi
  if [[ -n "$previous_version" && -f "$config_history/$previous_version.env" ]]; then
    install -m 0600 -o root -g my-vpn "$config_history/$previous_version.env" "$config_file"
  else
    rm -f "$config_file"
  fi
  rm -f "$config_history/$version.env"
  caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile || true
  echo "new Caddy configuration failed validation" >&2
  exit 1
fi

install -m 0644 -o root -g root "$release_dir/deploy/my-vpn.service" /etc/systemd/system/my-vpn.service
install -d -m 0755 -o root -g root /usr/local/libexec/my-vpn
install -m 0755 -o root -g root "$release_dir/scripts/backup.sh" /usr/local/libexec/my-vpn/backup.sh
install -m 0755 -o root -g root "$release_dir/scripts/restore-backup.sh" /usr/local/libexec/my-vpn/restore-backup.sh
install -m 0755 -o root -g root "$release_dir/scripts/rollback.sh" /usr/local/libexec/my-vpn/rollback.sh
install -m 0755 -o root -g root "$release_dir/scripts/deactivate-release.sh" /usr/local/libexec/my-vpn/deactivate-release.sh
install -m 0644 -o root -g root "$release_dir/deploy/my-vpn-backup.service" /etc/systemd/system/my-vpn-backup.service
install -m 0644 -o root -g root "$release_dir/deploy/my-vpn-backup.timer" /etc/systemd/system/my-vpn-backup.timer

next_link="$base/.current-$version"
rm -f "$next_link"
ln -s "$release_dir" "$next_link"
mv -Tf "$next_link" "$base/current"

systemctl daemon-reload
systemctl enable my-vpn.service >/dev/null
systemctl enable --now my-vpn-backup.timer >/dev/null
systemctl restart my-vpn.service

healthy=false
for _ in {1..20}; do
  if curl --fail --silent --show-error --max-time 2 http://127.0.0.1:8080/healthz >/dev/null; then
    healthy=true
    break
  fi
  sleep 1
done

if [[ "$healthy" != true ]]; then
  echo "new release failed its local health check; rolling back" >&2
  if [[ -n "$previous" && -d "$previous" ]]; then
    bash "$release_dir/scripts/rollback.sh" "$previous_version" || true
  else
    bash "$release_dir/scripts/deactivate-release.sh" "$version" || true
  fi
  exit 1
fi

systemctl reload caddy.service

echo "installed release $version"
