#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: install-release.sh VERSION ARTIFACT CHECKSUM RUNTIME_ENV" >&2
  exit 2
fi
if [[ "$EUID" -ne 0 ]]; then
  echo "install-release.sh must run as root" >&2
  exit 1
fi

version="$1"
artifact="$2"
checksum="$3"
runtime_env="$4"
[[ "$version" =~ ^[0-9a-f]{40}$ ]] || { echo "invalid release version" >&2; exit 2; }

base=/opt/my-vpn
release_dir="$base/releases/$version"
incoming="$base/.incoming-$version"
config_dir=/etc/my-vpn
config_file="$config_dir/my-vpn.env"
config_history="$config_dir/releases"
state_dir=/var/lib/my-vpn
previous=""
previous_version=""

for path in "$artifact" "$checksum" "$runtime_env"; do
  test -f "$path" -a ! -L "$path"
done
test -x /usr/local/sbin/my-vpn-release
test -f /etc/my-vpn/xray-client.env
test -f /etc/systemd/system/my-vpn.service
test -f /etc/caddy/conf.d/my-vpn.caddy

expected_sha="$(awk 'NF == 2 && $1 ~ /^[0-9a-f]{64}$/ {print $1}' "$checksum")"
[[ "$expected_sha" =~ ^[0-9a-f]{64}$ ]]
safe_artifact="$(mktemp /var/lib/my-vpn/.release-artifact.XXXXXX.tar.gz)"
trap 'rm -f "$safe_artifact"' EXIT
install -m 0600 -o root -g root "$artifact" "$safe_artifact"
artifact="$safe_artifact"
artifact_sha="$(sha256sum "$artifact" | awk '{print $1}')"
[[ "$artifact_sha" == "$expected_sha" ]]

install -d -m 0755 -o root -g root "$base" "$base/releases"
install -d -m 0750 -o my-vpn -g my-vpn "$state_dir"
install -d -m 0750 -o root -g my-vpn "$config_dir" "$config_history"

if [[ -L "$base/current" ]]; then
  previous="$(readlink -f "$base/current" || true)"
  test -n "$previous" -a -d "$previous"
  previous_version="$(basename "$previous")"
  [[ "$previous_version" =~ ^[0-9a-f]{40}$ ]]
  test -x "$previous/my-vpn"
  test "$(tr -d '\n' < "$previous/VERSION")" = "$previous_version"
  grep -Eq '^[0-9a-f]{64}$' "$previous/.artifact-sha256"
  (cd "$previous" && sha256sum --check MANIFEST.sha256)
  if [[ -f "$config_file" ]]; then
    install -m 0640 -o root -g my-vpn "$config_file" "$config_history/$previous_version.env"
  fi
elif [[ -e "$base/current" ]]; then
  echo "existing current path is not a symbolic link" >&2
  exit 1
fi

rm -rf "$incoming"
install -d -m 0755 -o root -g root "$incoming"

# Reject links and traversal before extraction. Releases may contain only the
# unprivileged application binary, web assets, migrations, and metadata.
while IFS= read -r member; do
  member="${member#./}"
  [[ -n "$member" ]] || continue
  [[ "$member" != /* && "$member" != *".."* ]] || {
    echo "unsafe archive member: $member" >&2
    exit 1
  }
  case "$member" in
    my-vpn|VERSION|MANIFEST.sha256|web|web/*|migrations|migrations/*) ;;
    *) echo "unexpected archive member: $member" >&2; exit 1 ;;
  esac
done < <(tar --absolute-names -tzf "$artifact")
if tar --absolute-names -tvzf "$artifact" | awk '$1 !~ /^[-d]/ {bad=1} END {exit !bad}'; then
  echo "release archive contains a link, device, socket, or other unsupported type" >&2
  exit 1
fi
tar -xzf "$artifact" -C "$incoming" --no-same-owner --no-same-permissions
test -x "$incoming/my-vpn"
test -s "$incoming/web/index.html"
test "$(tr -d '\n' < "$incoming/VERSION")" = "$version"
(cd "$incoming" && sha256sum --check MANIFEST.sha256)
rm -f "$safe_artifact"
trap - EXIT

if [[ -e "$release_dir" ]]; then
  test -d "$release_dir"
  test "$(tr -d '\n' < "$release_dir/.artifact-sha256")" = "$artifact_sha"
  (cd "$release_dir" && sha256sum --check MANIFEST.sha256)
  rm -rf "$incoming"
else
  printf '%s\n' "$artifact_sha" > "$incoming/.artifact-sha256"
  mv "$incoming" "$release_dir"
fi
chown -R root:root "$release_dir"
find "$release_dir" -type d -exec chmod 0755 {} +
find "$release_dir" -type f -exec chmod 0644 {} +
chmod 0755 "$release_dir/my-vpn"

if [[ -f "$state_dir/my-vpn.db" && -f "$config_file" ]]; then
  /usr/local/libexec/my-vpn/backup.sh >/dev/null
fi

new_env="$(mktemp "$config_dir/.my-vpn.env.XXXXXX")"
trap 'rm -f "$new_env"' EXIT
while IFS='=' read -r name value; do
  case "$name" in
    APP_LISTEN|APP_DB_PATH|PUBLIC_BASE_URL|WEB_ROOT|PROVISIONER_MODE|TELEGRAM_BOT_TOKEN|TELEGRAM_ADMIN_IDS)
      printf '%s=%s\n' "$name" "$value" >> "$new_env"
      ;;
    ''|'#'*) ;;
    *) echo "unsupported runtime setting: $name" >&2; exit 1 ;;
  esac
done < "$runtime_env"
for required in APP_LISTEN APP_DB_PATH PUBLIC_BASE_URL WEB_ROOT PROVISIONER_MODE TELEGRAM_BOT_TOKEN TELEGRAM_ADMIN_IDS; do
  grep -Eq "^${required}=.+" "$new_env" || { echo "missing runtime setting: $required" >&2; exit 1; }
done
grep -Fxq 'APP_LISTEN=127.0.0.1:8080' "$new_env"
grep -Fxq 'APP_DB_PATH=/var/lib/my-vpn/my-vpn.db' "$new_env"
grep -Fxq 'PUBLIC_BASE_URL=https://vpn.akalmaz.tech' "$new_env"
grep -Fxq 'WEB_ROOT=/opt/my-vpn/current/web' "$new_env"
grep -Fxq 'PROVISIONER_MODE=vless-reality' "$new_env"

preserve_or_generate() {
  local name="$1"
  local generated="$2"
  local value=""
  if [[ -f "$config_file" ]]; then
    value="$(sed -n "s/^${name}=//p" "$config_file" | tail -n 1)"
  fi
  [[ -n "$value" ]] || value="$generated"
  printf '%s=%s\n' "$name" "$value" >> "$new_env"
}
preserve_or_generate INVITE_HMAC_KEY "$(openssl rand -base64 48 | tr -d '\n')"
preserve_or_generate ADMIN_API_TOKEN "$(openssl rand -hex 32)"
chown root:my-vpn "$new_env"
chmod 0640 "$new_env"
mv -f "$new_env" "$config_file"
install -m 0640 -o root -g my-vpn "$config_file" "$config_history/$version.env"
trap - EXIT

next_link="$base/.current-$version"
rm -f "$next_link"
ln -s "$release_dir" "$next_link"
mv -Tf "$next_link" "$base/current"

systemctl daemon-reload
systemctl enable my-vpn.service >/dev/null
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
    /usr/local/libexec/my-vpn/rollback.sh "$previous_version" || true
  else
    /usr/local/libexec/my-vpn/deactivate-release.sh "$version" || true
  fi
  exit 1
fi

systemctl reload caddy.service
echo "installed release $version"
