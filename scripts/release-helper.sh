#!/usr/bin/env bash
set -euo pipefail

if [[ "$EUID" -ne 0 ]]; then
  echo "my-vpn-release must run as root" >&2
  exit 1
fi

command_name="${1:-}"
version="${2:-}"
incoming_root=/var/lib/my-vpn-deploy/incoming

validate_version() {
  [[ "$1" =~ ^[0-9a-f]{40}$ ]] || {
    echo "invalid release version" >&2
    exit 2
  }
}

case "$command_name" in
  current)
    [[ $# -eq 1 ]] || exit 2
    if [[ -L /opt/my-vpn/current ]]; then
      current="$(readlink -f /opt/my-vpn/current)"
      current_version="$(basename "$current")"
      validate_version "$current_version"
      printf '%s\n' "$current_version"
    fi
    ;;
  preflight)
    [[ $# -eq 1 ]] || exit 2
    command -v caddy >/dev/null
    command -v sqlite3 >/dev/null
    command -v openssl >/dev/null
    command -v curl >/dev/null
    command -v age >/dev/null
    command -v xray >/dev/null
    systemctl is-active --quiet caddy.service
    systemctl is-active --quiet xray.service
    test -x /usr/local/libexec/my-vpn/install-release.sh
    test -x /usr/local/libexec/my-vpn/rollback.sh
    test -x /usr/local/libexec/my-vpn/deactivate-release.sh
    test -x /usr/local/libexec/my-vpn/application-canary.sh
    test -x /usr/local/libexec/my-vpn/reality-canary.sh
    test -f /etc/my-vpn/xray-client.env
    ;;
  install)
    [[ $# -eq 2 ]] || exit 2
    validate_version "$version"
    incoming="$incoming_root/$version"
    artifact="$incoming/my-vpn-$version.tar.gz"
    checksum="$artifact.sha256"
    runtime_env="$incoming/runtime.env"
    test "$(stat -c %U "$incoming")" = my-vpn-deploy
    test -f "$artifact" -a ! -L "$artifact"
    test -f "$checksum" -a ! -L "$checksum"
    test -f "$runtime_env" -a ! -L "$runtime_env"
    /usr/local/libexec/my-vpn/install-release.sh \
      "$version" "$artifact" "$checksum" "$runtime_env"
    ;;
  rollback)
    [[ $# -eq 2 ]] || exit 2
    validate_version "$version"
    /usr/local/libexec/my-vpn/rollback.sh "$version"
    ;;
  deactivate)
    [[ $# -eq 2 ]] || exit 2
    validate_version "$version"
    /usr/local/libexec/my-vpn/deactivate-release.sh "$version"
    ;;
  backup)
    [[ $# -eq 1 ]] || exit 2
    /usr/local/libexec/my-vpn/backup.sh
    ;;
  canary)
    [[ $# -eq 1 ]] || exit 2
    /usr/local/libexec/my-vpn/reality-canary.sh
    /usr/local/libexec/my-vpn/application-canary.sh
    ;;
  *)
    echo "usage: my-vpn-release {current|preflight|install VERSION|rollback VERSION|deactivate VERSION|backup|canary}" >&2
    exit 2
    ;;
esac
