#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 VERSION" >&2
  exit 2
fi
if [[ "$EUID" -ne 0 ]]; then
  echo "deactivate-release.sh must run as root" >&2
  exit 1
fi

version="$1"
if [[ ! "$version" =~ ^[0-9a-f]{40}$ ]]; then
  echo "invalid release version" >&2
  exit 2
fi

base=/opt/my-vpn
if [[ -L "$base/current" ]]; then
  current="$(readlink -f "$base/current")"
  if [[ "$(basename "$current")" != "$version" ]]; then
    echo "refusing to deactivate a different current release" >&2
    exit 1
  fi
fi

systemctl disable --now my-vpn.service >/dev/null 2>&1 || true
rm -f "$base/current"

echo "deactivated failed first release $version"
