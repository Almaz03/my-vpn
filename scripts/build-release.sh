#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 VERSION OUTPUT_DIR" >&2
  exit 2
fi

version="$1"
output_dir="$2"

if [[ ! "$version" =~ ^[0-9a-f]{40}$ ]]; then
  echo "VERSION must be a full Git commit SHA" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

mkdir -p "$output_dir" "$stage/package"
cd "$repo_root"

CGO_ENABLED=0 go build \
  -trimpath \
  -ldflags "-s -w -X main.version=$version" \
  -o "$stage/package/my-vpn" \
  ./cmd/my-vpn

cp -a web "$stage/package/web"
if [[ -d migrations ]]; then
  cp -a migrations "$stage/package/migrations"
fi
printf '%s\n' "$version" > "$stage/package/VERSION"
find "$stage/package" -type d -exec chmod 0755 {} +
find "$stage/package" -type f -exec chmod 0644 {} +
chmod 0755 "$stage/package/my-vpn"
(
  cd "$stage/package"
  find . -type f ! -name MANIFEST.sha256 -print0 \
    | sort -z \
    | xargs -0 sha256sum > MANIFEST.sha256
)
chmod 0644 "$stage/package/MANIFEST.sha256"

artifact="$output_dir/my-vpn-$version.tar.gz"
tar --sort=name \
  --mtime='UTC 1970-01-01' \
  --owner=0 --group=0 --numeric-owner \
  -C "$stage/package" \
  -czf "$artifact" .
(
  cd "$output_dir"
  sha256sum "$(basename "$artifact")" > "$(basename "$artifact").sha256"
)
