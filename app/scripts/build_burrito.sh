#!/bin/sh
# Run through the pinned toolchain: mise x -- sh scripts/build_burrito.sh [target]
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
[ "$#" -le 1 ] || { echo "usage: $0 [linux_x86_64|linux_arm64|macos_x86_64|macos_arm64]" >&2; exit 64; }
case "${1-}" in
  '') targets='linux_x86_64 linux_arm64 macos_x86_64 macos_arm64'; unset BURRITO_TARGET ;;
  linux_x86_64|linux_arm64|macos_x86_64|macos_arm64) targets=$1; export BURRITO_TARGET=$1 ;;
  *) echo 'Unsupported target' >&2; exit 64 ;;
esac
[ "$(zig version)" = 0.16.0 ] || { echo 'The pinned Burrito revision requires Zig 0.16.0 on PATH' >&2; exit 69; }
command -v xz >/dev/null
export MIX_ENV=prod
mix deps.get --only prod
mix burrito
mkdir -p dist
stage=$(mktemp -d "${TMPDIR:-/tmp}/triage-bundle.XXXXXX")
trap 'rm -rf "$stage"' EXIT HUP INT TERM
for target in $targets; do
  bundle="triage-$target"
  mkdir "$stage/$bundle"
  cp "burrito_out/triage_burrito_$target" "$stage/$bundle/triage"
  chmod 755 "$stage/$bundle/triage"
  cp docs/BURRITO.md "$stage/$bundle/README.md"
  cp deploy/burrito.env.example "$stage/$bundle/triage.env.example"
  cp deploy/Caddyfile.example "$stage/$bundle/Caddyfile.example"
  cp docs/DEPLOYMENT.md "$stage/$bundle/DEPLOYMENT.md"
  tar -czf "dist/$bundle.tar.gz" -C "$stage" "$bundle"
  (cd dist && shasum -a 256 "$bundle.tar.gz" > "$bundle.tar.gz.sha256")
done
printf 'Portable bundles are in %s/dist (database and TLS proxy are not bundled).\n' "$root"
