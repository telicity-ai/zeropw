#!/bin/sh
# Build the product binaries the app ships beside its executable (docs/desktop-app.md §2:
# zeropw-admin, zeropw_session, zeropw-agent) from rust/ in release mode, and copy them to
# desktop/src-tauri/binaries/<name>-<target triple>, where
# `tauri build --config src-tauri/tauri.bundle.conf.json` (npm run bundle) picks them up as
# `bundle.externalBin`. The bundler strips the triple and places them next to the app
# executable (Contents/MacOS on macOS), which is where the app looks for them.
#
# Usage: scripts/prepare-sidecars.sh [target-triple]   (default: the host triple)
# Honors CARGO_TARGET_DIR. Like any build of product code, run it on a development machine
# or CI, never on a host that holds real vault or administrator keys.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
desktop=$(dirname "$here")
root=$(dirname "$desktop")
manifest="$root/rust/Cargo.toml"
host=$(rustc -vV | sed -n 's/^host: //p')
triple=${1:-${TAURI_ENV_TARGET_TRIPLE:-$host}}
case "$triple" in
  *[!A-Za-z0-9_.-]*|'') echo "prepare-sidecars: bad target triple" >&2; exit 2 ;;
esac
target_dir=${CARGO_TARGET_DIR:-$root/rust/target}

if [ "$triple" = "$host" ]; then
  cargo build --locked --release --manifest-path "$manifest" \
    --bin zeropw-admin --bin zeropw_session --bin zeropw-agent
  out="$target_dir/release"
else
  cargo build --locked --release --manifest-path "$manifest" --target "$triple" \
    --bin zeropw-admin --bin zeropw_session --bin zeropw-agent
  out="$target_dir/$triple/release"
fi

dest="$desktop/src-tauri/binaries"
mkdir -p "$dest"
for name in zeropw-admin zeropw_session zeropw-agent; do
  cp "$out/$name" "$dest/$name-$triple"
  chmod 755 "$dest/$name-$triple"
  echo "prepare-sidecars: $dest/$name-$triple"
done
