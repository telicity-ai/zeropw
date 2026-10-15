#!/bin/sh
# Prepare what `tauri build --config src-tauri/tauri.bundle.conf.json` (npm run bundle) bundles
# beyond the web interface (docs/desktop-app.md §9):
#
# 1. The product binaries the app ships beside its executable (§2: zeropw-admin, zeropw_session,
#    zeropw-agent), built exactly like the CLI release binaries: scripts/build-release.py --bin
#    builds them from rust/ with the pinned, checksum-verified static OpenSSL 3.5.9 SDK and
#    `--features bundled-openssl`, and refuses any binary that links Homebrew or system
#    OpenSSL. They are copied to src-tauri/binaries/<name>-<target triple>, which
#    `bundle.externalBin` picks up; the bundler strips the triple and places them next to the
#    app executable (Contents/MacOS on macOS), which is where the app looks for them.
# 2. src-tauri/notices/THIRD_PARTY_LICENSES.md (scripts/third-party-licenses.py): notices for
#    the desktop app's Rust dependencies, the sidecars' dependencies and OpenSSL, and the npm
#    packages bundled into the web interface. `bundle.resources` ships it with LICENSE.
#    Needs `npm ci` first (it reads node_modules) and fetches the desktop crates.
#
# Usage: scripts/prepare-sidecars.sh [target-triple]   (default: the host triple; the release
# builder refuses any other). The sidecar build lives in ${CARGO_TARGET_DIR:-rust/target}/
# sidecars-<triple>, which build-release.py owns: it must be new, empty or left by an earlier
# run. build-release.py builds with its allowlisted environment and remaps local source paths
# out of the binaries (see its docstring). Like any build of product code, run it on a
# development machine or CI, never on a host that holds real vault, signing or administrator
# keys.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
desktop=$(dirname "$here")
root=$(dirname "$desktop")
host=$(rustc -vV | sed -n 's/^host: //p')
triple=${1:-$host}
case "$triple" in
  *[!A-Za-z0-9_.-]*|'') echo "prepare-sidecars: bad target triple" >&2; exit 2 ;;
esac
work=${CARGO_TARGET_DIR:-$root/rust/target}/sidecars-$triple
names="zeropw-admin zeropw_session zeropw-agent"

set --
for name in $names; do set -- "$@" --bin "$name"; done
python3 "$root/scripts/build-release.py" --target "$triple" --out-dir "$work" "$@"

dest="$desktop/src-tauri/binaries"
rm -rf "$dest"
mkdir -p "$dest"
for name in $names; do
  cp "$work/bin/$name" "$dest/$name-$triple"
  chmod 755 "$dest/$name-$triple"
  echo "prepare-sidecars: $dest/$name-$triple"
done

python3 "$here/third-party-licenses.py" --target "$triple" \
  --sidecar-notices "$work/THIRD_PARTY_LICENSES.md" \
  --output "$desktop/src-tauri/notices/THIRD_PARTY_LICENSES.md"
