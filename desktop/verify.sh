#!/usr/bin/env bash
# Desktop app verification: frontend static checks, type check and build, unit tests,
# Rust formatting and strict Clippy for the desktop workspace, and the core's tests,
# including the end-to-end ones that drive freshly built zeropw binaries against a
# throwaway state directory. Usage: desktop/verify.sh
#
# Like rust/verify.sh it builds and runs product code: run it on a CI runner or an
# isolated verification VM, never on a host holding real vault or administrator keys.
set -uo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
desktop="$root/desktop"
manifest="$desktop/Cargo.toml"
failed=()
step() {
  local name=$1
  shift
  echo "VERIFY_STEP_BEGIN=$name"
  "$@"
  local status=$?
  echo "VERIFY_STEP_END=$name exit=$status"
  [ $status -eq 0 ] || failed+=("$name")
}
in_desktop() { (cd "$desktop" && "$@"); }

step npm-ci in_desktop npm ci --ignore-scripts --no-audit --no-fund
step static-check in_desktop npm run check
step unit-tests in_desktop npm test
step build in_desktop npm run build
step fmt cargo fmt --manifest-path "$manifest" --all -- --check
step clippy cargo clippy --locked --manifest-path "$manifest" --workspace --all-targets -- -D warnings
step product-bins cargo build --locked --manifest-path "$root/rust/Cargo.toml" --bins
target_dir=${CARGO_TARGET_DIR:-$root/rust/target}
step core-tests env ZEROPW_BIN_DIR="$target_dir/debug" \
  cargo test --locked --manifest-path "$manifest" --workspace -- --include-ignored
echo "VERIFY_FAILED=${failed[*]:-}"
[ ${#failed[@]} -eq 0 ]
