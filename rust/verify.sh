#!/usr/bin/env bash
# Rust verification matrix: formatting, strict Clippy, library and binary
# tests, every integration target, the ignored signer resource probes and the
# documentation tests. Usage: rust/verify.sh [--list | TARGET...]
#
# It builds and runs product code: run it on a CI runner or an isolated
# verification VM, never on a host holding gateway, vault, signer or
# administrator credentials.
set -uo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
manifest="$root/rust/Cargo.toml"
targets=()
for file in "$root"/rust/tests/*.rs; do
  targets+=("$(basename "$file" .rs)")
done
if [ "${1:-}" = "--list" ]; then
  printf '%s\n' "${targets[@]}"
  exit 0
fi
if [ $# -gt 0 ]; then
  targets=("$@")
  steps_only_targets=1
fi
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
if [ -z "${steps_only_targets:-}" ]; then
  step fmt cargo fmt --manifest-path "$manifest" -- --check
  step clippy cargo clippy --locked --manifest-path "$manifest" --all-targets -- -D warnings
  step lib-and-bins cargo test --locked --manifest-path "$manifest" --lib --bins
fi
for target in "${targets[@]}"; do
  step "test:$target" cargo test --locked --manifest-path "$manifest" --test "$target"
done
if [ -z "${steps_only_targets:-}" ]; then
  step signer-probes cargo test --locked --manifest-path "$manifest" --lib -- --ignored --test-threads=1
  step doc-tests cargo test --locked --manifest-path "$manifest" --doc
fi
echo "VERIFY_FAILED=${failed[*]:-}"
[ ${#failed[@]} -eq 0 ]
