#!/usr/bin/env bash
# Install a checksummed release without accessing a vault or using sudo.
set -euo pipefail
fail() { printf 'zeropw: %s\n' "$*" >&2; exit 1; }
usage() {
  cat <<'EOF'
Usage: install.sh --version VERSION [--prefix DIR] [--force]
       install.sh --archive FILE --sha256 HEX [--prefix DIR] [--force]
Installs the five ZeroPW binaries to DIR/bin (default: $HOME/.local).
No vault is initialized, no service is started, and no shell profile is edited.
EOF
}
version='' archive='' digest='' prefix="${HOME:+$HOME/.local}" force=0
while [ $# -gt 0 ]; do
  case "$1" in
    --version|--prefix|--archive|--sha256)
      [ $# -ge 2 ] || fail "missing value for $1"
      case "$1" in
        --version) version=$2;; --prefix) prefix=$2;;
        --archive) archive=$2;; --sha256) digest=$2;;
      esac
      shift 2;;
    --force) force=1; shift;;
    --help|-h) usage; exit 0;;
    *) fail "unknown option: $1";;
  esac
done
[ -n "$prefix" ] || fail 'specify --prefix or configure HOME'
[[ "$prefix" = /* ]] || fail 'prefix must be an absolute path'
case "$prefix" in *$'\n'*|*$'\r'*) fail 'invalid prefix';; esac
command -v tar >/dev/null || fail 'tar is required'
if command -v sha256sum >/dev/null; then
  hash() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null; then
  hash() { shasum -a 256 "$1" | awk '{print $1}'; }
else fail 'sha256sum or shasum is required'; fi
work=$(mktemp -d "${TMPDIR:-/tmp}/zeropw-install.XXXXXXXX")
trap 'rm -rf "$work"' EXIT
if [ -n "$archive" ]; then
  [ -z "$version" ] || fail 'choose --version or --archive, not both'
  [ -f "$archive" ] || fail 'archive does not exist'
  [[ "$digest" =~ ^[a-fA-F0-9]{64}$ ]] || fail '--archive requires a SHA-256 digest'
  cp "$archive" "$work/release.tar.gz"
else
  [ -z "$digest" ] || fail '--sha256 is only valid with --archive'
  [[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'specify a release version such as v0.1.0'
  case "$(uname -s):$(uname -m)" in
    Darwin:arm64) target=aarch64-apple-darwin;;
    Darwin:x86_64) target=x86_64-apple-darwin;;
    Linux:x86_64) target=x86_64-unknown-linux-gnu;;
    Linux:aarch64|Linux:arm64) target=aarch64-unknown-linux-gnu;;
    *) fail 'unsupported OS/architecture; build from source';;
  esac
  command -v curl >/dev/null || fail 'curl is required'
  name="zeropw-${version}-${target}.tar.gz"
  base="https://github.com/telicity-ai/zeropw/releases/download/${version}"
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    "$base/$name" -o "$work/release.tar.gz"
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    "$base/SHA256SUMS" -o "$work/SHA256SUMS"
  digest=$(awk -v name="$name" '$2 == name {print $1}' "$work/SHA256SUMS")
  [[ "$digest" =~ ^[a-fA-F0-9]{64}$ ]] || fail 'missing or ambiguous release checksum'
fi
actual=$(hash "$work/release.tar.gz")
[ "$actual" = "$(printf '%s' "$digest" | tr 'A-F' 'a-f')" ] || fail 'checksum mismatch'
bins=(zeropw-admin zeropw-agent zeropw_session zeropw-demo zeropw-democli)
printf '%s\n' "${bins[@]}" README.md LICENSE THIRD_PARTY_LICENSES.md | LC_ALL=C sort > "$work/expected"
tar -tzf "$work/release.tar.gz" | LC_ALL=C sort > "$work/entries"
cmp -s "$work/expected" "$work/entries" || fail 'unexpected, duplicate or missing archive entries'
# Reject links, directories and special files before extraction, including hardlinks.
tar -tvzf "$work/release.tar.gz" > "$work/types"
awk 'substr($0,1,1) != "-" {bad=1} END {exit bad}' "$work/types" || fail 'archive contains non-regular entries'
mkdir "$work/unpack"
tar -xzf "$work/release.tar.gz" -C "$work/unpack"
for bin in "${bins[@]}"; do
  [ -f "$work/unpack/$bin" ] && [ ! -L "$work/unpack/$bin" ] && [ -x "$work/unpack/$bin" ] \
    || fail "invalid executable: $bin"
done
[ ! -L "$prefix" ] && [ ! -L "$prefix/bin" ] || fail 'prefix and bin directory must not be symlinks'
docdir="$prefix/share/doc/zeropw"
for dir in "$prefix/share" "$prefix/share/doc" "$docdir"; do
  [ ! -L "$dir" ] || fail 'documentation directories must not be symlinks'
done
mkdir -p "$prefix/bin" "$docdir"
for bin in "${bins[@]}" README.md LICENSE THIRD_PARTY_LICENSES.md; do
  case "$bin" in README.md|LICENSE|THIRD_PARTY_LICENSES.md) dest="$docdir/$bin";; *) dest="$prefix/bin/$bin";; esac
  if [ -e "$dest" ] || [ -L "$dest" ]; then
    [ "$force" = 1 ] || fail "$dest exists; use --force to replace installed binaries"
    [ ! -d "$dest" ] || fail "$dest is a directory"
  fi
done
# Stage every file before replacing existing executables. Never follow a destination symlink.
stage=$(mktemp -d "$prefix/bin/.zeropw-install.XXXXXXXX")
docstage=$(mktemp -d "$docdir/.zeropw-docs.XXXXXXXX")
trap 'rm -rf "$work" "$stage" "$docstage"' EXIT
for bin in "${bins[@]}"; do install -m 755 "$work/unpack/$bin" "$stage/$bin"; done
for doc in README.md LICENSE THIRD_PARTY_LICENSES.md; do
  install -m 644 "$work/unpack/$doc" "$docstage/$doc"
done
for bin in "${bins[@]}"; do mv -f "$stage/$bin" "$prefix/bin/$bin"; done
for doc in README.md LICENSE THIRD_PARTY_LICENSES.md; do mv -f "$docstage/$doc" "$docdir/$doc"; done
printf 'Installed ZeroPW to %s/bin\nAdd this directory to PATH if needed.\n' "$prefix"
