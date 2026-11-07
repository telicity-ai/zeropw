#!/bin/bash
# Run ONLY in an isolated Linux development VM with synthetic credentials.
# Requires root for private network namespaces; no host network rules change.
# Usage: run.sh /source/zeropw-link /built/zeropw-admin
set -euo pipefail
if [ "$(uname -s)" != Linux ] || [ "$(id -u)" != 0 ]; then
  echo 'run inside an isolated Linux VM as root, never on the coordinator' >&2; exit 2
fi
LINK_SRC=$(realpath "${1:?zeropw-link source directory required}")
ADMIN=$(realpath "${2:?zeropw-admin binary required}")
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
LAB="$LINK_SRC/test/daemon-netns/run.sh"
[ -x "$ADMIN" ] && [ -f "$LAB" ] || exit 2
# Reuse the separate repository's maintained topology, TLS and coturn fixture.
# Refuse a changed entry point rather than accidentally invoking its main.
[ "$(tail -n 1 "$LAB")" = main ] || {
  echo 'unsupported daemon-netns fixture entry point' >&2; exit 2;
}
# shellcheck disable=SC1090
source <(head -n -1 "$LAB")
ROOT=$LINK_SRC
P=zpe-$$
W=$(mktemp -d /tmp/zpe.XXXXXX)
chmod 755 "$W"
# The sourced topology and cleanup functions consume this global.
# shellcheck disable=SC2034
NSES="$P-wan $P-srv $P-ra $P-rb $P-pa $P-pb"
export ZPE_WORK=$W ZPE_PREFIX=$P ZPE_USER=$RUNAS
trap cleanup EXIT
mkdir -p "$W/bin"
install -m 0755 "$ADMIN" "$W/bin/zeropw-admin"
echo "work=$W namespace_prefix=$P"
echo "zeropw_source=${ZPE_ZEROPW_SHA:-not-recorded} link_source=${ZPE_LINK_SHA:-not-recorded}"
uname -a
go version
"$TURNSERVER" --version 2>/dev/null | head -n 1 || true
sha256sum "$W/bin/zeropw-admin" "$TURNSERVER" "$LAB"
sha256sum "$SCRIPT_DIR/run.sh" "$SCRIPT_DIR/scenarios.py"
for binary in zeropw-link zeropw-linkd; do
  (cd "$ROOT" && CGO_ENABLED=0 go build -mod=readonly -trimpath -o "$W/bin/$binary" "./cmd/$binary")
done
(cd "$ROOT" && CGO_ENABLED=0 go build -mod=readonly -trimpath -o "$W/bin/sockxfer" ./test/sockxfer)
sha256sum "$W/bin/zeropw-link" "$W/bin/zeropw-linkd"
topo_up
services_up
# The fixture deliberately attempts a second enrollment and inspects its error.
# Its functions were written without errexit; retain that expected-error path.
if ! enroll; then echo 'enrollment fixture failed' >&2; exit 1; fi
umask 077
printf '{"invite_code":"%s","link_token":"%s"}\n' "${SECRETS[-2]}" "${SECRETS[-1]}" > "$W/enrollment-fixture.json"
umask 022
router_fw -A
nsx pa tcpdump -Z root -i eth0 -s 0 -U -w "$W/run/wire.pcap" > "$W/run/tcpdump.out" 2>&1 &
PIDS+=("$!")
python3 "$SCRIPT_DIR/scenarios.py"
secret_check
if grep -q '^FAIL' "$W/summary.txt"; then exit 1; fi
echo "E2E_RESULT=PASS work=$W"
