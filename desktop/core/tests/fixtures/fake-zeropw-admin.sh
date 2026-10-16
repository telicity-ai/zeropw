#!/bin/sh
# Fake zeropw-admin for the desktop core tests. Synthetic values only.
#
# Tests copy this file to <tmp>/bin/zeropw-admin. Every call is recorded next to it:
#   calls/<n>.argv   one argument per line
#   calls/<n>.stdin  the input envelope (only when --input-envelope is given)
#   calls/<n>.env    the environment the core gave the child
#   calls/<n>.key    the command key ("init", "secret_put", "team_invite-info", "serve", ...)
# The answer is chosen by that key: responses/<key>.json goes to stdout,
# responses/<key>.stderr to stderr, responses/<key>.exit is the exit status and
# responses/<key>.sleep a delay in seconds. Without a response file a built-in default is used.
set -u
dir=$(cd "$(dirname "$0")" && pwd)
calls="$dir/calls"
mkdir -p "$calls"
n=$(( $(cat "$calls/count" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$calls/count"
: > "$calls/$n.argv"
for a in "$@"; do
  printf '%s\n' "$a" >> "$calls/$n.argv"
done
env > "$calls/$n.env"

state_dir=""
envelope=0
listen=""
w1=""
w2=""
for a in "$@"; do
  case "$a" in
    --state-dir=*) state_dir=${a#--state-dir=} ;;
    --input-envelope) envelope=1 ;;
    --listen=*) listen=${a#--listen=} ;;
    -*) ;;
    *)
      if [ -z "$w1" ]; then w1=$a; elif [ -z "$w2" ]; then w2=$a; fi ;;
  esac
done
case "$w1" in
  project|secret|connection|principal|grant|approvals|rotation|incident|audit|team)
    key="${w1}_${w2}" ;;
  *) key="$w1" ;;
esac
echo "$key" > "$calls/$n.key"
if [ "$envelope" = 1 ]; then
  cat > "$calls/$n.stdin"
fi

# The hidden global --require-admin: only right after --input-envelope, and like the real CLI
# it refuses to run without an admin passphrase in the envelope.
i=0
for a in "$@"; do
  i=$((i + 1))
  if [ "$a" = "--require-admin" ]; then
    if [ "$i" != 3 ] || [ "${2:-}" != "--input-envelope" ]; then
      echo '{"error":"UsageError","reason":"usage","detail":"--require-admin out of place"}' >&2
      exit 2
    fi
    if ! grep -q '"admin_passphrase":"[^"]' "$calls/$n.stdin"; then
      echo '{"error":"AuthFailed","reason":"passphrase_missing"}' >&2
      exit 1
    fi
  fi
done

r="$dir/responses/$key"
if [ -f "$r.sleep" ]; then
  sleep "$(cat "$r.sleep")"
fi
if [ -f "$r.json" ] || [ -f "$r.stderr" ] || [ -f "$r.exit" ]; then
  if [ -f "$r.json" ]; then cat "$r.json"; fi
  if [ -f "$r.stderr" ]; then cat "$r.stderr" >&2; fi
  exit "$(cat "$r.exit" 2>/dev/null || echo 0)"
fi

case "$key" in
  init)
    mkdir -p "$state_dir" && : > "$state_dir/admin.json"
    printf '{"kms_key_id":"kms-synthetic","state_dir":"%s"}\n' "$state_dir" ;;
  status|stop-all|resume)
    echo '{"incident_open":null,"restore_pending":false,"stopped":false}' ;;
  project_create)
    echo '{"created_at":"2026-10-15T00:00:00Z","environments":["dev"],"name":"demo"}' ;;
  project_list)
    echo '{"projects":[]}' ;;
  secret_put)
    echo '{"environment":"dev","id":"api","kind":"api_key","project":"demo","status":"active","version":1}' ;;
  secret_list)
    echo '{"secrets":[]}' ;;
  secret_reveal)
    echo '{"id":"api","value":"synthetic-revealed-value","version":1}' ;;
  principal_create)
    echo '{"id":"agent-1","note":"shown once","runtime":"default","token":"zpw_synthetic_caller_token"}' ;;
  team_invite)
    echo '{"env_id":"env-synthetic","expires_at":"2026-10-16T00:00:00Z","invite":"SYNTHETICINVITE","invite_id":"00112233445566778899aabbccddeeff","link":"zeropw://join#SYNTHETICINVITE","name":"bob","role":"user"}' ;;
  team_invite-info)
    echo '{"addresses":["192.168.1.20:47390"],"env_id":"env-synthetic","expired":false,"expires_at":"2026-10-16T00:00:00Z","invite_id":"00112233445566778899aabbccddeeff","inviter":"ABCDEFGHIJKLMNOPQRSTUVWXYZ","name":"bob","role":"user"}' ;;
  team_join)
    echo '{"env_id":"env-synthetic","environment":"shared","inviter_fingerprint":"ABCDEFGHIJKLMNOPQRSTUVWXYZ","project":"demo","self_fingerprint":"ZYXWVUTSRQPONMLKJIHGFEDCBA"}' ;;
  team_invites)
    echo '{"env_id":"env-synthetic","invites":[]}' ;;
  serve)
    port=${listen##*:}
    if [ -f "$dir/responses/serve.ignore_term" ]; then
      trap '' TERM
    else
      trap 'exit 0' TERM
    fi
    printf '{"pid":%s,"url":"http://127.0.0.1:%s"}\n' "$$" "$port"
    while :; do sleep 1; done ;;
  *)
    echo '{}' ;;
esac
