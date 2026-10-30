#!/bin/sh
# Release gate: RUN the frozen companion the way the package user unit starts it and check where it listens.
#   1. ARROWBRIDGE_BIND=<this machine's private address>: listens on that address and port (plus loopback for the owner pages), never a wildcard.
#   2. ARROWBRIDGE_BIND unset: listens on 127.0.0.1 only.
#   3. Refused binds exit non-zero, name the refusal in the log, and leave nothing listening.
# Usage: scripts/test-frozen-bind.sh <frozen companion binary> [private address]   (needs ss; picks the address of the default route)
# One line per case: PASS or FAIL, the case, and what was seen (addresses only, never a key or a credential).
set -u
BIN="${1:?usage: test-frozen-bind.sh BINARY [ADDRESS]}"
ADDR="${2:-$(ip -4 route get 1.1.1.1 | awk '{for(i=1;i<NF;i++) if($i=="src") print $(i+1)}')}"
case "$ADDR" in 10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*) ;; *) echo "FAIL setup: no private address ($ADDR)"; exit 2;; esac
W="$(mktemp -d "${TMPDIR:-/tmp}/frozen-bind.XXXXXX")"; chmod 700 "$W"
PORT=18811
PID=""
stop() { [ -n "$PID" ] && { kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null; PID=""; }; }
trap 'stop; find "$W" -type f -delete 2>/dev/null; find "$W" -depth -type d -empty -delete 2>/dev/null' EXIT
fail=0
res() { if [ "$1" = ok ]; then echo "PASS $2: $3"; else echo "FAIL $2: $3"; fail=1; fi; }
listeners() { ss -ltnH 2>/dev/null | awk '{print $4}' | grep -E "[:.]$PORT\$" | sort | tr '\n' ' '; }
start() { # name, then env assignments as arguments
  name="$1"; shift
  mkdir -p "$W/$name"; chmod 700 "$W/$name"
  env -i HOME="$W" PATH=/usr/bin ARROWBRIDGE_PORT="$PORT" ARROWBRIDGE_STATE_DIR="$W/$name" "$@" "$BIN" > "$W/$name.log" 2>&1 &
  PID=$!
}
wait_listen() { n=0; while [ $n -lt 40 ]; do [ -n "$(listeners)" ] && return 0; kill -0 "$PID" 2>/dev/null || return 1; n=$((n+1)); sleep 0.5; done; return 1; }

# 1. the unit's environment
start lan ARROWBRIDGE_BIND="$ADDR"
if wait_listen; then
  L="$(listeners)"
  case "$L" in *"0.0.0.0:$PORT"*|*"*:$PORT"*|*"[::]:$PORT"*) res bad "bind=$ADDR" "wildcard listener: $L";; *"$ADDR:$PORT"*) res ok "bind=$ADDR" "listening on: $L";; *) res bad "bind=$ADDR" "not on the LAN address: $L";; esac
  case "$L" in *"$ADDR:$PORT"*) for a in $L; do case "$a" in "$ADDR:$PORT"|"127.0.0.1:$PORT") ;; *) res bad "bind=$ADDR" "unexpected listener $a";; esac; done;; esac
else res bad "bind=$ADDR" "did not start: $(head -c 200 "$W/lan.log" | tr '\n' ' ')"; fi
stop

# 2. unset
start unset
if wait_listen; then
  L="$(listeners)"
  [ "$L" = "127.0.0.1:$PORT " ] && res ok "bind unset" "listening on: $L" || res bad "bind unset" "listening on: $L"
else res bad "bind unset" "did not start"; fi
stop

# 3. refusals
refuse() { # label, value
  start "r$1" ARROWBRIDGE_BIND="$2"
  n=0; while kill -0 "$PID" 2>/dev/null && [ $n -lt 20 ]; do n=$((n+1)); sleep 0.5; done
  if kill -0 "$PID" 2>/dev/null; then L="$(listeners)"; stop; res bad "refuse $1" "still running, listening on: $L"; return; fi
  wait "$PID"; rc=$?; PID=""
  L="$(listeners)"
  why="$(grep -m1 -iE "refus" "$W/r$1.log" | cut -c1-90)"
  if [ "$rc" -ne 0 ] && [ -z "$L" ] && [ -n "$why" ]; then res ok "refuse $1" "exit $rc, nothing listening, log: $why"
  else res bad "refuse $1" "exit $rc, listeners: ${L:-none}, log: ${why:-no refusal line}"; fi
}
# The companion does not refuse these two: it reduces them to the SAME single private address (an IPv4-mapped literal is unwrapped, the value is
# stripped). They must then listen exactly like the plain address, never wider. NOTE lines are for the reviewer to rule on; they are not a pass of "refuses".
normalised() { # label, value
  start "n$1" ARROWBRIDGE_BIND="$2"
  if wait_listen; then L="$(listeners)"
    case "$L" in "127.0.0.1:$PORT $ADDR:$PORT "|"$ADDR:$PORT 127.0.0.1:$PORT ") echo "NOTE normalised $1: accepted, same single address as the plain bind, listening on: $L";; *) res bad "normalised $1" "listening on: $L";; esac
  else echo "NOTE normalised $1: refused to start"; fi
  stop
}
refuse wildcard4 "0.0.0.0"
refuse wildcard6 "::"
refuse hostname "example.com"
refuse tailscale "100.64.0.1"
refuse public "8.8.8.8"
refuse linklocal "169.254.1.1"
normalised mapped "::ffff:$ADDR"
refuse brackets "[$ADDR]"
normalised spaced " $ADDR "
# an empty value means "unset" to the companion (loopback only), not a LAN bind: it must NOT expose anything
start empty ARROWBRIDGE_BIND=""
if wait_listen; then L="$(listeners)"; [ "$L" = "127.0.0.1:$PORT " ] && res ok "empty" "treated as unset, listening on: $L" || res bad "empty" "listening on: $L"; else res bad "empty" "did not start"; fi
stop
[ "$fail" -eq 0 ] && echo "ALL PASS" || echo "FAILURES"
exit "$fail"
