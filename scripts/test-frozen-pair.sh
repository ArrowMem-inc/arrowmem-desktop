#!/bin/sh
# Release gate (review finding): the frozen companion must really START a pairing, not only answer /pair-status.
# 1. --selftest-imports: every module its bundled sources import (lazy ones included) loads inside the frozen program.
# 2. run it on loopback with a scratch state folder, open the pairing window the way the app does (POST /pair-open, owner header), then POST /pair-start the way the phone
#    does (a 32-byte public key and a 32-byte commitment, both base64). The answer must be 200 with a handshake id, the companion's public key and its commitment.
#    Before the fix this answered 500 and logged "cannot import name 'x25519'".
# Usage: scripts/test-frozen-pair.sh <frozen companion binary>      One line per check: PASS or FAIL. Never prints a key.
set -u
BIN="${1:?usage: test-frozen-pair.sh BINARY}"
W="$(mktemp -d "${TMPDIR:-/tmp}/frozen-pair.XXXXXX")"; chmod 700 "$W"
PORT=18812
PID=""
stop() { [ -n "$PID" ] && { kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null; PID=""; }; }
trap 'stop; find "$W" -type f -delete 2>/dev/null; find "$W" -depth -type d -empty -delete 2>/dev/null' EXIT
fail=0
res() { if [ "$1" = ok ]; then echo "PASS $2: $3"; else echo "FAIL $2: $3"; fail=1; fi; }

out="$(env -i HOME="$W" PATH=/usr/bin ARROWBRIDGE_PORT=18813 ARROWBRIDGE_BIND=127.0.0.1 ARROWBRIDGE_STATE_DIR="$W" timeout 20 "$BIN" --selftest-imports 2>&1)"; rc=$?
if [ "$rc" = 0 ]; then res ok "frozen imports" "$(printf '%s' "$out" | tail -1)"; else res bad "frozen imports" "$(printf '%s' "$out" | tr '\n' ' ' | head -c 300)"; fi

mkdir -p "$W/state"; chmod 700 "$W/state"
env -i HOME="$W" PATH=/usr/bin ARROWBRIDGE_PORT="$PORT" ARROWBRIDGE_BIND=127.0.0.1 ARROWBRIDGE_STATE_DIR="$W/state" ARROWBRIDGE_UPSTREAM_URL=http://127.0.0.1:9 ARROWBRIDGE_UPSTREAM_MODEL=local "$BIN" > "$W/run.log" 2>&1 &
PID=$!
python3 - "$PORT" <<'PYEOF'
import base64, json, os, sys, time, urllib.error, urllib.request
port = sys.argv[1]
base = "http://127.0.0.1:%s" % port
def call(method, path, body=None, owner=False):
    h = {"Content-Type": "application/json"}
    if owner: h["X-ArrowBridge-Owner"] = "1"
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(base + path, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=5) as r: return r.status, r.read().decode()
    except urllib.error.HTTPError as e: return e.code, e.read().decode()
    except Exception as e: return 0, "no answer: " + type(e).__name__
up = False
last = ""
for _ in range(60):
    try:
        if urllib.request.urlopen(base + "/pair-phones", timeout=3).status == 200: up = True; break
    except Exception as e: last = type(e).__name__ + " " + str(e)[:80]
    time.sleep(0.5)
if not up: print("FAIL start: the companion did not answer /pair-phones (" + last + ")"); sys.exit(1)
s, b = call("POST", "/pair-open", {}, owner=True)
if s != 200: print("FAIL pair-open: %s %s" % (s, b[:120])); sys.exit(1)
# the phone's side of the first two rounds, with a random key (the companion never checks the key is on the curve beyond its length)
import hashlib
def start(pub=None, commit=None):
    pub = os.urandom(32) if pub is None else pub
    nonce = os.urandom(16)
    c = hashlib.sha256(nonce + pub).digest() if commit is None else commit
    s, b = call("POST", "/pair-start", {"public_key": base64.b64encode(pub).decode(), "commitment": base64.b64encode(c).decode()})
    try: j = json.loads(b)
    except ValueError: j = {}
    return s, j, b, nonce
def bad(msg): print("FAIL " + msg); sys.exit(1)
# (b) wrong shapes: a refusal, never a 500 or a hang
for label, body in (("31-byte key", {"public_key": base64.b64encode(os.urandom(31)).decode(), "commitment": base64.b64encode(os.urandom(32)).decode()}),
                    ("not base64", {"public_key": "***", "commitment": "***"}),
                    ("31-byte commitment", {"public_key": base64.b64encode(os.urandom(32)).decode(), "commitment": base64.b64encode(os.urandom(31)).decode()})):
    s, b = call("POST", "/pair-start", body)
    if s != 400: bad("pair-start %s: expected 400, got %s %s" % (label, s, b[:100]))
    print("PASS pair-start %s: refused with 400" % label)
# (a) a good start
s, j, b, nonce = start()
if not (s == 200 and j.get("handshake_id") and len(base64.b64decode(j.get("public_key", ""))) == 32 and len(base64.b64decode(j.get("commitment", ""))) == 32):
    bad("pair-start: %s %s" % (s, b[:160]))
print("PASS pair-start: 200 with a handshake id, the companion's key and its commitment")
# (c) a second start while the first is open: refused, and the window closes
s2, j2, b2, _ = start()
if s2 != 409: bad("second pair-start while one is open: expected 409, got %s %s" % (s2, b2[:100]))
print("PASS second pair-start while one is open: refused with 409")
# (d) a fresh window; reveal; the WRONG six digits: one refusal, the window closes, nothing pairs
s, b = call("POST", "/pair-open", {}, owner=True)
if s != 200: bad("pair-open again: %s %s" % (s, b[:100]))
s, j, b, nonce = start()
if s != 200: bad("pair-start (second window): %s %s" % (s, b[:100]))
hid = j["handshake_id"]
s, b = call("POST", "/pair-reveal", {"handshake_id": hid, "nonce": base64.b64encode(nonce).decode()})
if s != 200 or "companion_nonce" not in b: bad("pair-reveal: %s %s" % (s, b[:100]))
print("PASS pair-reveal: the commitment checked, the companion's nonce answered")
s, b = call("POST", "/pair-confirm", {"handshake_id": hid, "code": "000000"}, owner=True)  # 1 in a million this is the right code
if s != 409 or "pair_code_mismatch" not in b: bad("wrong six digits: expected 409 pair_code_mismatch, got %s %s" % (s, b[:100]))
print("PASS wrong six digits: refused with 409, window closed")
s, b = call("POST", "/pair-confirm", {"handshake_id": hid, "code": "123456"}, owner=True)
if s != 404: bad("any digits after the one try: expected 404, got %s %s" % (s, b[:100]))
print("PASS digits after the one try: 404, nothing pairs")
s, b = call("GET", "/pair-phones")
try: n = len(json.loads(b).get("phones", []))
except ValueError: n = -1
if n != 0: bad("phones after the refused pairing: %s" % b[:100])
print("PASS no phone was paired")
PYEOF
[ $? = 0 ] && res ok "pair-start" "answered as the phone expects" || { res bad "pair-start" "see above; log tail: $(tail -4 "$W/run.log" | tr "\n" " " | head -c 400)"; }
stop
[ "$fail" = 0 ] && echo "frozen pair gate: ALL PASS" || echo "frozen pair gate: FAILED"
exit "$fail"
