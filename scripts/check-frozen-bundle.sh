#!/bin/sh
# Release gate: what a RUNNING frozen companion unpacks (onefile _MEIPASS) is exactly the allowlist of runtime files, built from the commit
# pinned in build-companion.sh: each Python file equals the pinned file after scripts/strip_python_for_ship.py (comments, docstrings and the three notes inside
# strings removed; the tool proves the stripped text parses to the same tree), each prompt equals the pinned file byte for byte, and nothing else is in the bundle.
# Usage: scripts/check-frozen-bundle.sh <frozen binary>   (needs python3.12 on PATH by exact name, git, the pinned commit in ~/dev/companion-source). Read only.
set -u
BIN="$1"; HERE="$(cd "$(dirname "$0")/.." && pwd)"
COMMIT="$(sed -n 's/^PIN_COMMIT="\([0-9a-f]*\)"$/\1/p' "$HERE/scripts/build-companion.sh")"
FILES="$(awk '/^RUNTIME_FILES="/{f=1; sub(/^RUNTIME_FILES="/,"")} f{print} /"$/{if(f) exit}' "$HERE/scripts/build-companion.sh" | tr -d '"' | tr '\n' ' ')"
[ -n "$COMMIT" ] && [ -n "$FILES" ] || { echo "cannot read the pin or the allowlist from build-companion.sh"; exit 2; }
export TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/bundle-eq.XXXXXX")"; chmod 700 "$TMPDIR"
S="$TMPDIR/state"; mkdir -p "$S"; chmod 700 "$S"
env -i HOME="$TMPDIR" PATH=/usr/bin TMPDIR="$TMPDIR" ARROWBRIDGE_PORT=18821 ARROWBRIDGE_STATE_DIR="$S" "$BIN" > "$TMPDIR/run.log" 2>&1 &
PID=$!
n=0; until ls -d "$TMPDIR"/_MEI*/companion/companion_server.py >/dev/null 2>&1; do n=$((n+1)); [ $n -gt 40 ] && { echo "no unpack dir"; kill $PID; exit 2; }; sleep 0.5; done
sleep 2
M="$(ls -d "$TMPDIR"/_MEI* | head -1)"
REF="$TMPDIR/ref"; mkdir -p "$REF"
# shellcheck disable=SC2086
git -C "$HOME/dev/companion-source" archive "$COMMIT" $FILES | tar -x -C "$REF"
python3.12 "$HERE/scripts/strip_python_for_ship.py" $(for f in $FILES; do case "$f" in *.py) echo "$REF/$f";; esac; done) > "$TMPDIR/strip.log" || { cat "$TMPDIR/strip.log"; kill $PID; exit 1; }
different=0; total=0
for f in $FILES; do
  total=$((total+1))
  a="$(sha256sum "$REF/$f" | cut -d' ' -f1)"; b="$(sha256sum "$M/$f" 2>/dev/null | cut -d' ' -f1)"
  [ "$a" = "$b" ] || { different=$((different+1)); echo "DIFFERENT or missing: $f"; }
done
(cd "$M" && find companion src tools -type f -not -path "*__pycache__*" | sort) > "$TMPDIR/bun.lst"
(for f in $FILES; do echo "$f"; done | sort) > "$TMPDIR/ref.lst"
extra=$(comm -13 "$TMPDIR/ref.lst" "$TMPDIR/bun.lst" | wc -l)
echo "allowlist files: $total, different or missing: $different, extra files in the bundle: $extra"
comm -13 "$TMPDIR/ref.lst" "$TMPDIR/bun.lst" | head -5
echo "bundle companion_server.py sha256: $(sha256sum "$M/companion/companion_server.py" | cut -d' ' -f1)"
kill $PID 2>/dev/null; wait $PID 2>/dev/null
[ "$different" -eq 0 ] && [ "$extra" -eq 0 ] && echo "BUNDLE EQUAL" || { echo "BUNDLE DIFFERS"; exit 1; }
