#!/bin/sh
# Release gate after makepkg: the binaries inside the built package must be byte-identical to the
# ones the build produced: the companion freeze from build-companion.sh and every file of both llama-server builds
# from fetch-sidecars.sh. Then the packaged companion is started from the extracted tree on a scratch loopback port
# and must answer /pair-status with pair_protocol typed6. Exits non-zero on any difference.
# Usage: scripts/verify-pkg.sh packaging/arch/arrowmem-desktop-<ver>-x86_64.pkg.tar.zst
set -eu
[ "$#" -eq 1 ] || { echo "usage: verify-pkg.sh PKGFILE" >&2; exit 2; }
PKG="$1"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$HERE/src-tauri/binaries"
TRIPLE="x86_64-unknown-linux-gnu"
# The reviewed companion freeze: both the build output and the packaged copy must equal this, so a wrong
# freeze cannot compare equal to itself. One line, 64 hex characters, in scripts/companion-freeze.sha256.
# The pin names ONE freeze file: the one built from b4db5567 (tree 67d49fce: models op + export store, launcher without the loopback override) for review.
# PyInstaller does not promise byte-identical rebuilds, so the package must be made from that exact file; a fresh
# build-companion.sh run will not match and this gate will refuse it.
PIN="$(tr -d ' \n' < "$HERE/scripts/companion-freeze.sha256")"
printf '%s' "$PIN" | grep -Eq '^[0-9a-f]{64}$' || { echo "verify-pkg: scripts/companion-freeze.sha256 is not a sha256" >&2; exit 1; }
PORT=18797
W="$(mktemp -d "${TMPDIR:-/tmp}/verify-pkg.XXXXXX")"
CPID=""
cleanup() { if [ -n "$CPID" ]; then kill "$CPID" 2>/dev/null; wait "$CPID" 2>/dev/null || true; fi; rm -rf "$W"; }
trap cleanup EXIT
bsdtar -xf "$PKG" -C "$W"
fail=0
same() {
  a="$(sha256sum "$1" | cut -d' ' -f1)"; b="$(sha256sum "$2" | cut -d' ' -f1)"
  echo "$a  build   $1"
  echo "$b  package $2"
  [ "$a" = "$b" ] || { echo "DIFFERENT: $2" >&2; fail=1; }
}
# Leak scan: nothing about the build host or its user may be in any packaged file. Prints only file names and
# reasons, never the matching text. Allowed /home/ shapes: the "/home/.cargo" the home remap leaves, and the upstream llama.cpp
# release runner path (home, runner, work). Also fails on the build user's login as a word, on a Tauri dev build (the embedded
# manifest folder string), on .BUILDINFO builddir or startdir outside /tmp, and on any "installed =" line.
# Prints one line per finding on stdout; no output means clean.
leak_scan() {
  d="$1"; login="${LEAK_LOGIN:-$(id -un)}"; host="${LEAK_HOST:-$(hostname 2>/dev/null || uname -n)}"; rn=runner
  find "$d" -type f | sort | while IFS= read -r f; do
    r="${f#"$d"/}"; t=""
    # .MTREE is gzip: scan what is inside it (a plain file stays as it is), under the package name r.
    if [ "$r" = .MTREE ]; then t="$(mktemp)"; zcat "$f" > "$t" 2>/dev/null || cp "$f" "$t"; f="$t"; fi
    n="$(grep -a -o '/home/[A-Za-z0-9._-]*\(/[A-Za-z0-9._-]*\)\?' "$f" | grep -Ev "^/home/\\.cargo(/|\$)|^/home/$rn/work\$" | wc -l)"
    [ "$n" = 0 ] || echo "LEAK: $r: $n /home/ string(s) outside the two neutral shapes"
    n="$(grep -a -c -i -w -F -- "$login" "$f" || :)"
    [ "$n" = 0 ] || echo "LEAK: $r: the build user's login as a word on $n line(s)"
    # an empty word would match every line, so an empty host (no hostname tool) is skipped; a lower or upper case copy still counts (-i)
    if [ -n "$host" ]; then
      n="$(grep -a -c -i -w -F -- "$host" "$f" || :)"
      [ "$n" = 0 ] || echo "LEAK: $r: the build host's name as a word on $n line(s)"
    fi
    # The build stage folder (build-clean-pkg.sh) belongs in the two .BUILDINFO lines builddir and startdir and nowhere else. A dev build
    # of this script would embed it, and unlike the src-tauri marker below it does not depend on the byte that follows.
    case "$r" in
      .BUILDINFO) n="$(grep -a -F '/tmp/ab-clean' "$f" | grep -Evc '^(builddir|startdir) = ' || :)";;
      *) n="$(grep -a -c -F '/tmp/ab-clean' "$f" || :)";;
    esac
    [ "$n" = 0 ] || echo "LEAK: $r: the build stage path on $n line(s) outside the two .BUILDINFO lines"
    case "$r" in
      usr/bin/arrowmem-desktop)
        n="$(grep -a -c -E '/[A-Za-z0-9._/-]+/src-tauri([^/]|$)' "$f" || :)"
        [ "$n" = 0 ] || echo "LEAK: $r: the Tauri config parent folder string is embedded ($n), so this is a dev build (custom-protocol feature missing)";;
      .BUILDINFO)
        n="$(grep -E '^(builddir|startdir) = ' "$f" | grep -Evc ' = /tmp/' || :)"
        [ "$n" = 0 ] || echo "LEAK: $r: builddir or startdir outside /tmp ($n)"
        n="$(grep -c '^installed = ' "$f" || :)"
        [ "$n" = 0 ] || echo "LEAK: $r: $n installed = line(s), the build host package list";;
    esac
    [ -z "$t" ] || rm -f "$t"
  done
}
echo "$PIN  pin     reviewed companion freeze"
leaks="$(leak_scan "$W")"
if [ -n "$leaks" ]; then echo "$leaks" >&2; echo "DIFFERENT: leak scan found host or user data in the package" >&2; fail=1; else echo "leak scan: 0 findings"; fi
# The icon files must be in the package and must be the committed ones (a package with the old solid placeholder must not pass).
for f in 48x48/apps/arrowmem-desktop.png 128x128/apps/arrowmem-desktop.png 256x256/apps/arrowmem-desktop.png scalable/apps/arrowmem-desktop.svg; do
  [ -f "$W/usr/share/icons/hicolor/$f" ] || { echo "MISSING icon: $f" >&2; fail=1; }
done
same "$HERE/packaging/icons/arrowmem-desktop-128.png" "$W/usr/share/icons/hicolor/128x128/apps/arrowmem-desktop.png"
same "$HERE/packaging/icons/arrowmem-desktop.svg" "$W/usr/share/icons/hicolor/scalable/apps/arrowmem-desktop.svg"
same "$BIN/arrowbridge-companion-$TRIPLE" "$W/usr/lib/arrowmem/arrowbridge-companion"
[ "$(sha256sum "$W/usr/lib/arrowmem/arrowbridge-companion" | cut -d' ' -f1)" = "$PIN" ] \
  || { echo "DIFFERENT: the packaged companion is not the reviewed freeze (build the package from that exact freeze file, never a fresh freeze)" >&2; fail=1; }
for v in cpu vulkan; do
  for f in "$BIN/llama-$v"/*; do
    same "$f" "$W/usr/lib/arrowmem/llama-$v/$(basename "$f")"
  done
  n_build=$(ls "$BIN/llama-$v" | wc -l); n_pkg=$(ls "$W/usr/lib/arrowmem/llama-$v" | wc -l)
  [ "$n_build" = "$n_pkg" ] || { echo "DIFFERENT file count in llama-$v: build $n_build, package $n_pkg" >&2; fail=1; }
done
[ "$fail" = 0 ] || { echo "verify-pkg: the package does not carry the built bytes" >&2; exit 1; }
mkdir -m 700 "$W/state"
ARROWBRIDGE_PORT=$PORT ARROWBRIDGE_BIND=127.0.0.1 ARROWBRIDGE_STATE_DIR="$W/state" \
  ARROWBRIDGE_UPSTREAM_URL=http://127.0.0.1:9 ARROWBRIDGE_UPSTREAM_MODEL=local \
  "$W/usr/lib/arrowmem/arrowbridge-companion" >"$W/companion.log" 2>&1 &
CPID=$!
i=0; until curl -fs -o /dev/null "http://127.0.0.1:$PORT/pair-phones"; do
  i=$((i+1)); [ "$i" -lt 60 ] || { echo "verify-pkg: packaged companion did not start" >&2; tail -5 "$W/companion.log" >&2; exit 1; }
  kill -0 "$CPID" 2>/dev/null || { echo "verify-pkg: packaged companion exited" >&2; tail -5 "$W/companion.log" >&2; exit 1; }
  sleep 1
done
curl -fs -X POST -H 'X-ArrowBridge-Owner: 1' -H 'Content-Type: application/json' -d '{}' "http://127.0.0.1:$PORT/pair-open" >/dev/null
st="$(curl -fs "http://127.0.0.1:$PORT/pair-status")"
echo "pair-status: $st"
echo "$st" | grep -q '"pair_protocol": *"typed6"' || { echo "verify-pkg: packaged companion does not speak typed6" >&2; exit 1; }
kill "$CPID" 2>/dev/null; wait "$CPID" 2>/dev/null || true; CPID=""
if curl -fs -o /dev/null "http://127.0.0.1:$PORT/pair-phones"; then echo "verify-pkg: a listener is still on $PORT" >&2; exit 1; fi
# The packaged companion must really START a pairing and load every module its sources import (the 0.1.0-2 to -4 packages passed everything above and could not pair).
sh "$HERE/scripts/test-frozen-pair.sh" "$W/usr/lib/arrowmem/arrowbridge-companion" || { echo "verify-pkg: the packaged companion cannot start a pairing" >&2; exit 1; }
echo "verify-pkg: OK"
sha256sum "$PKG"
