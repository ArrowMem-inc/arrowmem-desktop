#!/bin/sh
# Freeze the ArrowBridge companion with PyInstaller into src-tauri/binaries/arrowbridge-companion-<triple>.
#   scripts/build-companion.sh          no argument: the commit is pinned below and cannot be overridden
# Source is `git archive` of the pinned commit object (never a checkout, never the working tree), and
# PyInstaller builds from that export only. The script refuses unless the commit exists and its tree equals
# the pinned tree. After the freeze it checks the binary for LAN-hardening markers and deletes it if any is missing.
# PyInstaller cannot cross-compile: this builds for the machine it runs on. Linux binaries must be built on Linux.
set -eu
PIN_COMMIT="b4db5567e79b5e90bdfe2d1576eb84cf6051424b"
PIN_TREE="67d49fce11af57a02d6c97551481a4008b31c079"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
# Refuse before anything else (and so before any venv) unless the PyInstaller lock hashes the whole closure.
# For the build-machine operator, online, to generate it:
#   pip-compile --generate-hashes --allow-unsafe -o scripts/pyinstaller.lock <(echo pyinstaller==6.11.1)
LOCK="$HERE/scripts/pyinstaller.lock"
python3 "$HERE/scripts/check_lock.py" "$LOCK" || { echo "refusing: $LOCK must hash pyinstaller and its full dependency closure" >&2; exit 1; }
[ "$#" -eq 0 ] || { echo "no arguments: the commit is pinned" >&2; exit 2; }
REPO="$HOME/dev/companion-source"   # fixed path; the commit and tree pins are what make its content trustworthy
PY="python3.12"
git -C "$REPO" cat-file -e "$PIN_COMMIT^{commit}" || { echo "pinned commit $PIN_COMMIT not found in $REPO" >&2; exit 1; }
[ "$(git -C "$REPO" rev-parse "$PIN_COMMIT^{tree}")" = "$PIN_TREE" ] || { echo "tree of $PIN_COMMIT is not the pinned tree $PIN_TREE" >&2; exit 1; }
FULL="$PIN_COMMIT"
PATH="$HOME/.cargo/bin:$PATH"
TRIPLE="$(rustc --print host-tuple 2>/dev/null || rustc -vV | sed -n 's/^host: //p')"
[ -n "$TRIPLE" ] || { echo "cannot determine target triple (rustc missing)" >&2; exit 1; }
OUT="$HERE/src-tauri/binaries/arrowbridge-companion-$TRIPLE"
W="$(mktemp -d "${TMPDIR:-/tmp}/ab-freeze.XXXXXX")"
trap 'rm -rf "$W"' EXIT
mkdir "$W/src"
# ALLOWLIST: only the files the running companion needs. The companion server and the modules it imports (found by following every
# import, lazy ones included, from companion_server.py: arrowbridge_channel, cred_store, discovery, export_store, machine_id), the six gate files under src/,
# and the four prompts it reads at run time. No README, INSTALL, plist, installer, draft, test, monitor or helper script ever enters the bundle.
RUNTIME_FILES="companion/companion_server.py companion/arrowbridge_channel.py companion/cred_store.py companion/discovery.py companion/export_store.py companion/machine_id.py
 src/mvf_distress.py src/mvf_fact_guard.py src/mvf_link_gate.py src/mvf_pack_safety.py src/mvf_tel_guard.py src/mvf_urgent.py
 tools/prompts/route.txt tools/prompts/general.txt tools/prompts/company.txt tools/prompts/arrowmem_help.txt"
# shellcheck disable=SC2086
git -C "$REPO" archive "$FULL" $RUNTIME_FILES | tar -x -C "$W/src"
# The venv needs the frozen requirement set of the pinned companion; that one file is read from the same commit and never bundled.
git -C "$REPO" show "$FULL:companion/requirements.lock" > "$W/requirements.lock"
"$PY" -m venv "$W/venv"
"$W/venv/bin/pip" install -q --require-hashes --only-binary=:all: -r "$W/requirements.lock"
"$W/venv/bin/pip" install -q --require-hashes --only-binary=:all: -r "$LOCK"
# Comments and docstrings never ship: no working notes in a package. The exported copy is rewritten from its own syntax tree
# and each file must parse to the same tree minus docstrings (scripts/strip_python_for_ship.py refuses otherwise). The repository is never touched.
"$W/venv/bin/python" "$HERE/scripts/strip_python_for_ship.py" "$W"/src/companion/*.py "$W"/src/src/*.py > "$W/strip.log" || { cat "$W/strip.log" >&2; exit 1; }
# The interpreter's own build-time settings file (_sysconfigdata) names the directory this Python was installed in. A neutral copy goes first on the path, so
# PyInstaller freezes the neutral one: every path of the installing prefix is replaced by /usr.
SYSCFG_NAME="$("$W/venv/bin/python" -c 'import sysconfig; print(sysconfig._get_sysconfigdata_name())')"
SYSCFG_SRC="$("$W/venv/bin/python" -c "import importlib.util,sys; print(importlib.util.find_spec('$SYSCFG_NAME').origin)")"
PYPREFIX="$("$W/venv/bin/python" -c 'import sys; print(sys.base_prefix)')"
mkdir "$W/neutral" && sed "s|$PYPREFIX|/usr|g" "$SYSCFG_SRC" > "$W/neutral/$SYSCFG_NAME.py"
! grep -q "$HOME" "$W/neutral/$SYSCFG_NAME.py" || { echo "the neutral sysconfig data still names $HOME" >&2; exit 1; }
HI=""
for m in $(cd "$W/src/companion" && ls *.py | sed 's/\.py$//' | grep -v '^companion_server$') \
         $(cd "$W/src/src" && ls *.py | sed 's/\.py$//') zeroconf ifaddr segno cryptography; do
  HI="$HI --hidden-import $m"
done
# EVERY module the bundled sources import, lazy ones included (scripts/frozen_imports.py reads the syntax trees): the companion is run as DATA, so PyInstaller never sees an
# import inside a function. The pairing key exchange imports x25519 that way and the first packages could not pair (19:24 finding).
LAZY="$("$W/venv/bin/python" "$HERE/scripts/frozen_imports.py" "$W/src/companion" "$W/src/src")" || { echo "cannot list the imports of the bundled sources" >&2; exit 1; }
for m in $LAZY; do HI="$HI --hidden-import $m"; done
# zeroconf is compiled (Cython) and loads its own submodules by name: without them even `import zeroconf` fails in the frozen program (ModuleNotFoundError
# zeroconf._utils.ipaddress, found 19:3x by the new frozen import self test; the earlier freezes never loaded it, so mDNS could not have worked either).
HI="$HI --collect-submodules zeroconf"
# shellcheck disable=SC2086
(cd "$W" && "$W/venv/bin/pyinstaller" --onefile --noconfirm --clean --name arrowbridge-companion \
  --paths "$W/neutral" --paths "$W/src/companion" --paths "$W/src/src" $HI \
  --add-data "$W/src/companion:companion" --add-data "$W/src/src:src" --add-data "$W/src/tools:tools" \
  --distpath "$W/dist" --workpath "$W/build" --specpath "$W" "$HERE/scripts/companion_launcher.py" >"$W/pyi.log" 2>&1) \
  || { tail -30 "$W/pyi.log" >&2; exit 1; }
# Post-freeze, gate 1: every module the sources import must load INSIDE the frozen program (it runs as data, so the build cannot assume it).
if ! "$W/dist/arrowbridge-companion" --selftest-imports; then
  rm -f "$W/dist/arrowbridge-companion" "$OUT"
  echo "frozen companion cannot import everything its sources import: output deleted" >&2
  exit 1
fi
# Post-freeze: the binary must carry the LAN-hardening markers of the pinned companion_server.py.
if ! "$W/venv/bin/python" "$HERE/scripts/check_markers.py" "$W/dist/arrowbridge-companion"; then
  rm -f "$W/dist/arrowbridge-companion" "$OUT"
  echo "frozen companion lacks LAN-hardening markers: output deleted" >&2
  exit 1
fi
mkdir -p "$HERE/src-tauri/binaries"
cp "$W/dist/arrowbridge-companion" "$OUT"
chmod 755 "$OUT"
echo "built $OUT from $FULL"
