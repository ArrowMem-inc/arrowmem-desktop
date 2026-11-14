#!/bin/sh
# Build the arrowmesh daemon into src-tauri/binaries/arrowmesh-<triple> and write scripts/arrowmesh-freeze.sha256.
#   scripts/build-arrowmesh.sh          no argument: the commits are pinned below and cannot be overridden
# Source is `git archive` of each pinned commit object (never a checkout, never the working tree). arrowmesh has two sibling path
# dependencies (../arrowmem-core, ../arrowmem-gate), so all three are exported side by side and each is pinned by commit AND tree.
# The build is `cargo build --release --locked`, with the target directory under this project (never /tmp).
set -eu
MESH_COMMIT="df8c8468d445bb0c4d21593934c493313030bcb5"
MESH_TREE="222c145cabe394108f3cbeeaaa6ac0d59ef0cd5b"
CORE_COMMIT="6004351c166f97bdbda777427ea418b10f098d30"
CORE_TREE="8eb9eef820ec35a62a487f4e452308a57a484b55"
GATE_COMMIT="0f5f1493c359a9bd5640cb853fe01110956bb357"
GATE_TREE="29b0662656ff803038732e2ed0b5f69493b76135"
# The committed arrowmesh Cargo.lock at MESH_COMMIT is behind the pinned arrowmem-gate (idna, unicode-security, unicode-script are missing from it), so
# `--locked` against it fails. This project carries the lock that adds exactly those entries (additions only, every crate hash-pinned) and its sha256 is pinned here.
LOCK_SHA="2e31ec7e82b1573fdfbd068eb4b52081193ea1590eaa894e51cf463bc36fdbd0"
[ "$#" -eq 0 ] || { echo "no arguments: the commits are pinned" >&2; exit 2; }
HERE="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${ARROWMEM_SRC_ROOT:-$HOME/Projects}"
PATH="$HOME/.cargo/bin:$PATH"
pin() { # name commit tree
  git -C "$SRC/$1" cat-file -e "$2^{commit}" || { echo "pinned commit $2 not found in $SRC/$1" >&2; exit 1; }
  [ "$(git -C "$SRC/$1" rev-parse "$2^{tree}")" = "$3" ] || { echo "tree of $2 is not the pinned tree $3" >&2; exit 1; }
}
pin arrowmesh "$MESH_COMMIT" "$MESH_TREE"
pin arrowmem-core "$CORE_COMMIT" "$CORE_TREE"
pin arrowmem-gate "$GATE_COMMIT" "$GATE_TREE"
TRIPLE="$(rustc --print host-tuple 2>/dev/null || rustc -vV | sed -n 's/^host: //p')"
[ -n "$TRIPLE" ] || { echo "cannot determine target triple (rustc missing)" >&2; exit 1; }
# A fresh work directory per build, under the project. It holds source only; the compiled output goes to target-sidecar/build and is reused.
mkdir -p "$HERE/target-sidecar"
W="$(mktemp -d "$HERE/target-sidecar/work.XXXXXX")"
mkdir "$W/arrowmesh" "$W/arrowmem-core" "$W/arrowmem-gate"
git -C "$SRC/arrowmesh" archive "$MESH_COMMIT" | tar -x -C "$W/arrowmesh"
git -C "$SRC/arrowmem-core" archive "$CORE_COMMIT" | tar -x -C "$W/arrowmem-core"
git -C "$SRC/arrowmem-gate" archive "$GATE_COMMIT" | tar -x -C "$W/arrowmem-gate"
[ "$(sha256sum "$HERE/scripts/arrowmesh.Cargo.lock" | cut -d' ' -f1)" = "$LOCK_SHA" ] || { echo "scripts/arrowmesh.Cargo.lock is not the pinned lock" >&2; exit 1; }
cp "$HERE/scripts/arrowmesh.Cargo.lock" "$W/arrowmesh/Cargo.lock"
(cd "$W/arrowmesh" && CARGO_TARGET_DIR="$HERE/target-sidecar/build" cargo build --release --locked --bin arrowmesh)
OUT="$HERE/src-tauri/binaries/arrowmesh-$TRIPLE"
mkdir -p "$HERE/src-tauri/binaries"
cp "$HERE/target-sidecar/build/release/arrowmesh" "$OUT"
chmod 755 "$OUT"
SUM="$(sha256sum "$OUT" | cut -d' ' -f1)"
{
  echo "# arrowmesh $MESH_COMMIT tree $MESH_TREE"
  echo "# arrowmem-core $CORE_COMMIT tree $CORE_TREE"
  echo "# arrowmem-gate $GATE_COMMIT tree $GATE_TREE"
  echo "# lock $LOCK_SHA scripts/arrowmesh.Cargo.lock"
  echo "$SUM  src-tauri/binaries/arrowmesh-$TRIPLE"
} > "$HERE/scripts/arrowmesh-freeze.sha256"
rm -r "$W"
echo "built $OUT sha256 $SUM"
