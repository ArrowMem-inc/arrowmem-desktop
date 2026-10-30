#!/bin/sh
# Clean package build: nothing about this machine or this person may end up in the package.
#   sh scripts/build-clean-pkg.sh        (from a clean checkout; builds the COMMITTED tree, never the working tree)
# What it does, in a neutral folder (/tmp/ab-clean, no user name in any path):
#   1. exports HEAD with git archive, copies the already verified llama-server sidecars;
#   2. freezes the companion from the pinned commit with scripts/build-companion.sh (allowlist of runtime files, comments and docstrings stripped, neutral sysconfig);
#   3. builds the Rust app with --remap-path-prefix for the build folder, the cargo registry and the toolchain, so no home path survives in a panic location;
#   4. runs makepkg with a neutral builddir and startdir, the default packager ("Unknown Packager"), and an empty installed-package list (pacman -Qi is answered by a wrapper that
#      prints nothing), so .BUILDINFO names no host package and no home folder. A real clean chroot (extra-x86_64-build) needs root, which this seat does not have.
# Output: /tmp/ab-clean/out/arrowmem-desktop-<ver>-<rel>-x86_64.pkg.tar.zst (unsigned, unhosted). Then: scripts/verify-pkg.sh and the leak scan.
set -eu
HERE="$(cd "$(dirname "$0")/.." && pwd)"
STAGE="${AB_CLEAN_DIR:-/tmp/ab-clean}"
case "$STAGE" in /tmp/*) ;; *) echo "refusing: the build folder must be under /tmp ($STAGE)" >&2; exit 2;; esac
[ -z "$(git -C "$HERE" status --porcelain --untracked-files=no)" ] || { echo "refusing: tracked files are modified; commit first" >&2; exit 2; }
rm_tree() { [ -d "$1" ] && find "$1" -mindepth 1 -delete 2>/dev/null; [ -d "$1" ] && find "$1" -depth -type d -empty -delete 2>/dev/null; return 0; }
rm_tree "$STAGE"; mkdir -p "$STAGE/src" "$STAGE/out" "$STAGE/tmp" "$STAGE/target"
git -C "$HERE" archive HEAD | tar -x -C "$STAGE/src"
mkdir -p "$STAGE/src/src-tauri/binaries"
for v in llama-cpu llama-vulkan; do cp -a "$HERE/src-tauri/binaries/$v" "$STAGE/src/src-tauri/binaries/$v"; done
export TMPDIR="$STAGE/tmp"
# 1. the companion freeze (python3.12 must be on PATH by exact name)
( cd "$STAGE/src" && sh scripts/build-companion.sh )
FREEZE="$STAGE/src/src-tauri/binaries/arrowbridge-companion-x86_64-unknown-linux-gnu"
echo "freeze $(sha256sum "$FREEZE" | cut -d' ' -f1) $(stat -c %s "$FREEZE") bytes"
# 2. the app, no home path in it
export CARGO_TARGET_DIR="$STAGE/target"
RUSTFLAGS="--remap-path-prefix=$STAGE/src=/build --remap-path-prefix=$STAGE/target=/target --remap-path-prefix=$HOME/.cargo=/cargo --remap-path-prefix=$HOME/.rustup=/rustup --remap-path-prefix=$HOME=/home"
export RUSTFLAGS
( cd "$STAGE/src/src-tauri" && cargo build --release --offline --locked )
# the package takes the app from src-tauri/target/release; the neutral target folder is linked there
mkdir -p "$STAGE/src/src-tauri/target"; ln -s "$STAGE/target/release" "$STAGE/src/src-tauri/target/release"
# 3. makepkg with neutral metadata
cat > "$STAGE/pacman-wrapper" <<'EOF'
#!/bin/sh
# makepkg lists every installed package into .BUILDINFO with `pacman -Qi`; here that query answers with nothing. Anything else goes to the real pacman.
case "$*" in *-Qi*) exit 0;; esac
exec /usr/bin/pacman "$@"
EOF
chmod 755 "$STAGE/pacman-wrapper"
sed -e "s|^#\?BUILDDIR=.*|BUILDDIR=$STAGE/build|" /etc/makepkg.conf > "$STAGE/makepkg.conf"
( cd "$STAGE/src/packaging/arch" && PACMAN="$STAGE/pacman-wrapper" PKGDEST="$STAGE/out" SRCPKGDEST="$STAGE/out" SOURCE_DATE_EPOCH="$(date +%s)" makepkg --config "$STAGE/makepkg.conf" -f --nodeps --nocheck )
ls -l "$STAGE/out"
sha256sum "$STAGE"/out/*.pkg.tar.zst
