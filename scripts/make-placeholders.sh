#!/bin/sh
# Placeholder sidecars so the scaffold compiles. NOT the real companion or llama-server.
# Real ones: scripts/build-companion.sh and scripts/fetch-sidecars.sh (stubs).
set -eu
cd "$(dirname "$0")/../src-tauri/binaries"
T="${1:-$(rustc --print host-tuple)}"
for n in arrowbridge-companion llama-server; do
  printf '#!/bin/sh\necho "placeholder %s: not the real sidecar" >&2\nexit 1\n' "$n" > "$n-$T"
  chmod 755 "$n-$T"
done
echo "placeholders for $T"
