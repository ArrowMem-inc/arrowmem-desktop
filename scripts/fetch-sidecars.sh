#!/bin/sh
# Fetch the llama-server release pinned in models/manifest.json for a target triple, verify size and sha256
# against the manifest BEFORE anything is extracted or run, then place llama-server-<triple> and its shared
# libraries beside it. Usage: fetch-sidecars.sh [triple] [cpu|vulkan|both]   (OUT=<dir> overrides src-tauri/binaries)
# `both` fetches the two pinned builds, each sha256-checked, into OUT/llama-cpu and OUT/llama-vulkan (own libraries,
# so the two builds never share or overwrite a .so), each holding `llama-server`. The Arch package installs those.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
triple=${1:-}
variant=${2:-cpu}
if [ -z "$triple" ]; then
  case "$(uname -s)-$(uname -m)" in
    Darwin-arm64) triple=aarch64-apple-darwin ;;
    Linux-x86_64) triple=x86_64-unknown-linux-gnu ;;
    Linux-aarch64) triple=aarch64-unknown-linux-gnu ;;
    *) echo "unsupported host; pass a triple" >&2; exit 2 ;;
  esac
fi
exec python3 -I - "$here" "$triple" "$variant" "${OUT:-$here/src-tauri/binaries}" <<'PY'
import hashlib, json, os, shutil, sys, tarfile, tempfile, urllib.request
here, triple, variant, out = sys.argv[1:5]
m = json.load(open(os.path.join(here, "models", "manifest.json")))["llama_server"]
def fetch(variant, dest, binname):
    try:
        b = m["builds"][triple][variant]
    except KeyError:
        sys.exit("no pinned build for %s/%s in the manifest" % (triple, variant))
    url = m["base_url"] + b["asset"]
    if not url.startswith("https://github.com/ggml-org/llama.cpp/releases/download/"):
        sys.exit("refusing url outside the pinned release: " + url)
    work = tempfile.mkdtemp(prefix="llama-fetch-")
    tgz = os.path.join(work, b["asset"])
    h = hashlib.sha256()
    with urllib.request.urlopen(url) as r, open(tgz, "wb") as f:
        for chunk in iter(lambda: r.read(1 << 20), b""):
            h.update(chunk); f.write(chunk)
    if os.path.getsize(tgz) != b["size_bytes"] or h.hexdigest() != b["sha256"]:
        shutil.rmtree(work)
        sys.exit("sha256/size mismatch for %s: got %s, manifest %s. Nothing extracted." % (b["asset"], h.hexdigest(), b["sha256"]))
    print("verified", b["asset"], h.hexdigest())
    ex = os.path.join(work, "x"); os.mkdir(ex)
    with tarfile.open(tgz) as t:
        for mem in t.getmembers():
            if mem.name.startswith("/") or ".." in mem.name.split("/"):
                sys.exit("unsafe path in archive: " + mem.name)
        t.extractall(ex, filter="data")
    srv = [os.path.join(d, "llama-server") for d, _, fs in os.walk(ex) if "llama-server" in fs]
    if not srv:
        sys.exit("llama-server not in archive")
    src = os.path.dirname(srv[0])
    os.makedirs(dest, exist_ok=True)
    for n in os.listdir(src):
        p = os.path.join(src, n)
        if n == "llama-server":
            shutil.copy2(p, os.path.join(dest, binname))
        elif n.endswith((".dylib", ".so")) or ".so." in n:
            shutil.copy2(p, os.path.join(dest, n), follow_symlinks=False)
    shutil.rmtree(work)
    print("installed %s into %s" % (binname, dest))

if variant == "both":
    fetch("cpu", os.path.join(out, "llama-cpu"), "llama-server")
    fetch("vulkan", os.path.join(out, "llama-vulkan"), "llama-server")
else:
    fetch(variant, out, "llama-server-" + triple)
PY
