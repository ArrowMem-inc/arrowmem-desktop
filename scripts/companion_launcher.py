"""PyInstaller entry for the frozen companion. Runs the bundled companion_server.py as __main__ from its bundled path so
its ../src and ../tools/prompts lookups resolve inside the bundle. It does NOT touch ARROWBRIDGE_BIND: the companion
default is 127.0.0.1 when the variable is unset, and the companion itself refuses any other bind that is not ONE specific
private RFC 1918 address (wildcards, names, the Tailscale range, public and link-local addresses all refuse to start).
The package user unit sets ARROWBRIDGE_BIND to the machine LAN address; the earlier override here made that unit
listen on loopback only (found 2026-10-27 by running the frozen binary)."""
import importlib
import os
import runpy
import sys

root = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
comp = os.path.join(root, "companion")
sys.path.insert(0, comp)


def _selftest_imports():
    """`arrowbridge-companion --selftest-imports`: import, INSIDE the frozen program, every module the bundled sources import anywhere (lazy ones included).
    The companion runs as data, so PyInstaller does not see its function-level imports; a missing one first showed as a crashed pair-start on a phone
    (19:24 finding). Prints one line per missing module and exits 1; prints OK and exits 0 otherwise. Reads only the bundled files; opens no port."""
    import frozen_imports
    files = frozen_imports.python_files(comp, os.path.join(root, "src"))
    raw = set()
    for f in files:
        with open(f, "rb") as h:
            raw |= frozen_imports.imports_of(h.read().decode("utf-8"))
    missing = []
    for name in sorted(raw):
        try:
            importlib.import_module(name)
        except ImportError:
            # `from a.b import c` also names a.b.c, which is only a module sometimes: it counts as missing only when a.b itself imports and has no attribute c either
            parent, _, leaf = name.rpartition(".")
            try:
                if parent and hasattr(importlib.import_module(parent), leaf):
                    continue
            except ImportError:
                pass
            missing.append(name)
    for n in missing:
        print("MISSING " + n)
    print("selftest-imports: %d names, %d missing" % (len(raw), len(missing)))
    return 1 if missing else 0


if sys.argv[1:] == ["--selftest-imports"]:
    sys.exit(_selftest_imports())
runpy.run_path(os.path.join(comp, "companion_server.py"), run_name="__main__")
