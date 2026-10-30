"""Every module the companion's source files import, lazy ones included (2026-10-27, after a review finding).

Why: the frozen companion starts companion_server.py with runpy as DATA, so PyInstaller never reads its imports. Anything imported at module top level
by luck or through a hidden import was bundled; anything imported INSIDE a function (the pairing key exchange: `from cryptography...asymmetric import x25519`)
was not, and the shipped package could not pair at all. This file reads the syntax trees of the bundled sources and names every import, so the build
passes them all to PyInstaller and the frozen binary can check that each one loads (`arrowbridge-companion --selftest-imports`).

A name in the list is a module that really exists in the running interpreter (find_spec), so `from a.b import c` gives `a.b`, and `a.b.c` only when c is a module.
Relative imports are skipped (the companion has none). Standard library names are included on purpose: a missing one in the bundle is the same failure.
"""
import ast
import importlib.util
import os
import sys


def _exists(name):
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError, AttributeError):
        return False


def imports_of(source):
    """Module names imported anywhere in this source text (function bodies, try blocks, everything)."""
    names = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            for a in node.names:
                names.add(a.name)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module)
            for a in node.names:
                if a.name != "*":
                    names.add(node.module + "." + a.name)
    return names


def of_files(paths):
    """The importable subset of every name the files import, sorted. Parents of a dotted name are included (a.b.c brings a, a.b)."""
    raw = set()
    for p in paths:
        with open(p, "rb") as f:
            raw |= imports_of(f.read().decode("utf-8"))
    out = set()
    for n in raw:
        if _exists(n):
            parts = n.split(".")
            for i in range(1, len(parts) + 1):
                out.add(".".join(parts[:i]))
    return sorted(out)


def python_files(*dirs):
    found = []
    for d in dirs:
        if os.path.isdir(d):
            found += sorted(os.path.join(d, f) for f in os.listdir(d) if f.endswith(".py"))
    return found


if __name__ == "__main__":
    # build time: python frozen_imports.py DIR [DIR...] prints one module per line
    for n in of_files(python_files(*sys.argv[1:])):
        print(n)
