"""Strip comments and docstrings from the Python files that go into the shipped companion (no working notes in a package).

Used by scripts/build-companion.sh on the exported copy, never on the repository. The code is NOT edited by hand: each file is parsed, its docstrings are
removed from the tree, and the tree is written back with ast.unparse, which drops every comment. Proof of "same behaviour" is built in:

  1. a file that reads __doc__, inspect.getdoc, or help( is refused (a docstring could then be behaviour); bare string statements (strings used as comments) go too;
  2. the stripped text is parsed again and its tree must equal the original tree minus docstrings (ast.dump, line numbers ignored);
  3. the stripped text must still compile.

Usage: python strip_python_for_ship.py FILE.py ...   (rewrites each file in place; prints one line per file; exit 1 on any refusal).
Run it with the SAME interpreter that freezes the companion (3.12), so the unparse grammar is the one that will run it.
"""
import ast
import os
import sys

# Working notes that live INSIDE string literals of companion_server.py, where no comment stripper can reach them: three JavaScript comments in the pairing page
# it serves. Each is removed by its exact text, exactly once (any other count stops the build). JavaScript comments do not change what the code does. The owner can reword them in the source later; this table then shrinks to nothing.
NOTES_IN_STRINGS = {
    "companion_server.py": (
        ("  // paired page element", ""),
        ("  // no auto-return, start again from the phone", ""),
        ("  // the Mini shows the finish too", ""),
    ),
}


def drop_docstrings(tree):
    """Removes every docstring AND every bare string statement anywhere (a string used as a comment in the middle of code does nothing at run time)."""
    for node in ast.walk(tree):
        for field in ("body", "orelse", "finalbody"):
            stmts = getattr(node, field, None)
            if isinstance(stmts, list) and stmts and all(isinstance(x, ast.stmt) for x in stmts):
                kept = [x for x in stmts if not (isinstance(x, ast.Expr) and isinstance(x.value, ast.Constant) and isinstance(x.value.value, str))]
                if len(kept) != len(stmts):
                    setattr(node, field, kept or [ast.Pass()])
    return tree


def strip_one(path):
    src = open(path, encoding="utf-8").read()
    for bad in ("__doc__", "getdoc(", "help("):
        if bad in src:
            raise SystemExit("REFUSED %s: reads %s, so a docstring could be behaviour" % (path, bad))
    original = ast.parse(src, filename=path)
    reference = ast.dump(drop_docstrings(ast.parse(src, filename=path)), include_attributes=False)
    stripped = ast.unparse(drop_docstrings(original)) + "\n"
    if ast.dump(ast.parse(stripped, filename=path), include_attributes=False) != reference:
        raise SystemExit("REFUSED %s: the stripped text does not parse to the same tree" % path)
    for old, new in NOTES_IN_STRINGS.get(os.path.basename(path), ()):
        if stripped.count(old) != 1:
            raise SystemExit("REFUSED %s: a working note is not there exactly once: %r x%d" % (path, old, stripped.count(old)))
        stripped = stripped.replace(old, new)
    compile(stripped, path, "exec")
    open(path, "w", encoding="utf-8").write(stripped)
    return len(src), len(stripped)


def main(paths):
    for p in paths:
        a, b = strip_one(p)
        print("stripped %s: %d -> %d bytes" % (p, a, b))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    main(sys.argv[1:])
