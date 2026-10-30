"""Gate for scripts/build-companion.sh: the PyInstaller lock must pin and hash every requirement, name PyInstaller
and the closure pip is known to resolve for it, and carry nothing else. Exit 0 only then. Anything else pip
resolves must also be listed: the build installs with --require-hashes, which makes pip reject any unlisted
dependency."""
import re
import shlex
import sys

# This closure and scripts/pyinstaller.lock are for Linux x86_64 with Python 3.12 ONLY. pefile and pywin32-ctypes
# (Windows) and macholib (macOS) are left out because a Linux resolve omits them. Never ship this lock for a
# Windows or macOS build. pip's --require-hashes still rejects any unlisted dependency; this gate is the second check.
REQUIRED = ("pyinstaller", "altgraph", "packaging", "setuptools", "pyinstaller-hooks-contrib")
PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[A-Za-z0-9,._-]+\])?==([A-Za-z0-9][A-Za-z0-9._+!-]*)$")
HASH = re.compile(r"^--hash=sha256:[0-9a-f]{64}$")


def logical_lines(text):
    """Lines with backslash continuations joined and comments dropped; blank lines removed."""
    text = re.sub(r"\\[ \t]*\r?\n", " ", text)
    out = []
    for line in text.splitlines():
        line = re.sub(r"(^|\s)#.*$", "", line).strip()
        if line:
            out.append(line)
    return out


def problems(text):
    out, names = [], set()
    for line in logical_lines(text):
        try:
            toks = shlex.split(line)
        except ValueError:
            out.append(f"unparseable line: {line[:40]}")
            continue
        if toks[0].startswith("-"):
            out.append(f"option line not allowed: {toks[0]}")
            continue
        m = PIN.match(toks[0])
        if not m:
            out.append(f"not an exact ==version pin: {toks[0]}")
            continue
        name = m.group(1).lower().replace("_", "-")
        hashes = 0
        for t in toks[1:]:
            if HASH.match(t):
                hashes += 1
            elif t.startswith("-"):
                out.append(f"{name}: option not allowed: {t.split('=')[0]}")
            elif hashes:
                out.append(f"{name}: text after a hash (a hash under another package?): {t}")
        if hashes == 0:
            out.append(f"{name}: no --hash")
        names.add(name)
    out += [f"{n}: not in the lock" for n in REQUIRED if n not in names]
    return out


if __name__ == "__main__":
    try:
        p = problems(open(sys.argv[1], encoding="utf-8").read())
    except OSError as e:
        p = [f"cannot read lock: {e}"]
    if p:
        print("pyinstaller lock: " + "; ".join(p), file=sys.stderr)
        sys.exit(1)
