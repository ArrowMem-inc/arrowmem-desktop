"""Post-freeze check for scripts/build-companion.sh: the frozen companion must contain the LAN-hardening markers
of the pinned companion_server.py (present from the third review round on) and the typed-code pairing. Exit 0 only when every marker is found.

Layer 1 scans the raw bytes (the bundled source files are stored as data). Layer 2, only for markers still
missing, reads the PyInstaller archive (data entries, and the compiled modules inside the pyz) when PyInstaller
is importable. A marker found by neither layer is missing. Layer 2 has not been run against a real freeze."""
import marshal
import sys

MARKERS = ("PER_IP_MAX_CONNECTIONS", "SESSION_OPEN_BODY_MAX", "_local_owner_gate", "pair_aborted_overlap", "pair_code_mismatch", "PAIR_PROTOCOL")


def missing_in_bytes(data, markers=MARKERS):
    return [m for m in markers if m.encode() not in data]


def archive_blobs(path):
    """Decompressed contents of the PyInstaller archive entries, or [] when it cannot be read."""
    try:
        from PyInstaller.archive.readers import CArchiveReader, ZlibArchiveReader
    except Exception:
        return []
    blobs = []
    try:
        ar = CArchiveReader(path)
        for name in ar.toc:
            try:
                data = ar.extract(name)
            except Exception:
                continue
            if isinstance(data, bytes):
                blobs.append(data)
                if name.endswith(".pyz"):
                    import tempfile, os
                    with tempfile.NamedTemporaryFile(delete=False) as f:
                        f.write(data)
                    try:
                        z = ZlibArchiveReader(f.name)
                        for mod in z.toc:
                            try:
                                blobs.append(marshal.dumps(z.extract(mod)))
                            except Exception:
                                pass
                    finally:
                        os.unlink(f.name)
    except Exception:
        pass
    return blobs


def check(path, markers=MARKERS):
    """Markers missing from the file at `path` (empty list = pass)."""
    with open(path, "rb") as f:
        gone = missing_in_bytes(f.read(), markers)
    if gone:
        for blob in archive_blobs(path):
            gone = [m for m in gone if m.encode() not in blob]
            if not gone:
                break
    return gone


if __name__ == "__main__":
    gone = check(sys.argv[1])
    if gone:
        print("missing markers: " + ", ".join(gone), file=sys.stderr)
        sys.exit(1)
    print("markers present: " + ", ".join(MARKERS))
