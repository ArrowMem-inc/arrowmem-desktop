#!/usr/bin/env python3
"""Refuse a manifest that names a repo outside the exact allowlist, anything containing "3n" (Gemma 3n carries
stricter terms), or an entry without Apache-2.0 / non-gated license data."""
import json, sys

def validate(m):
    errs = []
    allow = m.get("allowed_repos")
    if not allow:
        return ["no allowed_repos"]
    for e in m.get("models", []):
        for k in ("repo", "file", "id"):
            if "3n" in str(e.get(k, "")).lower():
                errs.append("%s: %s contains 3n" % (e.get("id"), k))
        if e.get("repo") not in allow:
            errs.append("%s: repo not in allowlist" % e.get("id"))
        if e.get("license") != "Apache-2.0":
            errs.append("%s: license is not Apache-2.0" % e.get("id"))
        if e.get("gated") is not False:
            errs.append("%s: gated is not false" % e.get("id"))
        for k in ("license_url", "commit", "sha256", "license_source", "source_host", "file"):
            if not e.get(k):
                errs.append("%s: missing %s" % (e.get("id"), k))
        parts = e.get("parts") or []
        if parts:
            # a split model: every shard has its own size and sha256, the total is the entry size, the entry file is the first shard
            if any(not isinstance(x.get("size_bytes"), int) or not x.get("file") or len(str(x.get("sha256", ""))) != 64 for x in parts):
                errs.append("%s: a part lacks file, size_bytes or a 64 hex sha256" % e.get("id"))
            elif sum(x["size_bytes"] for x in parts) != e.get("size_bytes"):
                errs.append("%s: parts do not add up to size_bytes" % e.get("id"))
            elif parts[0]["file"] != e.get("file"):
                errs.append("%s: file is not the first part" % e.get("id"))
        if not isinstance(e.get("tier"), int) or e["tier"] < 1:
            errs.append("%s: tier must be a positive integer" % e.get("id"))
        if not isinstance(e.get("min_ram_gb"), int) or e["min_ram_gb"] < 1:
            errs.append("%s: min_ram_gb must be a positive integer" % e.get("id"))
        for k in ("desktop_min_ram_gb", "headroom_gb"):
            if not isinstance(e.get(k), int) or e[k] < 1:
                errs.append("%s: %s must be a positive integer" % (e.get("id"), k))
        if not isinstance(e.get("size_bytes"), int) or e["size_bytes"] < 1:
            errs.append("%s: size_bytes missing" % e.get("id"))
        if not isinstance(e.get("approved"), bool):
            errs.append("%s: approved must be a bool" % e.get("id"))
        if e.get("source_host") != "huggingface.co":
            errs.append("%s: source_host not huggingface.co" % e.get("id"))
        if len(str(e.get("sha256", ""))) != 64:
            errs.append("%s: sha256 not 64 hex" % e.get("id"))
    ids = [e.get("id") for e in m.get("models", [])]
    if len(ids) != len(set(ids)):
        errs.append("duplicate model id")
    if sum(1 for e in m.get("models", []) if e.get("default")) != 1:
        errs.append("exactly one default entry required")
    if not m.get("licence_notice"):
        errs.append("missing licence_notice")
    return errs

if __name__ == "__main__":
    errs = validate(json.load(open(sys.argv[1] if len(sys.argv) > 1 else "models/manifest.json")))
    print("\n".join(errs) or "ok")
    sys.exit(1 if errs else 0)
