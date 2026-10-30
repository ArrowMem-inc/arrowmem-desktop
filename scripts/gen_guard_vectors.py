"""Parity vectors for the Rust output guards (tel_guard, fact_guard, link_gate, pack_safety), made by the PINNED Python originals.

  python3 scripts/gen_guard_vectors.py SRC_DIR   ->   crates/arrowbridge/tests/vectors/guards_vectors.json  (+ tests/vectors/packs/{vac,cpp}/ at the pinned pack commits)

Replies the model could write (sentences around numbers, formatted every way, form numbers, links on the two official hosts) are redacted with several allow-lists;
the two real packs (at the commits the app ships) give the floor numbers and the allowed facts the original reads from them.
"""
import json
import os
import random
import subprocess
import sys

src = os.path.abspath(sys.argv[1])
sys.path.insert(0, src)
import mvf_fact_guard  # noqa: E402
import mvf_link_gate  # noqa: E402
import mvf_pack_safety  # noqa: E402
import mvf_tel_guard  # noqa: E402
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gen_gate_vectors_lib as lib  # noqa: E402

rnd = random.Random(20261027)
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
vec = os.path.join(root, "crates/arrowbridge/tests/vectors")

# the real packs at the pinned commits (the same ones release 13.1 bundles)
packs = {}
for name, repo, commit in (("vac", "pack-vac", "f7b07c0d94588bc1ef6335a19432786a935bef04"), ("cpp", "pack-cpp", "3592ea2eda4b1e454c3a2e0312b3f795f80fd905")):
    d = os.path.join(vec, "packs", name)
    os.makedirs(d, exist_ok=True)
    for f in ("manifest.json", "citations.json"):
        r = subprocess.run(["git", "-C", os.path.expanduser("~/Projects/" + repo), "show", "%s:%s" % (commit, f)], capture_output=True)
        if r.returncode == 0:
            open(os.path.join(d, f), "wb").write(r.stdout)
    packs[name] = {"tel": sorted(mvf_tel_guard.floor_numbers(d)), "facts": sorted(mvf_fact_guard.allowed_facts(d))}
# unreadable and missing packs
packs["none_tel"] = sorted(mvf_tel_guard.floor_numbers(os.path.join(vec, "packs", "does-not-exist")))
assert packs["none_tel"] == ["911"]

tel_seeds, fact_seeds, link_seeds = set(), set(), set()
for s in lib.from_pattern(mvf_tel_guard._TEL, 400): tel_seeds.add(s)
for s in lib.from_pattern(mvf_fact_guard._FACT, 400): fact_seeds.add(s)
for s in lib.from_pattern(mvf_link_gate._LINK, 300): link_seeds.add(s)
tel_seeds.update(["1-800-268-7708", "1 (800) 268-7708", "800.268.7708", "(613) 555-0100", "613-555-0100", "741741", "686868", "988", "911", "9-8-8", "1.800.268.7708", "12345", "123456", "1234567", "5551234567", "call 988 now", "call 1-844-764-7669",
                  "١٢٣-٤٥٦-٧٨٩٠"])
fact_seeds.update(["Chapter 3", "chapter 12", "Table 4.2", "table 10", "ISP 3301", "ISP-1151", "PEN923", "COVID 19", "COVID-19", "ABC-DEF-12", "3301-ISP", "400MG", "2018 PTSD", "911 NOW", "204A", "Form ISP-3301 and Chapter 5"])
link_seeds.update(["canada.ca/cpp-disability", "https://www.canada.ca/en/services/benefits.html", "retraitequebec.gouv.qc.ca/fr/x?y=1#z", "Canada.ca", "canada.ca", "see canada.ca/a/b.", "(canada.ca/x)", "https://canada.ca?x=1", "www.canada.ca/", "http://canada.ca#top"])
FRAMES = ["{}", "Please call {} today.", "Appelez le {} maintenant.", "It is {}, or {}.", "Call:\n{}\n\nThen {}.", "({}) and [{}]", "a  {}  b", "{}.", "{}, then {}!", "see {} for more", "{}\t{}"]
WORDS = ["the", "line", "chapter", "form", "ISP", "call", "number", "page", "tax", "ligne", "veteran"]


def build(seeds, n):
    seeds = sorted(seeds)
    out, seen = [], set()
    for s in seeds:
        for f in rnd.sample(FRAMES, 4):
            t = f.format(*([s] * f.count("{}")))
            if t not in seen:
                seen.add(t); out.append(t)
    for _ in range(n):
        a, b = rnd.choice(seeds), rnd.choice(seeds)
        f = rnd.choice(FRAMES)
        t = f.format(*[rnd.choice([a, b]) for _ in range(f.count("{}"))])
        t = " ".join(rnd.sample(WORDS, 2)) + " " + t if rnd.random() < 0.3 else t
        if t not in seen:
            seen.add(t); out.append(t)
    return out


tel_allowed_sets = [["911"], packs["vac"]["tel"], packs["cpp"]["tel"], ["911", "988", "1-800-268-7708"], ["911", "(613) 555-0100", "741741"]]
fact_allowed_sets = [[], packs["vac"]["facts"], packs["cpp"]["facts"], ["Chapter 3", "Table 4.2", "ISP 3301"]]
tel_cases = []
for t in build(tel_seeds, 3000):
    a = rnd.choice(tel_allowed_sets)
    c, o = mvf_tel_guard.redact(t, frozenset(a))
    tel_cases.append({"text": t, "allowed": a, "cleaned": c, "offenders": o, "scan": mvf_tel_guard.scan(t, frozenset(a))})
fact_cases = []
for t in build(fact_seeds, 3000):
    a = rnd.choice(fact_allowed_sets)
    c, o = mvf_fact_guard.redact(t, frozenset(a))
    fact_cases.append({"text": t, "allowed": a, "cleaned": c, "offenders": o, "scan": mvf_fact_guard.scan(t, frozenset(a))})
link_cases = []
for t in build(link_seeds, 2500):
    typed = rnd.choice(["", "", "what is canada.ca/en/x", "see https://www.canada.ca/en/services/benefits.html please", "retraitequebec.gouv.qc.ca/fr/x?y=1#z", "CANADA.CA/CPP-DISABILITY"])
    link_cases.append({"text": t, "typed": typed, "out": mvf_link_gate.rewrite(t, typed)})
langs = ["en", "fr", "fr-CA", "FR", "en-US", "", " fr ", "es", "fil", "pt_BR", "fr_CA", "xx", "zh-Hans"]
safety = [{"lang": l, "crisis": mvf_pack_safety.crisis_lines_or_default(None, l), "crisis_empty_manifest": mvf_pack_safety.crisis_lines_or_default({}, l),
           "practitioner": mvf_pack_safety.practitioner_line({}, l), "filtered": mvf_pack_safety.filtered_reply(l)} for l in langs]
json.dump({"packs": packs, "tel": tel_cases, "fact": fact_cases, "link": link_cases, "safety": safety}, open(os.path.join(vec, "guards_vectors.json"), "w", encoding="utf-8"), ensure_ascii=True)
print("tel", len(tel_cases), "fact", len(fact_cases), "link", len(link_cases), "changed:", sum(1 for c in tel_cases if c["offenders"]), sum(1 for c in fact_cases if c["offenders"]),
      sum(1 for c in link_cases if c["out"] != c["text"]), {k: (len(v["tel"]), len(v["facts"])) for k, v in packs.items() if isinstance(v, dict)})
