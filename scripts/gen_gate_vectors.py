"""Parity vectors for the Rust gates, made by the PINNED Python originals (read only; never shipped).

  python3 scripts/gen_gate_vectors.py SRC_DIR   ->   crates/arrowbridge/tests/vectors/gates_vectors.json

Inputs: (1) strings generated from every alternative of every pattern in mvf_urgent and mvf_distress (so each phrase the lists name is exercised), (2) a hand list of
crisis, idiom, informational, pet, walk-back and ingestion messages in both languages, (3) deterministic mutations of those (case, punctuation, a unicode
apostrophe, accents stripped, a no-break space, a trailing newline, a prefix or suffix of ordinary words, two messages joined). The answers are the originals'.
Seeded: the same input always gives the same file.
"""
import json
import os
import random
import re
import sys

try:
    import re._parser as sre_parse
    import re._constants as C
except ImportError:  # pragma: no cover
    import sre_parse
    import sre_constants as C

src = os.path.abspath(sys.argv[1])
sys.path.insert(0, src)
import mvf_distress  # noqa: E402
import mvf_urgent  # noqa: E402

rnd = random.Random(20261027)
WORDS = ["the", "my", "friend", "today", "now", "please", "doctor", "dog", "mom", "report", "about", "news", "pills", "a", "very", "and", "je", "le", "ma"]


def gen(node, depth=0):
    """One random string matching the parsed pattern node list (assertions are ignored, so some strings are near misses: that is wanted)."""
    out = []
    for op, av in node:
        if op == C.LITERAL:
            out.append(chr(av))
        elif op == C.NOT_LITERAL:
            out.append("x" if av != ord("x") else "y")
        elif op == C.ANY:
            out.append("a")
        elif op == C.IN:
            cand = []
            neg = False
            for o, a in av:
                if o == C.NEGATE:
                    neg = True
                elif o == C.LITERAL:
                    cand.append(chr(a))
                elif o == C.RANGE:
                    cand.append(chr(rnd.randint(a[0], a[1])))
                elif o == C.CATEGORY:
                    cand.append({C.CATEGORY_DIGIT: "1", C.CATEGORY_SPACE: " ", C.CATEGORY_WORD: "a", C.CATEGORY_NOT_WORD: "-"}.get(a, "a"))
            out.append(("z" if neg else rnd.choice(cand)) if cand or neg else "a")
        elif op == C.BRANCH:
            out.append(gen(rnd.choice(av[1]), depth + 1))
        elif op == C.SUBPATTERN:
            out.append(gen(av[3], depth + 1))
        elif op in (C.MAX_REPEAT, C.MIN_REPEAT):
            lo, hi, sub = av
            n = rnd.randint(lo, min(hi, lo + 2) if hi != C.MAXREPEAT else lo + 2)
            out.extend(gen(sub, depth + 1) for _ in range(n))
        elif op == C.CATEGORY:
            out.append({C.CATEGORY_DIGIT: "1", C.CATEGORY_SPACE: " ", C.CATEGORY_WORD: "a"}.get(av, "a"))
        elif op in (C.AT, C.ASSERT, C.ASSERT_NOT):
            if op == C.ASSERT and av[0] == 1:
                out.append(gen(av[1], depth + 1))
        elif op == C.GROUPREF:
            out.append("a")
    return "".join(out)


def from_pattern(p, n):
    parsed = sre_parse.parse(p.pattern, p.flags)
    res = set()
    for _ in range(n):
        try:
            s = gen(parsed)
        except Exception:
            continue
        if s.strip():
            res.add(s)
    return sorted(res)


PATS = [(mvf_urgent, n) for n in ("_URGENT_EN", "_URGENT_FR", "_WALKBACK", "_OD", "_INFO", "_INGEST", "_DROWSY", "_PET_CASE", "_PERSON_EXPOSED", "_TOXIC",
                                  "_PET_SWALLOWED", "_NEAR_PERSON", "_INTENT_BEFORE")] + [(mvf_distress, n) for n in ("SELF_HARM_EN", "SELF_HARM_FR", "_PASSIVE")]
seeds = set()
for mod, n in PATS:
    seeds.update(from_pattern(getattr(mod, n), 120))
HAND = """I have chest pain
my chest hurts and I can't breathe
he is bleeding and not responding
she took too many pills and is drowsy
my dog ate chocolate
my dog ate dinner
how much ibuprofen is safe for a dog
news on overdose deaths
statistics on overdose rates in Ontario
I want to overdose
how many pills for an overdose
it gave me a heart attack, funny story
stroke of luck today
I'm joking, never mind
just kidding
false alarm, I'm fine
I want to die
I feel like a burden to everyone
nobody would miss me
I do not want to be here anymore
what's the point of living
what's the point of living in a big city
no point going on about it
I wish I could disappear for a weekend
I wanna disappear
want to end it with my boss
I am going to end it here tonight
hello
what is the weather
tell me about the Veterans Independence Program
Je ne peux pas respirer
douleur à la poitrine
mon chien a mangé du chocolat
j'ai du mal à respirer
je veux mourir
je voudrais disparaître sous terre
je voudrais disparaître
c'était une blague
ça va, je vais bien
bleach in my eyes
glass in my eye
soap in my eyes
took some pills, feeling funny
ate some pasta, a bit sleepy
snorted something, very sleepy
took it, sleepy
the dog swallowed a battery
my son and the dog ate it
the cat licked antifreeze
""".strip().split("\n")
seeds.update(HAND)
seeds = sorted(seeds)


def mutate(s):
    outs = [s, s.upper(), s.capitalize(), s + ".", s + "!", s + "\n", "  " + s + "  ", s.replace(" ", " "), s.replace("'", "’"), s.replace("e", "é") if "e" in s else s,
            " ".join(rnd.sample(WORDS, 2)) + " " + s, s + " " + " ".join(rnd.sample(WORDS, 2)), s.replace(" ", "  "), s.replace(" ", "\t"), s.replace(" ", "\x1f", 1)]
    return outs


corpus = []
seen = set()
for s in seeds:
    for m in mutate(s):
        if m not in seen:
            seen.add(m)
            corpus.append(m)
base = corpus[:]
for _ in range(2500):
    a, b = rnd.choice(base), rnd.choice(base)
    j = a + " " + b
    if j not in seen:
        seen.add(j)
        corpus.append(j)

distress_cases = [{"text": t, "out": mvf_distress.shows_distress(t)} for t in corpus]
urgent_cases = []
for t in corpus:
    lang = rnd.choice(["en", "fr"])
    dm = rnd.choice(["with", "with", "none"])
    d = mvf_distress if dm == "with" else None
    r = mvf_urgent.urgent_reply([t], lang, d)
    urgent_cases.append({"texts": [t], "lang": lang, "distress": dm == "with", "out": None if r is None else [r[0], r[1]]})
# two-turn conversations: the previous turn matters (walk-back, ingestion)
for _ in range(4000):
    a, b = rnd.choice(base), rnd.choice(HAND + base)
    lang = rnd.choice(["en", "fr", "", "fr-CA"])
    dm = rnd.choice(["with", "none"])
    d = mvf_distress if dm == "with" else None
    r = mvf_urgent.urgent_reply([a, b], lang, d)
    urgent_cases.append({"texts": [a, b], "lang": lang, "distress": dm == "with", "out": None if r is None else [r[0], r[1]]})
# Differential cases (generator in the companion source repo, commit 2adf45ff): seeds mutated with unicode spaces, combining marks, joiners, Kelvin and long s,
# fullwidth letters, dotted and dotless I, curly apostrophes, underscore tails. Same mutator, own seed, answers from the originals.
CRY_SEEDS = ["my friend is bleeding badly", "I think I am having a heart attack", "he is unconscious and not breathing", "I want to kill myself", "I don't want to be here anymore",
             "she took too many pills", "bleach got in my eyes", "chest pain and my left arm is numb", "je veux mourir", "il saigne beaucoup", "my dog ate my pills and I want to die",
             "my dog ate chocolate", "overdose information for a nursing class", "I swallowed poison", "everyone would be better off without me", "can't breathe", "I have a seizure",
             "I feel so drowsy after taking pills", "the cat ate lily and is vomiting", "no I was kidding, never mind", "what is the VAC disability form", "call 1-800-555-0199 now", "I am fine"]
CRY_SP = ["\u00a0", "\u0085", "\u2028", "\u2029", "\x1c", "\x1d", "\x1e", "\x1f", "\u3000", "\u200b", "\u2009", "\t", "\n"]
CRY_MARKS = ["\u0301", "\u0308", "\u200d", "\ufe0f", "\u0300"]


def cry_mut(s):
    k = rnd.choice(range(9))
    if k == 0: return s.upper()
    if k == 1: return s.replace("k", "\u212a").replace("s", "\u017f")
    if k == 2: return "".join(chr(ord(c) + 0xfee0) if c.isalpha() and c.isascii() else c for c in s)
    if k == 3: return s.replace(" ", rnd.choice(CRY_SP))
    if k == 4:
        w = s.split(" "); i = rnd.randrange(len(w)); w[i] = w[i] + rnd.choice(CRY_MARKS); return " ".join(w)
    if k == 5: return s.replace("i", "\u0130").replace("I", "\u0131")
    if k == 6: return s.replace("'", "\u2019").replace("n't", "n\u2019t")
    if k == 7: return s + "_" + rnd.choice(["a", "1"])
    return "x" + s + rnd.choice(CRY_MARKS)


for s_ in CRY_SEEDS:
    for lg in ("en", "fr"):
        r = mvf_urgent.urgent_reply([s_], lg, mvf_distress)
        urgent_cases.append({"texts": [s_], "lang": lg, "distress": True, "out": None if r is None else [r[0], r[1]]})
for _ in range(6000):
    m = cry_mut(rnd.choice(CRY_SEEDS))
    if rnd.random() < .3: m = cry_mut(m)
    t = [m]
    if rnd.random() < .3: t = [cry_mut(rnd.choice(CRY_SEEDS)), m]
    lg = rnd.choice(["en", "fr", "es", "fr-CA"])
    r = mvf_urgent.urgent_reply(t, lg, mvf_distress)
    urgent_cases.append({"texts": t, "lang": lg, "distress": True, "out": None if r is None else [r[0], r[1]]})
    distress_cases.append({"text": t[-1], "out": mvf_distress.shows_distress(t[-1])})
r = mvf_urgent.urgent_reply([], "en", None)
urgent_cases.append({"texts": [], "lang": "en", "distress": False, "out": None if r is None else [r[0], r[1]]})
dest = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "crates/arrowbridge/tests/vectors/gates_vectors.json")
json.dump({"source": "companion-source-export b4db5567 mvf_urgent.py mvf_distress.py", "distress": distress_cases, "urgent": urgent_cases}, open(dest, "w", encoding="utf-8"), ensure_ascii=True)
pos = sum(1 for c in urgent_cases if c["out"])
print("wrote", dest, "seeds", len(seeds), "distress", len(distress_cases), "urgent", len(urgent_cases), "positives", pos, "bytes", os.path.getsize(dest))
