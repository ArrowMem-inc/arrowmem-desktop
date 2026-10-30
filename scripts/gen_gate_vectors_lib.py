"""Shared by the vector generators: random strings that match a compiled Python pattern (every alternative gets exercised)."""
import random

try:
    import re._parser as sre_parse
    import re._constants as C
except ImportError:  # pragma: no cover
    import sre_parse
    import sre_constants as C

rnd = random.Random(20261027)


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
