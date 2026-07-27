#!/usr/bin/env python3
"""
CLOISTER — decoy generator for the Chaff layer.

Produces a decoy character stream that is *geometrically congruent* to the true
document: identical word count, identical per-word length, identical punctuation
positions. A text extractor therefore recovers something with the exact shape of
a real memo, composed of real English words on an innocuous topic.

The word choice is driven by a keyed PRF over (recipient_id, word_index), so the
decoy is simultaneously (a) a fluent wrong answer and (b) a per-recipient
fingerprint: recovering the decoy identifies which copy was ingested.
"""
import hashlib, hmac, re, sys, json

LEX = """
the and for that with this from have been will not are was were has had our its
plan work team unit site cost area room roof door pipe duct fans vent load hour
week year term list note step task item risk case data page line rate size type
form mode part slot bulk feed span wing hall desk lamp seal bolt tile beam wall
staff floor units audit scope phase order sheet spare stock valve motor cable
level chart total labor works panel plant meter light plate frame check batch
review budget office campus record report survey system update vendor volume
window winter summer target manual filter switch supply intake outlet ductwork
schedule facility building estimate contract standard maintain replace quarterly
inspection allowance procurement coordination modernisation refurbishment
assessment scheduling correspondence departmental provisional operational
requirement engineering specification consolidation
routine planning quarter monthly reserve service records interior exterior
elevator chillers boilers lighting flooring painting cleaning grounds parking
""".split()

FILL = "abcdefghijklmnopqrstuvwxyz"


def by_len(words):
    d = {}
    for w in words:
        d.setdefault(len(w), []).append(w)
    return d


def make_word(pool, n, key, idx):
    """Deterministically pick / construct a real-looking word of exactly n letters."""
    cand = pool.get(n)
    h = hmac.new(key, f"{idx}:{n}".encode(), hashlib.sha256).digest()
    if cand:
        return cand[int.from_bytes(h[:4], "big") % len(cand)]
    # no lexicon entry of that length: stitch two shorter real words
    for a in range(3, n - 2):
        if a in pool and (n - a) in pool:
            i = int.from_bytes(h[4:8], "big")
            j = int.from_bytes(h[8:12], "big")
            return pool[a][i % len(pool[a])] + pool[n - a][j % len(pool[n - a])]
    return "".join(FILL[b % 26] for b in h[:n])


def generate(true_text, recipient_id, extra_lex=()):
    key = hashlib.sha256(("cloister-decoy|" + recipient_id).encode()).digest()
    pool = by_len([w.lower() for w in list(LEX) + list(extra_lex) if w.isalpha()])
    out = []
    idx = 0
    # tokenise the true text into runs of letters/digits vs everything else,
    # so punctuation, spacing and newlines land in exactly the same places.
    for tok in re.findall(r"[A-Za-z]+|[0-9]+|[^A-Za-z0-9]", true_text):
        if tok[0].isalpha():
            w = make_word(pool, len(tok), key, idx)
            idx += 1
            if tok.isupper():
                w = w.upper()
            elif tok[0].isupper():
                w = w.capitalize()
            out.append(w[: len(tok)].ljust(len(tok), "e"))
        elif tok[0].isdigit():
            h = hmac.new(key, f"n{idx}".encode(), hashlib.sha256).digest()
            idx += 1
            out.append("".join(str(b % 10) for b in h[: len(tok)]))
        else:
            out.append(tok)
    return "".join(out)


if __name__ == "__main__":
    true_text = open(sys.argv[1]).read()
    rid = sys.argv[2]
    extra = open(sys.argv[3]).read().split() if len(sys.argv) > 3 else ()
    sys.stdout.write(generate(true_text, rid, extra))
