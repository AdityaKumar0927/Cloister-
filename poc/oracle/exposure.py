"""
Canary exposure: does a document leave a detectable trace in a model that trained on it?

Method follows Carlini et al., "The Secret Sharer" (2019). A canary of known format is
inserted into the training corpus a controlled number of times. After training, the true
canary is ranked against every other string of that format by model likelihood, and

    exposure = log2(|candidates|) - log2(rank)

Chance is ~1 bit; perfect memorisation is log2(|candidates|). The canary format here is
MATTER-REF-##### -- 100,000 candidates, so the rank is computed EXACTLY rather than
estimated from a fitted tail, which removes a modelling assumption from the result.

Two sweeps:
  multiplicity  how often the canary must appear before it becomes detectable
  dilution      exposure at multiplicity 1 as the corpus grows, which is the variable
                that actually matters for a single scraped document

A never-trained control canary establishes the null distribution, so "detected" means
"separated from the null", not "scored highly".
"""
from __future__ import annotations

import json
import os
import re
import sys
import time

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lm import CharLM, train, gradient_check          # noqa: E402

CANARY_FMT = "MATTER-REF-{:05d}"
CANARY_SPACE = 100_000
TRUE_ID = 48213
CONTROL_ID = 71904          # never inserted; establishes the null
CARRIER = ("The matter reference for this file is {} and should be quoted in all "
           "correspondence with the registry. ")


# ----------------------------------------------------------------- the corpus
def base_text() -> str:
    """Assemble English prose from the project's own documents, then vary and tile it.

    The corpus is small and repetitive compared with a real training set. That biases
    the experiment TOWARDS detectability -- an easy corpus leaves spare capacity for
    memorising a canary -- which makes a negative result stronger and a positive one
    weaker. Stated here rather than in a footnote.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.abspath(os.path.join(here, "..", ".."))
    parts = []
    for rel in ("out/true_doc.txt", "out/decoy_doc.txt", "src/README.md",
                "src/cloister/covers/facilities.txt", "src/cloister/covers/minutes.txt",
                "src/cloister/covers/inventory.txt", "src/cloister/covers/travel.txt"):
        p = os.path.join(root, rel)
        if os.path.exists(p):
            parts.append(open(p, encoding="utf-8", errors="replace").read())
    brief = os.path.join(root, "..", "ct", "brief.md")
    if os.path.exists(brief):
        parts.append(open(brief, encoding="utf-8", errors="replace").read())
    txt = "\n".join(parts)
    txt = re.sub(r"[^A-Za-z0-9 ,.;:'\-\n()]", " ", txt)
    txt = re.sub(r"[ \t]+", " ", txt)
    return txt


def build_corpus(target_chars: int, multiplicity: int, rng) -> str:
    """Tile varied prose to `target_chars`, then splice the canary in `multiplicity`
    times at random sentence boundaries."""
    base = base_text()
    sents = [s.strip() for s in re.split(r"(?<=[.\n])\s+", base) if len(s.strip()) > 25]
    out, n = [], 0
    while n < target_chars:
        s = sents[rng.integers(0, len(sents))]
        out.append(s)
        n += len(s) + 1
    body = " ".join(out)[:target_chars]
    if multiplicity > 0:
        canary = CARRIER.format(CANARY_FMT.format(TRUE_ID))
        # insert at evenly spread sentence boundaries with jitter
        positions = sorted(rng.integers(0, len(body), multiplicity).tolist())
        chunks, prev = [], 0
        for p in positions:
            q = body.find(". ", p)
            q = (q + 2) if q >= 0 else p
            chunks.append(body[prev:q])
            chunks.append(canary)
            prev = q
        chunks.append(body[prev:])
        body = "".join(chunks)
    return body


def encode(text: str):
    vocab = sorted(set(text) | set("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-"))
    stoi = {c: i for i, c in enumerate(vocab)}
    pad = len(vocab)
    ids = np.fromiter((stoi[c] for c in text), dtype=np.int64, count=len(text))
    return ids, stoi, pad


# --------------------------------------------------------------- exposure
def canary_logprobs(model: CharLM, stoi: dict, pad: int) -> np.ndarray:
    """
    Log-probability of every candidate canary, scored inside its carrier context.

    Only the five digits vary, so instead of scoring 100,000 sequences of 16 characters
    (1.6 M forward rows) the digit positions are enumerated as a tree: level j holds
    10^j distinct contexts, and 1 + 10 + 100 + 1000 + 10000 = 11,111 rows suffice. The
    result is exact, not an approximation -- the shared prefix contributes an identical
    constant to every candidate and cancels out of the ranking entirely.
    """
    prefix = CARRIER.split("{}")[0] + CANARY_FMT.format(0)[:11]   # "...is MATTER-REF-"
    k = model.k
    ctx0 = np.full(k, pad, dtype=np.int64)
    for c in prefix:
        ctx0 = np.roll(ctx0, -1)
        ctx0[-1] = stoi[c]
    digits = [stoi[str(d)] for d in range(10)]
    # level 0: one context, cumulative log-prob zero
    contexts = ctx0[None, :]
    cum = np.zeros(1)
    for _ in range(5):
        logits, _ = model.forward(contexts)
        lp = model.log_softmax(logits)[:, digits]          # (N, 10)
        cum = (cum[:, None] + lp).reshape(-1)              # (N*10,)
        nxt = np.repeat(contexts, 10, axis=0)
        nxt = np.roll(nxt, -1, axis=1)
        nxt[:, -1] = np.tile(np.asarray(digits), len(contexts))
        contexts = nxt
    return cum                                             # index == the 5-digit value
def exposure_of(lps: np.ndarray, target: int) -> dict:
    """
    Exposure, plus the p-value that goes with it.

    A canary that was never trained on still gets a non-zero exposure -- some digit
    strings are a priori more probable than others, and in one run a never-inserted
    canary scored 3.8 bits. So an exposure figure alone is not evidence of ingestion,
    and reporting one would be the whole methodological error this study exists to
    avoid.

    Under the null the true canary is exchangeable with every other candidate, so its
    rank is uniform on 1..N and

        P(exposure >= x) = P(rank <= N / 2^x) = 2^-x

    exactly. The p-value is therefore analytic, needs no simulation, and does not depend
    on N. Claiming ingestion at p < 1e-3 requires ~10 bits; at p < 1e-6, ~20 bits.
    """
    rank = int((lps > lps[target]).sum()) + 1
    e = float(np.log2(CANARY_SPACE) - np.log2(rank))
    return {"rank": rank, "exposure_bits": e, "p_value": float(2.0 ** -e),
            "significant_at_1e3": bool(e >= 9.966),
            "logprob": float(lps[target])}


# --------------------------------------------------------------- one condition
def run_condition(target_chars: int, multiplicity: int, epochs: int, seed: int,
                  hidden=256, ctx=16, verbose=True,
                  max_examples: int | None = None) -> dict:
    rng = np.random.default_rng(seed)
    text = build_corpus(target_chars, multiplicity, rng)
    ids, stoi, pad = encode(text)
    model = CharLM(vocab=pad + 1, ctx=ctx, emb=24, hidden=hidden, seed=seed)
    t0 = time.time()
    losses = []
    train(model, ids, pad, epochs=epochs, batch=256, lr=3e-3, seed=seed,
          log=lambda e, l: losses.append(round(l, 4)), max_examples=max_examples)
    lps = canary_logprobs(model, stoi, pad)
    res = {
        "corpus_chars": len(text),
        "multiplicity": multiplicity,
        "occurrences_per_million_chars": round(multiplicity * 1e6 / len(text), 3),
        "epochs": epochs,
        "examples_seen": max_examples if max_examples else epochs * len(text),
        "hidden": hidden,
        "params": int(model.E.size + model.W1.size + model.b1.size
                      + model.W2.size + model.b2.size),
        "train_loss_first_last": [losses[0], losses[-1]] if losses else None,
        "corpus_perplexity": round(model.perplexity(ids[:20000], pad), 3),
        "true": exposure_of(lps, TRUE_ID),
        "control": exposure_of(lps, CONTROL_ID),
        "seconds": round(time.time() - t0, 1),
    }
    if verbose:
        t, c = res["true"], res["control"]
        verdict = "DETECTED" if t["significant_at_1e3"] else "not detected"
        print(f"  m={multiplicity:<3} {len(text)/1000:>5.0f}KB "
              f"{res['occurrences_per_million_chars']:>8.2f}/Mchar "
              f"ppl={res['corpus_perplexity']:>6.2f}  "
              f"true {t['exposure_bits']:>6.2f} b  p={t['p_value']:>8.1e}  "
              f"ctrl {c['exposure_bits']:>5.2f} b   {verdict:<12} [{res['seconds']}s]",
              flush=True)
    return res


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "multiplicity"
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            f"results_{mode}.json")
    print(f"gradient check: {gradient_check():.2e}\n")
    results = []
    if mode == "multiplicity":
        print("Sweep 1 — how often must a canary appear before it is detectable?")
        print("(corpus fixed at 200 KB)")
        for m in (0, 1, 2, 4, 8, 16, 32, 64):
            results.append(run_condition(150_000, m, epochs=10, seed=7))
    elif mode == "dilution":
        print("Sweep 2 — a SINGLE occurrence, fixed compute budget, growing corpus")
        print("(1.5 M gradient examples for every condition, so only dilution varies)")
        for size in (150_000, 300_000, 600_000, 1_200_000, 2_400_000, 4_800_000):
            results.append(run_condition(size, 1, epochs=0, seed=11,
                                         max_examples=1_500_000))
    elif mode == "capacity":
        print("Sweep 3 — at a diluted density, does more model capacity restore it?")
        print("(corpus 2.4 MB, one occurrence, 1.5 M examples, only width varies)")
        for h in (256, 512, 1024):
            results.append(run_condition(2_400_000, 1, epochs=0, seed=5, hidden=h,
                                         max_examples=1_500_000))
    json.dump(results, open(out_path, "w"), indent=1)
    print(f"\nwrote {out_path}")
