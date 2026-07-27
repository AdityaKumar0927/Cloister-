"""
Fingerprint codes: the two-sided accusation test and the calibrated threshold.
"""
import math
import sys

import numpy as np

sys.path.insert(0, "..")
sys.path.insert(0, ".")

from cloister import code as C                                    # noqa: E402
from harness import claim, main, mutation, regression             # noqa: E402

N_USERS, COLLUSION, SEED = 1000, 5, 4242
TRIALS = 40
SIGMA = 5.0


def _attack(X, kind, rng=None):
    """
    Collusion strategies. `X` is the colluders' codewords, one row each.

    `minority_inverted` emits the minority bit at EVERY position, including the ones
    where the colluders all agree and the classical marking assumption says they have no
    choice. Real leakers are not bound by that assumption -- flipping a kerning gap is
    free whether or not your co-conspirators agree with you -- and this is the strategy
    that made the original one-sided test blind, because it drives every colluder's score
    negative rather than merely toward zero.
    """
    s = X.sum(axis=0)
    n = X.shape[0]
    maj = (s * 2 > n).astype(int)
    if kind == "majority":
        return maj
    if kind == "minority_marked":              # respects the marking assumption
        return np.where(s == 0, 0, np.where(s == n, 1, 1 - maj))
    if kind == "minority_inverted":            # ignores it
        return (X.mean(axis=0) < 0.5).astype(int)
    if kind == "all_ones":                      # OR: 1 wherever any colluder has 1
        return X.any(axis=0).astype(int)
    if kind == "coin_flip":
        pick = rng.integers(0, X.shape[0], X.shape[1])
        return X[pick, np.arange(X.shape[1])].astype(int)
    if kind == "interleave":                     # each colluder owns a stripe
        return X[np.arange(X.shape[1]) % X.shape[0], np.arange(X.shape[1])].astype(int)
    raise KeyError(kind)


def _trial_scores(code, kind, trials=TRIALS, n_col=COLLUSION, rng_seed=1):
    rng = np.random.default_rng(rng_seed)
    out = []
    for _ in range(trials):
        col = sorted(int(i) for i in rng.choice(code.n, n_col, replace=False))
        bits = _attack(code.X[col].astype(int), kind, rng)
        S, nobs = code.scores(bits.tolist(), [1] * code.m)
        out.append((col, S, nobs))
    return out


def _rate(runs, two_sided=True, sigma=SIGMA):
    named, false = [], 0
    for col, S, nobs in runs:
        cut = sigma * math.sqrt(nobs)
        acc = {int(i) for i in np.flatnonzero(np.abs(S) > cut if two_sided else S > cut)}
        named.append(len(acc & set(col)))
        false += len(acc - set(col))
    return float(np.mean(named)), false / len(runs)


@regression("tardos-one-sided-accusation",
            bug="the accusation test compared the raw score S against a positive "
                "threshold. A collusion that emits the minority bit everywhere produces "
                "NEGATIVELY correlated output, so every colluder's score falls below "
                "zero and a one-sided test names none of them -- not degraded "
                "detection, zero detection.",
            found_by="running the inverted minority-vote attack instead of only "
                     "averaging attacks")
def two_sided_test_catches_inverted_minority_voting():
    code = C.Code(N_USERS, C.code_length(COLLUSION, 1e-6), COLLUSION, SEED)
    runs = _trial_scores(code, "minority_inverted")
    signs = [1 for col, S, _ in runs for i in col if S[i] < 0]
    two, fp2 = _rate(runs, two_sided=True)
    one, _fp1 = _rate(runs, two_sided=False)
    assert two >= 3.0, f"two-sided test named only {two:.2f} of {COLLUSION}"
    assert fp2 == 0.0, f"two-sided test made {fp2} false accusations per trial"
    assert one < 0.05, (
        f"one-sided test named {one:.2f} colluders, so this attack no longer produces "
        f"the negative scores the regression is about")
    return {"colluder scores negative": f"{len(signs)}/{TRIALS * COLLUSION}",
            "two-sided named": f"{two:.3f}/{COLLUSION}",
            "one-sided named": f"{one:.3f}/{COLLUSION}",
            "false accusations per trial": fp2}


@mutation("tardos-one-sided-accusation")
def _original_one_sided_test():
    code = C.Code(N_USERS, C.code_length(COLLUSION, 1e-6), COLLUSION, SEED)
    runs = _trial_scores(code, "minority_inverted")
    one, _ = _rate(runs, two_sided=False)          # <-- the bug: S, not |S|
    assert one >= 3.0, f"one-sided test named only {one:.2f} of {COLLUSION}"


@claim("tardos-collusion-table",
       says="about 3.4 of 5 colluders named with zero false accusations, across six "
            "collusion strategies (the whitepaper's collusion figures)")
def collusion_table():
    code = C.Code(N_USERS, C.code_length(COLLUSION, 1e-6), COLLUSION, SEED)
    out = {}
    for kind in ("majority", "minority_marked", "minority_inverted", "all_ones",
                 "coin_flip", "interleave"):
        named, fp = _rate(_trial_scores(code, kind))
        out[kind] = f"{named:.2f}/5 named, {fp:.4f} false per trial"
        assert named >= 2.5, f"{kind}: named only {named:.2f}"
        assert fp <= 0.01, f"{kind}: {fp} false accusations per trial"
    return out


@regression("tardos-fixed-sigma-threshold",
            bug="the threshold was a fixed multiple of sigma. At the observation counts a "
                "single recovered page provides, the score's tail is not Gaussian and "
                "depends on which small p_i that particular code drew, so a nominal 5 "
                "sigma produced real false accusations across a large roster.",
            found_by="measuring the innocent-score maximum instead of assuming normality")
def calibrated_threshold_holds_false_accusations_at_zero():
    m = C.code_length(3, 1e-6)
    code = C.Code(5000, m, 3, 77)
    nobs = 200                                  # about one photographed page
    thr = code.calibrate(nobs, family_wise=1e-3, trials=900, seed=3)
    det, fp = code.power(nobs, thr, trials=500, seed=21)
    assert fp == 0.0, f"calibrated threshold still gave {fp} false accusations per trial"
    assert det > 0.9, f"calibrated threshold lost detection power: {det}"
    return {"calibrated threshold": f"{thr:.2f} sqrt(nobs)", "detection": f"{det:.3f}",
            "false accusations per trial": fp}


@mutation("tardos-fixed-sigma-threshold")
def _original_five_sigma():
    m = C.code_length(3, 1e-6)
    code = C.Code(5000, m, 3, 77)
    det, fp = code.power(200, 5.0, trials=500, seed=21)     # <-- nominal 5 sigma
    assert fp == 0.0, f"5 sigma gave {fp} false accusations per trial"


@claim("tardos-code-screening",
       says="codes with identical parameters differ enormously in power, so the "
            "realisation is chosen rather than accepted as drawn")
def screening_matters():
    m, nobs = C.code_length(2, 1e-6), 160
    best, chosen, tried = C.screen(2000, m, 2, nobs, candidates=4,
                                   family_wise=1e-3, base_seed=500)
    dets = sorted(t["detection"] for t in tried)
    assert chosen["detection"] == dets[-1], "screening did not keep the best candidate"
    assert dets[-1] - dets[0] > 0.02, (
        f"candidates were all alike ({dets}); this claim needs a spread to be meaningful")
    return {"candidate detection rates": dets,
            "spread": round(dets[-1] - dets[0], 3),
            "chosen threshold": chosen["threshold"]}


@claim("tardos-code-length",
       says="code length follows (pi^2/2) c^2 ln(1/eps1) with the optimal constant 4.93")
def code_length_formula():
    assert C.code_length(1, 1e-6) == math.ceil(4.93 * math.log(1e6))
    quad = C.code_length(4, 1e-6) / C.code_length(2, 1e-6)
    assert 3.9 < quad < 4.1, f"length is not quadratic in c: ratio {quad}"
    return {"c=2": C.code_length(2, 1e-6), "c=5": C.code_length(5, 1e-6),
            "c=4 / c=2": round(quad, 3)}


@claim("tardos-bit-error-tolerance",
       says="detection survives the bit error rate a photographed page actually produces")
def survives_bit_errors():
    m = C.code_length(3, 1e-6)
    code = C.Code(2000, m, 3, 77)
    nobs = 200
    thr = code.calibrate(nobs, family_wise=1e-3, trials=800, seed=3)
    out = {}
    for ber in (0.0, 0.05, 0.10):
        det, fp = code.power(nobs, thr, ber=ber, trials=400, seed=31)
        out[f"ber {ber:.0%}"] = f"detection {det:.3f}, false {fp}"
        if ber <= 0.05:
            assert det > 0.85, f"detection collapsed at ber={ber}: {det}"
        assert fp == 0.0, f"false accusations at ber={ber}: {fp}"
    return out


if __name__ == "__main__":
    main(__doc__)
