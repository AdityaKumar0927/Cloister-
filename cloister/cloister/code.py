"""
Fingerprint codes and the accusation test.

Symmetric Tardos probabilistic fingerprinting (Tardos 2003; symmetric score per
Skoric et al. 2008). Two things this module does that the textbook does not, both
because measurement showed they were necessary:

  1. The accusation test is TWO-SIDED. The minority-voting collusion attack produces
     a negatively correlated sequence that a one-sided test cannot see at all -- not
     degraded detection, zero detection.

  2. The threshold is CALIBRATED against the code's own simulated null distribution
     rather than taken as a fixed number of sigma. At the observation counts a single
     recovered page provides, the score is not reliably Gaussian, and its tail depends
     on how many small p_i that particular code happened to draw. Codes are also
     screened at generation time, because two codes with identical parameters can
     differ by an order of magnitude in detection power.
"""
from __future__ import annotations
import math

import numpy as np


def code_length(collusion: int, eps1: float = 1e-6) -> int:
    """~ (pi^2 / 2) c^2 ln(1/eps1); the asymptotically optimal constant is 4.93."""
    return int(math.ceil(4.93 * collusion * collusion * math.log(1.0 / eps1)))


class Code:
    def __init__(self, n_users: int, m: int, collusion: int, seed: int):
        self.n, self.m, self.c, self.seed = n_users, m, collusion, seed
        rng = np.random.default_rng(seed)
        t = 1.0 / (900.0 * max(1, collusion))
        lo = math.asin(math.sqrt(t))
        hi = math.pi / 2 - lo
        self.p = np.sin(rng.uniform(lo, hi, m)) ** 2
        self.X = rng.random((n_users, m)) < self.p
        g1 = np.sqrt((1 - self.p) / self.p).astype(np.float32)
        g0 = -np.sqrt(self.p / (1 - self.p)).astype(np.float32)
        self.U = np.where(self.X, g1, g0)

    def word(self, row: int) -> list[int]:
        return self.X[row].astype(int).tolist()

    # -- accusation --------------------------------------------------------------
    def scores(self, bits, mask):
        v = np.zeros(self.m, dtype=np.float32)
        idx = np.flatnonzero(np.asarray(mask))
        if idx.size == 0:
            return None, 0
        b = np.asarray(bits, dtype=np.float32)[idx]
        v[idx] = 2 * b - 1
        return self.U @ v, int(idx.size)

    def accuse(self, bits, mask, threshold_sigma: float):
        S, nobs = self.scores(bits, mask)
        if S is None:
            return [], None, 0
        thr = threshold_sigma * math.sqrt(nobs)
        order = np.argsort(-np.abs(S))
        accused = [int(i) for i in order if abs(S[i]) > thr]
        return accused, S, nobs

    # -- calibration -------------------------------------------------------------
    def calibrate(self, nobs: int, family_wise: float = 1e-3, trials: int = 3000,
                  seed: int = 7) -> float:
        """
        Empirical threshold: the (1 - family_wise) quantile of the largest innocent
        score, in units of sqrt(nobs). This is what keeps false accusations near zero
        at small observation counts, where a nominal sigma count does not.
        """
        rng = np.random.default_rng(seed)
        nobs = min(nobs, self.m)
        mx = np.empty(trials)
        for t in range(trials):
            u = int(rng.integers(0, self.n))
            pos = rng.choice(self.m, nobs, replace=False)
            v = np.zeros(self.m, dtype=np.float32)
            v[pos] = 2 * self.X[u][pos].astype(np.float32) - 1
            S = np.abs(self.U @ v)
            S[u] = -1e9
            mx[t] = S.max() / math.sqrt(nobs)
        return float(np.quantile(mx, 1.0 - family_wise))

    def power(self, nobs: int, threshold: float, ber: float = 0.0,
              trials: int = 1500, seed: int = 11):
        rng = np.random.default_rng(seed)
        nobs = min(nobs, self.m)
        hit = fp = 0
        for t in range(trials):
            u = int(rng.integers(0, self.n))
            y = self.X[u].astype(np.float32).copy()
            pos = rng.choice(self.m, nobs, replace=False)
            if ber > 0:
                fl = pos[rng.random(nobs) < ber]
                y[fl] = 1 - y[fl]
            v = np.zeros(self.m, dtype=np.float32)
            v[pos] = 2 * y[pos] - 1
            S = self.U @ v
            acc = set(np.flatnonzero(np.abs(S) > threshold * math.sqrt(nobs)).tolist())
            hit += 1 if u in acc else 0
            fp += len(acc - {u})
        return hit / trials, fp / trials


def screen(n_users: int, m: int, collusion: int, nobs: int, candidates: int = 8,
           family_wise: float = 1e-3, base_seed: int = 1000):
    """
    Generate several candidate codes, calibrate each, and keep the most powerful.
    Two codes with identical parameters can differ enormously in detection power, so
    the realisation is chosen deliberately rather than accepted as drawn.
    """
    best = None
    tried = []
    for i in range(candidates):
        seed = base_seed + i
        code = Code(n_users, m, collusion, seed)
        thr = code.calibrate(nobs, family_wise=family_wise, trials=1200)
        det, fp = code.power(nobs, thr, trials=700)
        tried.append({"seed": seed, "threshold": round(thr, 3),
                      "detection": round(det, 4), "fp_per_trial": round(fp, 5)})
        if best is None or det > best[1]["detection"]:
            best = (code, tried[-1])
    return best[0], best[1], tried
