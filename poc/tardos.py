#!/usr/bin/env python3
"""
CLOISTER — Layer T (Trace): collusion-resistant per-copy fingerprinting.

Symmetric Tardos probabilistic fingerprinting code (Tardos, STOC 2003; symmetric
score function per Skoric-Katzenbeisser-Celik 2008), evaluated against the standard
collusion attacks under the marking assumption.

Every distributed copy carries an m-bit codeword embedded redundantly across
independent channels (inter-word micro-kerning, glyph-variant selection, and the
chaff decoy's word choices). Given a recovered fragment -- including one produced
by a coalition that diffed several copies -- the accusation algorithm names
colluders at a chosen false-accusation sigma.
"""
import json, math
import numpy as np

rng = np.random.default_rng(20260725)


def build_code(n, m, c, rng):
    t = 1.0 / (900.0 * c)                      # Tardos cutoff on p
    lo, hi = math.asin(math.sqrt(t)), math.pi / 2 - math.asin(math.sqrt(t))
    p = np.sin(rng.uniform(lo, hi, m)) ** 2
    X = (rng.random((n, m)) < p)
    g1 = np.sqrt((1 - p) / p).astype(np.float32)
    g0 = -np.sqrt(p / (1 - p)).astype(np.float32)
    U = np.where(X, g1, g0)                    # per-user, per-position contribution
    return X, p, U


ATTACKS = {
    "majority":   lambda C, rng: C.mean(axis=0) > 0.5,
    "minority":   lambda C, rng: C.mean(axis=0) < 0.5,
    "coin_flip":  lambda C, rng: C[rng.integers(0, C.shape[0], C.shape[1]), np.arange(C.shape[1])],
    "all_ones":   lambda C, rng: C.any(axis=0),
    "interleave": lambda C, rng: C[np.arange(C.shape[1]) % C.shape[0], np.arange(C.shape[1])],
}


def experiment(n, c, trials, survival=1.0, Z=5.0, eps1=1e-6,
               two_sided=True, R=1):
    """
    two_sided : accuse on |S| > Z*sigma. Required because the minority-voting
                attack produces a *negatively* correlated sequence, which a
                one-sided test cannot see at all.
    R         : redundancy schedule -- each code bit is embedded at R independent
                document locations. A leaked fragment of relative size `survival`
                yields Binomial(R, survival) observations per bit, resolved by
                majority vote. This is what makes short fragments traceable.
    """
    m = int(math.ceil(4.93 * c * c * math.log(1 / eps1)))   # ~ (pi^2/2) c^2 ln(1/eps1)
    X, p, U = build_code(n, m, c, rng)
    res = {}
    for name, atk in ATTACKS.items():
        caught = frac_any = innocent = 0
        for _ in range(trials):
            col = rng.choice(n, c, replace=False)
            y = atk(X[col], rng).astype(np.float32)
            v = (2 * y - 1)
            if survival < 1.0:
                obs = rng.binomial(R, survival, m)
                # a bit is recoverable iff at least one of its R copies survived
                v = v * (obs > 0)
            m_obs = float(np.count_nonzero(v))
            if m_obs == 0:
                continue
            S = U @ v
            thr = Z * math.sqrt(m_obs)
            accused = set(np.flatnonzero(np.abs(S) > thr).tolist()) if two_sided \
                else set(np.flatnonzero(S > thr).tolist())
            true_set = set(col.tolist())
            caught += len(accused & true_set)
            frac_any += 1 if (accused & true_set) else 0
            innocent += len(accused - true_set)
        res[name] = {
            "avg_colluders_named": round(caught / trials, 3),
            "P(at_least_one_named)": round(frac_any / trials, 4),
            "avg_false_accusations": round(innocent / trials, 6),
        }
    return {"users_n": n, "collusion_c": c, "code_bits_m": m,
            "fragment_survival": survival, "redundancy_R": R,
            "two_sided": two_sided, "threshold_sigma": Z,
            "trials": trials, "attacks": res}


if __name__ == "__main__":
    out = [
        experiment(1000, 2, 300),
        experiment(1000, 5, 300),
        experiment(1000, 10, 200),
        experiment(1000, 5, 300, two_sided=False),            # one-sided, for contrast
        experiment(1000, 5, 300, survival=0.30, R=1),          # 30% fragment, no redundancy
        experiment(1000, 5, 300, survival=0.30, R=12),         # 30% fragment, R=12
        experiment(1000, 5, 300, survival=0.10, R=12),         # 10% fragment, R=12
        experiment(1000, 5, 300, survival=0.05, R=40),         # one paragraph, R=40
        experiment(50000, 5, 100),                             # university-scale roster
    ]
    print(json.dumps(out, indent=2))
