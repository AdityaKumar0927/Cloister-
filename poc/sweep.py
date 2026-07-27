"""Figure-4 sweep: majority-vote attack, 500 trials/point, for a smooth curve."""
import json, math, sys
import numpy as np
sys.path.insert(0, 'poc')
from tardos import build_code

rng = np.random.default_rng(20260725)
n, c, eps1, Z, TRIALS = 1000, 5, 1e-6, 5.0, 500
m = int(math.ceil(4.93 * c * c * math.log(1 / eps1)))
X, p, U = build_code(n, m, c, rng)
rows = []
for R in (1, 12, 40):
    for s in (0.05, 0.1, 0.2, 0.3, 0.5, 1.0):
        hit = fp = 0
        for _ in range(TRIALS):
            col = rng.choice(n, c, replace=False)
            y = (X[col].mean(axis=0) > 0.5).astype(np.float32)
            v = 2 * y - 1
            if s < 1.0:
                v = v * (rng.binomial(R, s, m) > 0)
            mo = float(np.count_nonzero(v))
            S = U @ v
            acc = set(np.flatnonzero(np.abs(S) > Z * math.sqrt(mo)).tolist())
            ts = set(col.tolist())
            hit += 1 if (acc & ts) else 0
            fp += len(acc - ts)
        rows.append({"R": R, "survival": s, "P_majority": round(hit / TRIALS, 4),
                     "FP": round(fp / TRIALS, 5), "trials": TRIALS})
        print(rows[-1], flush=True)
json.dump(rows, open("out/sweep.json", "w"), indent=1)
