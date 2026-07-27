"""
A small character-level neural language model, in numpy.

Purpose: settle whether the "ingestion oracle" proposed in the whitepaper can work.
The oracle's claim is that a document's canary leaves a detectable trace in a model
that trained on it. That is a measurable question, so it should be measured rather than
asserted, and the honest way to measure it is to train a model where the ground truth
is known.

Architecture is a fixed-context feedforward LM (Bengio et al. 2003): the previous k
characters are embedded, concatenated, passed through one hidden layer, and projected
to a softmax over the vocabulary. Chosen deliberately over a recurrent or attention
model: backpropagation has no time dimension, so the gradients are simple enough to
verify numerically, and a wrong gradient would silently produce whatever result we
went looking for.

The bias this introduces is stated in the writeup rather than buried: a fixed-context
MLP can only memorise a long canary through overlapping k-grams, which is a weaker
memorisation channel than attention. Working against that, the corpus here is small and
repetitive, which makes memorisation easier than it would be at scale.
"""
from __future__ import annotations

import numpy as np


class CharLM:
    def __init__(self, vocab: int, ctx: int = 16, emb: int = 24, hidden: int = 256,
                 seed: int = 0):
        rng = np.random.default_rng(seed)
        self.V, self.k, self.d, self.h = vocab, ctx, emb, hidden
        self.E = rng.normal(0, 0.08, (vocab, emb))
        self.W1 = rng.normal(0, np.sqrt(2.0 / (ctx * emb)), (ctx * emb, hidden))
        self.b1 = np.zeros(hidden)
        self.W2 = rng.normal(0, np.sqrt(1.0 / hidden), (hidden, vocab))
        self.b2 = np.zeros(vocab)
        self._m = {k: np.zeros_like(v) for k, v in self.params.items()}
        self._v = {k: np.zeros_like(v) for k, v in self.params.items()}
        self._t = 0

    @property
    def params(self):
        return {"E": self.E, "W1": self.W1, "b1": self.b1, "W2": self.W2, "b2": self.b2}

    # ------------------------------------------------------------------ forward
    def forward(self, X):
        """X: (B, k) int context. Returns logits (B, V) and a cache."""
        B = X.shape[0]
        emb = self.E[X]                                  # (B, k, d)
        flat = emb.reshape(B, self.k * self.d)
        pre = flat @ self.W1 + self.b1
        act = np.tanh(pre)
        logits = act @ self.W2 + self.b2
        return logits, (X, flat, act)

    @staticmethod
    def log_softmax(logits):
        m = logits.max(axis=1, keepdims=True)
        z = logits - m
        return z - np.log(np.exp(z).sum(axis=1, keepdims=True))

    def loss_and_grads(self, X, y, l2=0.0):
        B = X.shape[0]
        logits, (Xc, flat, act) = self.forward(X)
        logp = self.log_softmax(logits)
        loss = -logp[np.arange(B), y].mean()
        p = np.exp(logp)
        dlogits = p
        dlogits[np.arange(B), y] -= 1.0
        dlogits /= B
        g = {}
        g["W2"] = act.T @ dlogits
        g["b2"] = dlogits.sum(axis=0)
        dact = dlogits @ self.W2.T
        dpre = dact * (1.0 - act ** 2)
        g["W1"] = flat.T @ dpre
        g["b1"] = dpre.sum(axis=0)
        dflat = dpre @ self.W1.T
        dE = np.zeros_like(self.E)
        demb = dflat.reshape(B, self.k, self.d)
        np.add.at(dE, Xc, demb)
        g["E"] = dE
        if l2:
            for k, v in self.params.items():
                if k != "b1" and k != "b2":
                    g[k] = g[k] + l2 * v
            loss += 0.5 * l2 * sum(
                float((v ** 2).sum()) for k, v in self.params.items()
                if k not in ("b1", "b2"))
        return loss, g

    # ------------------------------------------------------------------- update
    def adam(self, g, lr=3e-3, b1=0.9, b2=0.999, eps=1e-8):
        self._t += 1
        for k, v in self.params.items():
            self._m[k] = b1 * self._m[k] + (1 - b1) * g[k]
            self._v[k] = b2 * self._v[k] + (1 - b2) * (g[k] ** 2)
            mh = self._m[k] / (1 - b1 ** self._t)
            vh = self._v[k] / (1 - b2 ** self._t)
            v -= lr * mh / (np.sqrt(vh) + eps)

    # --------------------------------------------------------------- evaluation
    def seq_logprob(self, ids: np.ndarray, pad: int) -> float:
        """Total log-probability of a character sequence under this model."""
        ctx = np.full(self.k, pad, dtype=np.int64)
        X, y = [], []
        for c in ids:
            X.append(ctx.copy())
            y.append(c)
            ctx = np.roll(ctx, -1)
            ctx[-1] = c
        X = np.asarray(X)
        y = np.asarray(y)
        total = 0.0
        for i in range(0, len(X), 4096):
            logits, _ = self.forward(X[i:i + 4096])
            lp = self.log_softmax(logits)
            yy = y[i:i + 4096]
            total += float(lp[np.arange(len(yy)), yy].sum())
        return total

    def perplexity(self, ids: np.ndarray, pad: int, stride: int = 1) -> float:
        n = len(ids)
        lp = self.seq_logprob(ids, pad)
        return float(np.exp(-lp / max(1, n)))


def gradient_check(seed=0) -> float:
    """Numerical gradient check. A silent gradient bug would let this study produce
    whatever answer it was pointed at, so the gradients are verified, not trusted."""
    rng = np.random.default_rng(seed)
    m = CharLM(vocab=11, ctx=4, emb=5, hidden=7, seed=1)
    X = rng.integers(0, 11, (6, 4))
    y = rng.integers(0, 11, 6)
    _, g = m.loss_and_grads(X, y)
    worst = 0.0
    for name in ("W1", "b1", "W2", "b2", "E"):
        P = m.params[name]
        flat = P.reshape(-1)
        gf = g[name].reshape(-1)
        idxs = rng.choice(flat.size, min(12, flat.size), replace=False)
        for i in idxs:
            old = flat[i]
            h = 1e-5
            flat[i] = old + h
            lp, _ = m.loss_and_grads(X, y)
            flat[i] = old - h
            lm_, _ = m.loss_and_grads(X, y)
            flat[i] = old
            num = (lp - lm_) / (2 * h)
            den = max(1e-9, abs(num) + abs(gf[i]))
            worst = max(worst, abs(num - gf[i]) / den)
    return worst


def all_contexts(ids: np.ndarray, ctx: int, pad: int) -> np.ndarray:
    """Every training context as a strided view -- no copy, no Python loop. Building
    batches with a list comprehension dominated runtime before this."""
    padded = np.concatenate([np.full(ctx, pad, dtype=np.int64), ids])
    return np.lib.stride_tricks.sliding_window_view(padded, ctx)[:len(ids)]


def make_batches(ids: np.ndarray, ctx: int, pad: int, rng, batch: int,
                 windows: np.ndarray | None = None):
    """Contexts and targets over the whole corpus, shuffled."""
    W = all_contexts(ids, ctx, pad) if windows is None else windows
    idx = rng.permutation(len(ids))
    for s in range(0, len(ids), batch):
        sel = idx[s:s + batch]
        yield W[sel], ids[sel]


def train(model: CharLM, ids: np.ndarray, pad: int, epochs: int = 0,
          batch: int = 256, lr: float = 3e-3, seed: int = 0, log=None,
          max_examples: int | None = None):
    """
    Train for `epochs` passes, or until `max_examples` gradient examples have been seen.

    The max_examples budget is what makes the dilution sweep a controlled experiment.
    Holding epochs fixed while the corpus grows also grows the compute, which confounds
    dilution with training length. A frontier model sees each document roughly once under
    a fixed compute budget, so fixing the budget and varying the corpus is the condition
    that actually corresponds to the question being asked.
    """
    rng = np.random.default_rng(seed)
    windows = all_contexts(ids, model.k, pad)
    seen, ep = 0, 0
    while True:
        tot, nb = 0.0, 0
        for X, y in make_batches(ids, model.k, pad, rng, batch, windows):
            loss, g = model.loss_and_grads(X, y)
            model.adam(g, lr=lr)
            tot += loss
            nb += 1
            seen += len(y)
            if max_examples is not None and seen >= max_examples:
                if log:
                    log(ep, tot / max(1, nb))
                return model
        ep += 1
        if log:
            log(ep - 1, tot / max(1, nb))
        if max_examples is None and ep >= epochs:
            return model
