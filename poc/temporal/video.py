"""
Video recording: what can and cannot be done, and why.

Start with the negative result, because it determines everything else.

  NECESSITY ARGUMENT. Suppose the display is a function of the document and time alone,
  and the adversary records every frame. The reader's retina integrates incident light
  over some window W; call that integral R(W). The adversary holds every frame, so the
  adversary can compute R(W) for any W, including the reader's. Anything legible to the
  reader is therefore legible to the adversary. No display-only scheme can prevent
  recovery from a complete recording -- not masking, not keyed interleaving, not
  temporal secret sharing.

  The escape is forced: the reader must possess a physical element that makes their
  optical path differ from the camera's. Then the two integrate DIFFERENT subsequences,
  and the equality above breaks. This is not a convenience, it is the only way out.

So: give the reader a shutter, synchronised to the display, that passes half the frames.

  Cycle of four frames, at 240 Hz:
      A = L + d          passed by the shutter
      B = L - d          passed by the shutter
      X = (1-L) + e      blocked
      Y = (1-L) - e      blocked

  Reader integrates the passed pair:  (A+B)/2 = L                  the true page
  Anything integrating the full cycle: (A+B+X+Y)/4 = 1/2 EXACTLY   uniform grey

The second identity holds pixel by pixel and independently of the masks, because
L + (1-L) = 1 everywhere. A capture that spans whole cycles therefore contains no spatial
information at all -- not degraded information, none. That is the strongest statement
available anywhere in this project, and it is worth being precise about what it does and
does not cover, which is what the measurements below are for.

The consequence that matters practically: an ordinary camera at 30 fps with an exposure of
1/30 s integrates eight display frames -- two whole cycles -- and records a grey
rectangle. Beating this needs a camera that resolves individual display frames, which
means high frame rate AND a sub-millisecond shutter, deliberately aimed. A phone on a desk
does not do it by accident.
"""
from __future__ import annotations

import itertools
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import frames as F                                             # noqa: E402

DISPLAY_HZ = 240
CYCLE = 4


def build_cycle(LT, block=12, amp=1.0 / 3.0, seed=0):
    """One four-frame cycle. Returns (frames, passed_indices)."""
    rng = np.random.default_rng(seed)
    d = F.block_mask(LT.shape, block, rng, amp)
    e = F.block_mask(LT.shape, block, rng, amp)
    inv = 1.0 - LT
    A, B = LT + d, LT - d
    X, Y = inv + e, inv - e
    return [A, X, B, Y], [0, 2]          # shutter passes A and B


def sequence(LT, n_cycles, block=12, amp=1.0 / 3.0, seed=0):
    seq, passed = [], []
    for c in range(n_cycles):
        fr, idx = build_cycle(LT, block, amp, seed=seed + 17 * c)
        base = len(seq)
        seq.extend(fr)
        passed.extend(base + i for i in idx)
    return seq, passed


def reader_view(seq, passed, window=8):
    """What the eye integrates: only the frames the shutter passes."""
    sel = [seq[i] for i in passed[:window]]
    return sum(sel) / len(sel)


def camera(seq, start, exposure_frames):
    """A camera integrating `exposure_frames` consecutive display frames."""
    sel = [seq[(start + i) % len(seq)] for i in range(exposure_frames)]
    return sum(sel) / len(sel)


def pairwise_attack(seq, truth, limit=10, tag="pa"):
    """
    The attack against frame-resolved capture: try every pair of frames, average, and
    keep whichever averages read as text. The complementary pair (A,B) averages to the
    true page, so this succeeds -- and it is only O(n^2) with a trivial scoring function,
    which is why a keyed frame schedule buys nothing.
    """
    best = (0.0, None)
    tried = 0
    for i, j in itertools.combinations(range(min(limit, len(seq))), 2):
        tried += 1
        r = F.recovery(truth, F.ocr((seq[i] + seq[j]) / 2, f"{tag}_{i}_{j}"))
        if r > best[0]:
            best = (r, (i, j))
    return best[0], best[1], tried
