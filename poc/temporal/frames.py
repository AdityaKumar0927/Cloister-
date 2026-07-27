"""
Defeating the screenshot: complementary temporal decomposition.

The problem with OCR and photography is that the page has to be legible to the reader,
and a camera sees what the reader sees. Every spatial trick against OCR -- CAPTCHA-style
distortion, adversarial perturbation, microtype -- has lost, because it degrades the page
for the human at least as much as for the machine, and vision models keep improving.

So look for an asymmetry that is not about the image but about *how the image is
sampled*. There is one, and it is structural rather than perceptual:

    A human integrates light over the whole frame period. A screenshot captures ONE
    composited frame. A rolling-shutter camera integrates a different short slice per
    scanline.

That gap is not something a better model can close. It follows from how framebuffers and
CMOS sensors work.

Construction. Let L_T be the true page and L_A a decoy page, both rendered into a
restricted luminance band. Display two frames alternately:

    F1 = L_A                 (a clean, readable, WRONG document)
    F2 = 2 * L_T - L_A       (the compensator)
    mean(F1, F2) = L_T       (what the eye integrates: the true document)

Every value stays in range provided both pages are rendered with luminance in [1/3, 2/3],
which is a 2:1 contrast ratio -- the real cost of the method, and it is a cost to the
human, so it is stated rather than buried.

A screenshot therefore returns either a fluent wrong document or a visibly corrupted one,
never the true page, and it does so WITHOUT any cooperation from the operating system.
That matters because capture exclusion is unavailable exactly where the whitepaper admits
defeat: bare X11, and the zero-install web viewer.

What this does not beat: an exposure long enough to span both frames, or software frame
averaging. Those recover the true page. The measurements below quantify how long that
exposure has to be.
"""
from __future__ import annotations

import os
import subprocess
import sys

import numpy as np
from PIL import Image

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "src"))

LO, HI = 1.0 / 3.0, 2.0 / 3.0          # luminance band that keeps 2T-A in [0,1]


# ------------------------------------------------------------------ page rendering
def render_plain(text_blocks, out_pdf):
    """Render blocks with every glyph reporting itself -- an ordinary document."""
    from cloister import render as R

    class Identity:
        def segment(self, n):
            return "\x00" * n

    orig = R.Bank.cid
    R.Bank.cid = lambda self, ch, reported: orig(self, ch, ch)
    try:
        r = R.Renderer(text_blocks, Identity(), bits=None, delta_mille=0).layout()
        r.write(out_pdf)
    finally:
        R.Bank.cid = orig
    return out_pdf


def raster(pdf, dpi, prefix):
    subprocess.run(["pdftoppm", "-r", str(dpi), "-gray", "-png", "-f", "1", "-l", "1",
                    pdf, prefix], check=True, capture_output=True)
    d = os.path.dirname(prefix) or "."
    base = os.path.basename(prefix)
    f = sorted(x for x in os.listdir(d) if x.startswith(base) and x.endswith(".png"))[0]
    return np.asarray(Image.open(os.path.join(d, f)).convert("L"),
                      dtype=np.float64) / 255.0


def to_band(L):
    """Compress an ordinary 0..1 page into the [LO, HI] luminance band."""
    return LO + (HI - LO) * L


def as_u8(F):
    return Image.fromarray(np.clip(F * 255.0, 0, 255).astype(np.uint8))


# --------------------------------------------------------------- the decomposition
def decompose_decoy(LT, LA):
    """
    First attempt, kept because it FAILS and the failure is instructive.

    F1 = decoy page, F2 = 2*LT - LA. The average is exactly LT, but frame 2 leaks the
    true text at full recovery: overlaying a second document does not destroy glyph
    structure, it just adds a layer of opposite polarity, and OCR reads straight through
    that. Worse, the factor of two amplifies the true signal in the compensator.
    """
    return LA.copy(), 2.0 * LT - LA


def block_mask(shape, block, rng, amp):
    """Zero-mean perturbation, constant over blocks of `block` pixels.

    Per-pixel noise is useless here: a glyph stroke covers dozens of pixels, so averaging
    within the stroke recovers the signal with a sqrt(area) gain. The perturbation has to
    be correlated at the scale of letter features so that no local average can separate
    it from the text.
    """
    h, w = shape
    bh, bw = (h + block - 1) // block, (w + block - 1) // block
    small = rng.choice([-amp, amp], size=(bh, bw))
    big = np.kron(small, np.ones((block, block)))
    return big[:h, :w]


def decompose_masked(LT, block=12, amp=1.0 / 3.0, seed=0):
    """
    F1 = LT + d, F2 = LT - d with d a block-structured zero-mean mask.

    The true signal appears at unit amplitude in each frame -- not doubled -- while the
    mask spans twice the signal's contrast, so neither frame is individually legible. The
    average is exactly LT because the mask cancels, whatever its spatial structure.

    Range: with LT confined to [1/3, 2/3] and |d| <= 1/3, both frames stay inside [0, 1]
    with no clipping, which is what makes the cancellation exact rather than approximate.
    """
    rng = np.random.default_rng(seed)
    d = block_mask(LT.shape, block, rng, amp)
    return LT + d, LT - d, d


def ink_mask(L, thresh=0.5):
    """Binary ink map of a rendered page, in the normalised 0..1 domain."""
    return (L < thresh).astype(np.float64)


def decompose_textmask(LT, MA, MB, amp=1.0 / 3.0):
    """
    The mask is itself TEXT.

    d = amp * (MA - MB) for two decoy ink maps, so each displayed frame carries the true
    page plus one decoy rendered dark and another rendered bright, all at comparable
    contrast. The average is exactly LT.

    This is the version that survives filtering. A block mask is piecewise constant, so it
    lives entirely in the DC term of each block and a high-pass filter at the block scale
    strips it while leaving glyph edges intact. A mask made of glyphs has the same spatial
    spectrum as the content it hides, so no linear filter separates them.
    """
    d = amp * (MA - MB)
    return LT + d, LT - d, d


def block_median_attack(Fr, block, offset=0):
    """
    The attack a competent adversary actually runs.

    A piecewise-constant mask is fully determined by one value per cell. Glyph ink covers
    a minority of any cell, so the cell MEDIAN estimates background-plus-mask robustly;
    subtract it and the glyph contrast survives. The cell grid is recoverable from the
    autocorrelation of the capture, so assuming the adversary knows it is the right
    assumption.
    """
    H, W = Fr.shape
    out = Fr.copy()
    for y in range(-offset, H, block):
        for x in range(-offset, W, block):
            y0, y1 = max(0, y), min(H, y + block)
            x0, x1 = max(0, x), min(W, x + block)
            if y1 <= y0 or x1 <= x0:
                continue
            cell = Fr[y0:y1, x0:x1]
            out[y0:y1, x0:x1] = cell - np.median(cell) + 0.5
    return out


def dense_mask_from_text(L_dense, amp):
    """A mask that is text-shaped AND dense: +-amp driven by a heavily overset page whose
    ink coverage approaches half. Sparse decoy text fails as a mask -- it covers about 4%
    of the page, so it hides almost nothing."""
    M = ink_mask(L_dense)
    return amp * (2.0 * M - 1.0), float(M.mean())


def highpass_attack(Fr, scale):
    """Subtract a local mean at the given scale: removes any perturbation whose energy is
    confined below that spatial frequency, and keeps glyph edges."""
    from scipy.ndimage import uniform_filter
    return Fr - uniform_filter(Fr, size=scale) + 0.5


def frame_sequence(LT, n, block=12, amp=1.0 / 3.0, seed=0):
    """n frames, re-keying the mask every pair so consecutive pairs are independent."""
    seq = []
    for i in range(0, n, 2):
        F1, F2, _ = decompose_masked(LT, block, amp, seed=seed + i)
        seq.append(F1)
        seq.append(F2)
    return seq[:n]


# ------------------------------------------------------------------- capture models
def screenshot(seq, index):
    return seq[index % len(seq)]


def long_exposure(seq, nframes, phase=0):
    """A camera whose shutter spans `nframes` display frames."""
    acc = np.zeros_like(seq[0])
    for i in range(nframes):
        acc += seq[(phase + i) % len(seq)]
    return acc / nframes


def rolling_shutter(seq, band_px, phase=0, exposure_frames=1):
    """
    A CMOS sensor reads the image out line by line. With the readout spanning several
    display frames, each horizontal band integrates a different part of the frame
    sequence -- so the capture is a striped mixture rather than a clean average.
    """
    H, W = seq[0].shape
    out = np.empty((H, W))
    nb = int(np.ceil(H / band_px))
    for b in range(nb):
        y0, y1 = b * band_px, min(H, (b + 1) * band_px)
        acc = np.zeros((y1 - y0, W))
        for e in range(exposure_frames):
            f = seq[(phase + b + e) % len(seq)]
            acc += f[y0:y1, :]
        out[y0:y1, :] = acc / exposure_frames
    return out


# ------------------------------------------------------------------------- scoring
def ocr(img_arr, tag, autocontrast=True):
    im = as_u8(img_arr)
    if autocontrast:
        from PIL import ImageOps
        im = ImageOps.autocontrast(im)     # give the attacker every advantage
    p = f"/tmp/tmp_{tag}.png"
    im.save(p)
    return subprocess.run(["tesseract", p, "-", "--psm", "6"],
                          capture_output=True, text=True).stdout


def content_words(s):
    import re
    STOP = set("the and for that with this from have been will not are was were has had "
               "our its than then they them their there these those such being upon "
               "which while whose would could should shall must may might into over "
               "under about above after before between during without within also only "
               "same each other more most some any all both few many much very when "
               "where what who whom does did done doing because however therefore thus "
               "said per via".split())
    return {w for w in re.findall(r"[a-z]{4,}", s.lower()) if w not in STOP}


def recovery(truth, got):
    tw = content_words(truth)
    return round(len(tw & content_words(got)) / max(1, len(tw)), 4)
