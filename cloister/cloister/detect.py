"""
Recover the kerning fingerprint from an image of the page.

The detector never segments words out of the image. It holds the master, so it
computes each word's expected window analytically from the layout map and takes an
intensity-weighted centroid inside it. Segmenting by ink connectivity fails at chance:
one split or merged glyph shifts every following gap index and inverts the bits after
it.

Before measuring, a leaked image is deskewed and then affinely normalised onto the
reference render's ink bounding box, so photographs at arbitrary scale and modest
rotation land on the same coordinate system as the master.
"""
from __future__ import annotations
import os
import re
import subprocess

import numpy as np
from PIL import Image

PAGE_H = 792.0


def render_pdf(pdf: str, dpi: int, prefix: str) -> list[str]:
    """
    Rasterise a PDF to one greyscale PNG per page and return them in page order.

    Stale files matching the prefix are removed FIRST. pdftoppm names its output by page
    number, and this function then collects everything matching the prefix, so a render of
    a shorter document into a directory a longer one used before would silently adopt the
    leftover pages as its own. The trace command reuses a fixed working directory, which
    is exactly the condition that triggers it: the detector would compare a leaked page
    against a reference page belonging to a different document and report the result with
    no indication that anything was wrong.
    """
    d = os.path.dirname(prefix) or "."
    base = os.path.basename(prefix)
    os.makedirs(d, exist_ok=True)
    # Match pdftoppm's own naming exactly -- <base>-<page>.png -- rather than any file
    # starting with the prefix. Plain prefix matching also confuses neighbouring renders
    # whose names nest: cleaning "m2" would delete "m21-1.png", and collecting "m2" would
    # adopt it.
    pat = re.compile(rf"^{re.escape(base)}-\d+\.png$")
    for f in os.listdir(d):
        if pat.match(f):
            os.remove(os.path.join(d, f))
    subprocess.run(["pdftoppm", "-r", str(dpi), "-gray", "-png", pdf, prefix],
                   check=True, capture_output=True)
    return [os.path.join(d, f) for f in sorted(os.listdir(d)) if pat.match(f)]


def flatten(I: np.ndarray, grid=12, q=5.0) -> np.ndarray:
    """
    Subtract the illumination surface, so that "how dark is the paper here" stops being a
    global constant.

    No single threshold can separate ink from paper on a page that is not evenly lit. A
    cut high enough to clear the bright side of a photograph sits below the paper on the
    dark side, and that paper is then counted as ink. The damage is not cosmetic: it
    stretches the text bounding box toward the dark edge, normalise() fits that stretched
    box onto the reference, and every word window afterwards is displaced by more than the
    signal being measured. Recovery then fails at chance while the diagnostics still look
    healthy -- the tell is a median gap margin several times larger than the embedded
    displacement, which is measurement error being read as signal.

    Construction, and why it is shaped this way:

      * sample the paper level as a low percentile inside each cell of a `grid` x `grid`
        lattice. A low percentile tracks paper rather than ink, because ink is a minority
        of any cell that contains text.
      * fit a QUADRATIC surface in (x, y) to those samples by least squares -- six
        coefficients, from grid^2 samples.

    The two-stage shape matters. Interpolating the per-cell samples directly makes the
    surface as detailed as the lattice, so a fine lattice absorbs text and a coarse one
    can only represent a ramp; the fit decouples "enough samples to be robust" from "too
    smooth to absorb text". Six coefficients cannot follow a text line, and they do
    represent the illumination a camera actually produces: a linear falloff across the
    page plus the quadratic bowl of vignetting. A clean render is left untouched, because
    there the fitted surface is zero.
    """
    H, W = I.shape
    gy, gx = max(2, min(grid, H)), max(2, min(grid, W))
    ph, pw = -(-H // gy) * gy, -(-W // gx) * gx
    pad = np.pad(I, ((0, ph - H), (0, pw - W)), mode="edge")
    samples = np.percentile(pad.reshape(gy, ph // gy, gx, pw // gx), q, axis=(1, 3))

    cy = (np.arange(gy) + 0.5) * (ph / gy) / max(1, H)
    cx = (np.arange(gx) + 0.5) * (pw / gx) / max(1, W)
    Y, X = np.meshgrid(cy, cx, indexing="ij")

    def basis(x, y):
        o = np.ones_like(x)
        return np.stack([o, x, y, x * x, x * y, y * y], axis=-1)

    A = basis(X.ravel(), Y.ravel())
    coef, *_ = np.linalg.lstsq(A, samples.ravel(), rcond=None)
    yy = (np.arange(H) / max(1, H))[:, None] * np.ones((1, W))
    xx = np.ones((H, 1)) * (np.arange(W) / max(1, W))[None, :]
    return I - basis(xx, yy) @ coef


def ink(img, flat=True) -> np.ndarray:
    if isinstance(img, str):
        img = Image.open(img)
    I = 255.0 - np.asarray(img.convert("L"), dtype=np.float64)
    return flatten(I) if flat else I


def _skew_score(im: Image.Image, ang: float) -> float:
    a = ink(im.rotate(ang, resample=Image.BILINEAR, fillcolor=255))
    return float(ink_mask(a).sum(axis=1).astype(float).var())


def deskew(im: Image.Image, search=2.5, coarse=11, refine=9
           ) -> tuple[Image.Image, float]:
    """
    Text rows are sharpest when level, so maximise the variance of the row profile.
    Searched coarse-to-fine on a downsampled copy: a full-resolution sweep costs
    dozens of page rotations for no extra accuracy, since the optimum is smooth.
    """
    small = im.convert("L")
    if max(small.size) > 900:
        f = 900 / max(small.size)
        small = small.resize((max(1, int(small.width * f)),
                              max(1, int(small.height * f))), Image.BILINEAR)
    best, bang = None, 0.0
    for i in range(coarse):
        ang = -search + 2 * search * i / (coarse - 1)
        v = _skew_score(small, ang)
        if best is None or v > best:
            best, bang = v, ang
    step = 2 * search / (coarse - 1)
    lo, hi = bang - step, bang + step
    for i in range(refine):
        ang = lo + (hi - lo) * i / (refine - 1)
        v = _skew_score(small, ang)
        if v > best:
            best, bang = v, ang
    if abs(bang) < 1e-3:
        return im, 0.0
    return im.rotate(bang, resample=Image.BICUBIC, fillcolor=255), bang


def paper_cut(A: np.ndarray, frac: float, k: float = 4.0) -> tuple[float, float, float]:
    """
    Where ink stops and paper begins, measured FROM THE PAPER LEVEL rather than from
    zero. Returns (floor, cut, sigma).

    Both of this module's thresholds were originally written as a fraction of the peak,
    which silently assumes paper sits at zero. It does in a rasterised PDF, where the
    page is pure white, and it does not in a photograph: a phone camera under office
    light renders paper as grey, so the ink array carries a large constant pedestal.
    A cut measured from zero then lands *below* the pedestal, every paper pixel counts
    as ink, and the failure is the same one twice over -- the ink bounding box becomes
    the whole page, and the centroid window fills with paper.

    Two terms, and both are needed:

      frac * (peak - floor)   scale-free: tracks the contrast actually present, so a
                              faint photograph is thresholded proportionally
      k * sigma               noise-floor: guarantees the cut clears the paper's own
                              fluctuation even when contrast is high, which is what
                              stops half-wave rectified noise surviving the clip

    sigma is a median-absolute-deviation estimate taken from the sub-floor half of the
    data, so ink cannot inflate it.
    """
    floor = float(np.percentile(A, 50))
    peak = float(np.percentile(A, 99.9))
    lo = A[A <= floor]
    sigma = (float(1.4826 * np.median(np.abs(lo - np.median(lo))))
             if lo.size else 0.0)
    return floor, floor + max(frac * (peak - floor), k * sigma), sigma


def ink_mask(I: np.ndarray) -> np.ndarray:
    """Binary ink map. Thresholding before any projection is essential: on a noisy
    scan every row of blank paper accumulates enough energy to look like text, which
    silently turns the text bounding box into the whole page."""
    _floor, cut, _sigma = paper_cut(I, 0.35)
    return I > cut


def ink_bbox(I: np.ndarray, min_px=3, min_frac=0.06):
    """
    The text box. A row counts as text only if it carries a reasonable FRACTION of the
    busiest row's ink, not merely `min_px` pixels: an absolute pixel count is meaningless
    on an image whose size the detector does not choose, and a handful of surviving
    paper pixels per row -- inevitable once illumination is uneven -- is enough to stretch
    an absolute-threshold box to the page edges.
    """
    M = ink_mask(I)
    rows, cols = M.sum(axis=1), M.sum(axis=0)
    if rows.max() == 0 or cols.max() == 0:
        return None
    ry = np.flatnonzero(rows >= max(min_px, min_frac * rows.max()))
    cx = np.flatnonzero(cols >= max(min_px, min_frac * cols.max()))
    if len(ry) == 0 or len(cx) == 0:
        return None
    return int(cx[0]), int(ry[0]), int(cx[-1]) + 1, int(ry[-1]) + 1


def normalise(leaked: Image.Image, ref_png: str) -> Image.Image:
    """Deskew, then scale and translate the leaked page onto the reference's ink box."""
    im, _ang = deskew(leaked)
    Il, Ir = ink(im), ink(ref_png)
    bl, br = ink_bbox(Il), ink_bbox(Ir)
    if bl is None or br is None:
        return im
    lw, lh = bl[2] - bl[0], bl[3] - bl[1]
    rw, rh = br[2] - br[0], br[3] - br[1]
    if lw < 8 or lh < 8:
        return im
    sx, sy = rw / lw, rh / lh
    W, H = Image.open(ref_png).size
    out = Image.new("L", (W, H), 255)
    crop = im.convert("L").crop(bl).resize((max(1, rw), max(1, rh)), Image.LANCZOS)
    out.paste(crop, (br[0], br[1]))
    return out


INK_THRESHOLD = 0.20


def denoise(band: np.ndarray) -> np.ndarray:
    """
    Keep ink, discard paper. Subtracting a percentile and clipping at zero -- the
    obvious approach -- leaves HALF-WAVE RECTIFIED noise spread over the whole
    measurement window, and because the window is mostly whitespace that rectified
    floor drags the centroid by several pixels: more than the signal. A hard threshold
    removes it, and the threshold is taken relative to the paper level rather than to
    zero so that a grey photograph does not defeat it (see paper_cut). The same
    threshold is applied to the reference, so the two measurements stay symmetric.
    """
    floor, cut, sigma = paper_cut(band, INK_THRESHOLD)
    peak = float(band.max())
    if peak - floor < max(3.0 * sigma, 8.0):
        # nothing rises detectably above the paper: report no ink rather than a
        # rectified noise field, so the position becomes an erasure and not a guess
        return np.zeros_like(band)
    return np.clip(band - cut, 0, None)


def word_centroids(I: np.ndarray, line: dict, dpi: int, pad_pt=1.2):
    sc = dpi / 72.0
    size = line["size"]
    y = PAGE_H - line["baseline_pt"]
    y0 = int(max(0, (y - 0.88 * size) * sc))
    y1 = int(min(I.shape[0], (y + 0.32 * size) * sc))
    if y1 - y0 < 3:
        return None
    cols = denoise(I[y0:y1, :]).sum(axis=0)
    out = []
    for a_pt, b_pt in line["spans_pt"]:
        x0 = int(max(0, (a_pt - pad_pt) * sc))
        x1 = int(min(len(cols), (b_pt + pad_pt) * sc))
        if x1 - x0 < 2:
            return None
        w = cols[x0:x1]
        tot = float(w.sum())
        if tot <= 0:
            return None
        out.append(float((w * np.arange(x0, x1)).sum() / tot))
    return out


def row_profile(I: np.ndarray, bins=96) -> np.ndarray:
    """Normalised vertical ink profile — a cheap page signature."""
    M = ink_mask(I).sum(axis=1).astype(float)
    b = ink_bbox(I)
    if b is not None:
        M = M[b[1]:b[3]]
    if M.size < bins or M.max() <= 0:
        return np.zeros(bins)
    idx = (np.arange(bins) * (M.size / bins)).astype(int)
    v = M[idx]
    return (v - v.mean()) / (v.std() + 1e-9)


def identify_page(evidence_png: str, ref_pngs: list[str]) -> tuple[int, float]:
    """
    Which page of the master is this? A leaked artefact is usually a photograph of one
    page, not the whole document, so the detector has to locate it before it can use
    the layout map. Matching the vertical ink profile is enough and costs nothing.
    """
    e = row_profile(ink(evidence_png))
    best, score = 0, -9e9
    for i, r in enumerate(ref_pngs):
        c = float(np.dot(e, row_profile(ink(r))) / len(e))
        if c > score:
            best, score = i, c
    return best, round(score, 4)


def recover(marked_by_page: dict, ref_pngs, geometry, m: int, dpi: int):
    """
    marked_by_page maps a geometry page index to the image of that page, so partial
    evidence (a single photographed page out of many) works.

    Returns (bits, mask, diagnostics). Positions that cannot be read become erasures
    rather than guesses: the accusation tolerates erasures far better than flips.

    Code positions repeat: the renderer cycles the codeword through however many gaps the
    document provides, so a page-filling document carries each position several times.
    Those repeats are COMBINED rather than overwritten, and combined as signed evidence
    rather than as a majority vote on hard bits -- a gap measured with a 2 px margin
    deserves more weight than one measured with 0.1 px, and summing the displacements
    keeps that weighting for free. Writing each repeat over the last one, which is the
    obvious way to fill the array, throws the redundancy away and roughly triples the
    bit error rate on a dim photograph.
    """
    acc = np.zeros(m)
    reps = np.zeros(m, dtype=int)
    margins = []
    diag = {"lines_used": 0, "lines_unreadable": 0}
    Im = {p: ink(v) for p, v in marked_by_page.items()}
    Ir = {i: ink(p) for i, p in enumerate(ref_pngs)}
    for line in geometry:
        pi = line["page"]
        if pi not in Im or pi not in Ir or not line["bit_indices"]:
            continue
        mc = word_centroids(Im[pi], line, dpi)
        rc = word_centroids(Ir[pi], line, dpi)
        if mc is None or rc is None:
            diag["lines_unreadable"] += 1
            continue
        diag["lines_used"] += 1
        r = np.array(mc) - np.array(rc)
        # Remove any residual affine error on this line before reading the signal.
        # A photograph normalised by bounding box still carries a sub-percent scale
        # error, which across a text line is the same magnitude as the displacement
        # we are trying to measure. The embedded signal is bounded and trend-free by
        # construction (gaps are written in pairs that sum to zero), so fitting and
        # subtracting a straight line in x removes the alignment error and leaves the
        # fingerprint intact.
        xs = np.array(rc)
        if len(r) >= 4:
            A = np.vstack([np.ones_like(xs), xs]).T
            coef, *_ = np.linalg.lstsq(A, r, rcond=None)
            r = r - A @ coef
        else:
            r = r - r[0]
        for k, bidx in enumerate(line["bit_indices"]):
            if 2 * k + 1 >= len(r):
                break
            d = r[2 * k + 1] - r[2 * k]
            acc[bidx] += d
            reps[bidx] += 1
            margins.append(abs(d))
    mask = [bool(n > 0) for n in reps]
    bits = [1 if acc[i] > 0 else 0 for i in range(m)]
    read = reps > 0
    diag["positions_read"] = int(read.sum())
    diag["median_margin_px"] = round(float(np.median(margins)), 3) if margins else 0.0
    diag["redundancy"] = (round(float(reps[read].mean()), 2) if read.any() else 0.0)
    diag["combined_margin_px"] = (round(float(np.median(np.abs(acc[read]))), 3)
                                  if read.any() else 0.0)
    return bits, mask, diag


def pages_of(path: str, dpi: int, prefix: str) -> list[str]:
    """Accept a PDF or one/many images as the leaked artefact."""
    if path.lower().endswith(".pdf"):
        return render_pdf(path, dpi, prefix)
    return [path]
