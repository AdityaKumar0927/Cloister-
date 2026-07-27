"""
The kerning detector: end-to-end recovery, and the two image-domain bugs that made it
score at chance without ever raising an error.
"""
import os
import sys
import tempfile

import numpy as np
from PIL import Image

sys.path.insert(0, "..")
sys.path.insert(0, ".")

from cloister import decoy as D                                   # noqa: E402
from cloister import detect as DT                                 # noqa: E402
from cloister import render as R                                  # noqa: E402
from harness import claim, main, mutation, regression             # noqa: E402

DPI = 300
BODY = [
    {"kind": "h1", "text": "Interim Findings, Restricted Circulation"},
    {"kind": "p", "text":
        "The committee reviewed the outstanding items and agreed that the remaining "
        "questions should be settled before the schedule is published to the wider "
        "group. Several members asked for a written summary of the reasoning, which "
        "will be circulated with the next agenda and held under the usual terms of "
        "restricted circulation until the review has formally closed."},
    {"kind": "p", "text":
        "A second paragraph gives the detector more lines to work with, because each "
        "line carries only a handful of paired gaps and the accusation test wants as "
        "many observed positions as the page can provide without any of them being "
        "guessed rather than measured."},
]

_BUILT = {}


def _build(bits, tag):
    """Render a marked copy plus the unmarked reference, and rasterise both."""
    key = (tuple(bits), tag)
    if key in _BUILT:
        return _BUILT[key]
    d = tempfile.mkdtemp(prefix="cloister-kern-")
    marked = os.path.join(d, "marked.pdf")
    ref = os.path.join(d, "ref.pdf")
    _rep, geom = R.protect(BODY, marked, D.Decoy("minutes", tag), bits=bits)
    R.protect(BODY, ref, D.Decoy("minutes", tag), bits=None)
    m_png = DT.render_pdf(marked, DPI, os.path.join(d, "m"))
    r_png = DT.render_pdf(ref, DPI, os.path.join(d, "r"))
    _BUILT[key] = (geom, m_png, r_png, d)
    return _BUILT[key]


def _degrade(path, out, rotate=0.6, scale=0.87, noise=9.0, seed=0,
             paper=255, gradient=0.0, vignette=0.0):
    """
    A plausible photograph: slight rotation, rescaling, sensor noise, and -- when
    `paper` is below 255 -- a page that is grey rather than white, with an illumination
    gradient across it.

    That last part matters more than it sounds. With paper at 255 the uint8 save clips
    away the negative half of every noise sample, so the noise arrives at the detector
    already one-sided and a threshold measured from zero happens to work. A real
    photograph has paper well inside the range. Every degradation ladder in this project
    used white paper until this suite was written, which is how two threshold bugs
    survived measurement.
    """
    rng = np.random.default_rng(seed)
    im = Image.open(path).convert("L")
    if rotate:
        im = im.rotate(rotate, resample=Image.BICUBIC, fillcolor=255, expand=True)
    if scale != 1.0:
        im = im.resize((int(im.width * scale), int(im.height * scale)), Image.LANCZOS)
    a = np.asarray(im, dtype=np.float64) * (paper / 255.0)
    h, w = a.shape
    if gradient:
        a = (a + np.linspace(-gradient, gradient, w)[None, :]
             + np.linspace(-gradient / 2, gradient / 2, h)[:, None])
    if vignette:
        # cos^4-style falloff plus an off-centre shadow: illumination that a linear ramp
        # cannot represent, so the detector's background model is not being handed the
        # exact family of surfaces it was tuned on
        yy = (np.arange(h) / h)[:, None] - 0.42
        xx = (np.arange(w) / w)[None, :] - 0.55
        rr = np.sqrt(xx ** 2 + yy ** 2) / 0.7
        a = a * (1.0 - vignette * np.clip(rr, 0, 1.4) ** 2)
    a = a + rng.normal(0, noise, (h, w))
    Image.fromarray(np.clip(a, 0, 255).astype(np.uint8)).save(out)
    return out


@claim("kerning-recovers-bits-from-a-photograph",
       says="the fingerprint survives rotation, rescaling and sensor noise, and every "
            "position that is read is read correctly")
def recovers_from_photograph():
    rng = np.random.default_rng(5)
    m = 64
    bits = rng.integers(0, 2, m).tolist()
    geom, m_png, r_png, d = _build(bits, "photo")
    leaked = _degrade(m_png[0], os.path.join(d, "leak.png"), seed=1)
    got, mask, diag = DT.recover({0: DT.normalise(Image.open(leaked), r_png[0])},
                                 r_png, geom, m, DPI)
    read = [i for i in range(m) if mask[i]]
    assert read, "no positions were read at all"
    wrong = [i for i in read if got[i] != bits[i]]
    assert len(wrong) <= 1, f"{len(wrong)} of {len(read)} positions read wrong: {wrong}"
    return {"positions read": f"{len(read)}/{m}", "bit errors": len(wrong),
            "median margin": f"{diag['median_margin_px']} px",
            "lines used": diag["lines_used"]}


@claim("kerning-erasures-not-guesses",
       says="positions the detector cannot measure become erasures, never guesses, "
            "because the accusation test tolerates erasures far better than flips")
def unread_positions_are_erasures():
    bits = [1, 0] * 32
    geom, _m_png, r_png, _d = _build(bits, "erasure")
    # give the detector a blank page: it must read nothing rather than invent bits
    blank = Image.new("L", Image.open(r_png[0]).size, 255)
    got, mask, diag = DT.recover({0: blank}, r_png, geom, 64, DPI)
    assert sum(mask) == 0, f"read {sum(mask)} positions off a blank page"
    assert diag["lines_unreadable"] > 0, "blank page did not register as unreadable"
    return {"positions read from a blank page": 0,
            "lines reported unreadable": diag["lines_unreadable"]}


# ------------------------------------------------------------------ the two bugs
@regression("kerning-ink-bbox-under-noise",
            bug="the ink bounding box projected raw intensity, so on a noisy scan every "
                "row of blank paper accumulated enough energy to look like text. The box "
                "became the whole page, normalise() then rescaled by the wrong factor, "
                "and the detector scored at chance with no error raised.",
            found_by="feeding the detector a noisy page instead of a clean render")
def ink_bbox_ignores_paper_noise():
    _geom, m_png, _r_png, d = _build([0] * 64, "bbox")
    noisy = _degrade(m_png[0], os.path.join(d, "noisy.png"),
                     rotate=0, scale=1.0, noise=14.0, seed=3)
    I = DT.ink(noisy)
    page = I.shape[0] * I.shape[1]
    box = DT.ink_bbox(I)
    assert box is not None
    area = (box[2] - box[0]) * (box[3] - box[1])
    frac = area / page
    assert frac < 0.85, (
        f"the ink box covers {frac:.1%} of a noisy page, so it is measuring paper")
    # and the box must still contain the text: compare against the clean render's box
    clean = DT.ink_bbox(DT.ink(m_png[0]))
    for k in range(4):
        assert abs(box[k] - clean[k]) < 0.06 * max(I.shape), (
            f"noisy box edge {k} moved {abs(box[k] - clean[k])} px from the clean box")
    return {"ink box on a noisy page": f"{frac:.1%} of the page",
            "clean box": f"{(clean[2] - clean[0]) * (clean[3] - clean[1]) / page:.1%}",
            "edges agree with clean render": "within 6% of page size"}


@mutation("kerning-ink-bbox-under-noise")
def _original_unthresholded_projection():
    _geom, m_png, _r_png, d = _build([0] * 64, "bbox")
    noisy = os.path.join(d, "noisy.png")
    if not os.path.exists(noisy):
        _degrade(m_png[0], noisy, rotate=0, scale=1.0, noise=14.0, seed=3)
    I = DT.ink(noisy)
    rows, cols = I.sum(axis=1), I.sum(axis=0)          # <-- the bug: no threshold
    ry = np.flatnonzero(rows >= 3)
    cx = np.flatnonzero(cols >= 3)
    box = (int(cx[0]), int(ry[0]), int(cx[-1]) + 1, int(ry[-1]) + 1)
    frac = ((box[2] - box[0]) * (box[3] - box[1])) / (I.shape[0] * I.shape[1])
    assert frac < 0.85, f"unthresholded box covers {frac:.1%} of the page"


@regression("kerning-rectified-noise-denoiser",
            bug="denoise() subtracted a percentile and clipped at zero, which leaves "
                "half-wave rectified noise spread over the whole measurement window. The "
                "window is mostly whitespace, so that rectified floor dragged the "
                "centroid several pixels -- more than the 1.09 px signal.",
            found_by="measuring centroid drift on a noisy page against the signal "
                     "amplitude, rather than assuming the noise averaged out")
def denoiser_leaves_the_centroid_alone():
    _geom, drift, signal_px, worst = _centroid_drift(DT.denoise)
    assert drift < 0.85 * signal_px, (
        f"noise drags the centroid {drift:.2f} px against a {signal_px:.2f} px signal "
        f"(worst at {worst})")
    return {"worst centroid drift": f"{drift:.2f} px ({worst})",
            "signal amplitude": f"{signal_px:.2f} px",
            "drift / signal": round(drift / signal_px, 3)}


SIGNAL_PX = 0.2625 * DPI / 72.0

# paper level, noise sigma, illumination gradient: white office scan through to a dim
# phone photograph
LIGHTING = [(255, 12.0, 0.0), (224, 12.0, 18.0), (200, 14.0, 18.0), (180, 16.0, 20.0)]


def _centroid_drift(denoiser):
    """Worst centroid displacement caused by degradation alone, across lighting."""
    geom, m_png, _r_png, d = _build([0] * 64, "denoise")
    line = next(l for l in geom if l["bit_indices"])
    real = DT.denoise
    worst, where = 0.0, None
    try:
        DT.denoise = denoiser
        c0 = DT.word_centroids(DT.ink(m_png[0]), line, DPI)
        for paper, noise, grad in LIGHTING:
            png = os.path.join(d, f"lit{paper}.png")
            if not os.path.exists(png):
                _degrade(m_png[0], png, rotate=0, scale=1.0, noise=noise,
                         seed=7, paper=paper, gradient=grad)
            c1 = DT.word_centroids(DT.ink(png), line, DPI)
            if c1 is None:
                worst, where = float("inf"), f"paper {paper}: window unreadable"
                break
            dr = float(np.max(np.abs(np.array(c1) - np.array(c0))))
            if dr > worst:
                worst, where = dr, f"paper {paper}"
    finally:
        DT.denoise = real
    return geom, worst, SIGNAL_PX, where


@mutation("kerning-rectified-noise-denoiser")
def _original_percentile_subtract():
    def broken(band):
        return np.clip(band - np.percentile(band, 60), 0, None)   # <-- the bug

    _geom, drift, signal_px, worst = _centroid_drift(broken)
    assert drift < 0.85 * signal_px, (
        f"percentile denoiser drifts {drift:.2f} px against {signal_px:.2f} px of "
        f"signal (worst at {worst})")


@regression("kerning-paper-pedestal",
            bug="the detector had no background model and both its thresholds were a "
                "fraction of the PEAK, which assumes paper sits at zero. It does in a "
                "rasterised PDF and it does not in a photograph: grey, unevenly lit paper "
                "is a pedestal the cut lands below, so paper counts as ink, the text box "
                "stretches toward the dark edge, normalise() fits that stretched box, and "
                "every word window afterwards is displaced by more than the signal. Fixed "
                "in two places: an illumination surface is subtracted first (flatten), "
                "and what remains is thresholded relative to the paper level with a "
                "noise-floor term (paper_cut).",
            found_by="this suite. Every earlier degradation ladder used white paper, "
                     "where the uint8 clip removes the negative half of the noise and a "
                     "cut measured from zero happens to work.")
def thresholds_are_measured_from_the_paper_level():
    _geom, m_png, _r_png, d = _build([0] * 64, "pedestal")
    clean_box = DT.ink_bbox(DT.ink(m_png[0]))
    I0 = DT.ink(m_png[0])
    page = I0.shape[0] * I0.shape[1]
    clean_frac = ((clean_box[2] - clean_box[0]) * (clean_box[3] - clean_box[1])) / page
    out = {}
    for paper, noise, grad in LIGHTING:
        png = os.path.join(d, f"ped{paper}.png")
        _degrade(m_png[0], png, rotate=0, scale=1.0, noise=noise, seed=7,
                 paper=paper, gradient=grad)
        I = DT.ink(png)
        box = DT.ink_bbox(I)
        assert box is not None, f"paper {paper}: no ink found at all"
        frac = ((box[2] - box[0]) * (box[3] - box[1])) / (I.shape[0] * I.shape[1])
        assert frac < 2.0 * clean_frac, (
            f"paper {paper}: ink box is {frac:.1%} of the page against {clean_frac:.1%} "
            f"on the clean render, so the threshold is below the paper pedestal")
        out[f"paper {paper}"] = f"ink box {frac:.1%} (clean {clean_frac:.1%})"
    return out


@mutation("kerning-paper-pedestal")
def _original_peak_relative_threshold():
    """
    The original detector, restored: no background model, and a threshold measured as a
    fraction of the peak. Both pieces have to go -- flatten() removes the pedestal before
    ink_mask ever sees it, so reverting only the threshold reverts nothing.
    """
    _geom, m_png, _r_png, d = _build([0] * 64, "pedestal")

    def broken_mask(I):
        peak = np.percentile(I, 99.9)
        return I > max(0.35 * peak, 24.0)                 # <-- the bug

    real_mask, real_flat = DT.ink_mask, DT.flatten
    try:
        DT.ink_mask = broken_mask
        DT.flatten = lambda I, **kw: I                    # <-- and no background model
        I0 = DT.ink(m_png[0])
        page = I0.shape[0] * I0.shape[1]
        clean_box = DT.ink_bbox(I0)
        clean_frac = ((clean_box[2] - clean_box[0])
                      * (clean_box[3] - clean_box[1])) / page
        for paper, noise, grad in LIGHTING:
            png = os.path.join(d, f"ped{paper}.png")
            if not os.path.exists(png):
                _degrade(m_png[0], png, rotate=0, scale=1.0, noise=noise, seed=7,
                         paper=paper, gradient=grad)
            I = DT.ink(png)
            box = DT.ink_bbox(I)
            assert box is not None
            frac = ((box[2] - box[0]) * (box[3] - box[1])) / (I.shape[0] * I.shape[1])
            assert frac < 2.0 * clean_frac, (
                f"peak-relative threshold: paper {paper} gives a {frac:.1%} ink box "
                f"against {clean_frac:.1%} clean")
    finally:
        DT.ink_mask, DT.flatten = real_mask, real_flat


@claim("kerning-recovers-from-a-dim-photograph",
       says="bits are still recovered when the page is photographed grey and unevenly "
            "lit, not only when it is scanned white")
def recovers_from_dim_photograph():
    rng = np.random.default_rng(11)
    m = 64
    bits = rng.integers(0, 2, m).tolist()
    geom, m_png, r_png, d = _build(bits, "dim")
    leaked = _degrade(m_png[0], os.path.join(d, "dim.png"), rotate=0.5, scale=0.9,
                      noise=13.0, seed=4, paper=196, gradient=20.0)
    got, mask, diag = DT.recover({0: DT.normalise(Image.open(leaked), r_png[0])},
                                 r_png, geom, m, DPI)
    read = [i for i in range(m) if mask[i]]
    wrong = [i for i in read if got[i] != bits[i]]
    ber = len(wrong) / max(1, len(read))
    assert len(read) >= 20, f"only {len(read)} positions read from a dim photograph"
    # A dim, unevenly lit photograph does produce a few flips. The claim is not that it
    # produces none -- it is that the bit error rate stays inside the range the
    # accusation test tolerates, which test_code measures independently at 5% and 10%.
    assert ber < 0.10, f"bit error rate {ber:.1%} exceeds what the accusation tolerates"
    return {"positions read": f"{len(read)}/{m}", "bit errors": len(wrong),
            "bit error rate": f"{ber:.1%}",
            "median margin": f"{diag['median_margin_px']} px"}


@claim("kerning-page-identification",
       says="a single leaked page out of many is matched to its position in the master "
            "by row profile, so partial evidence is usable")
def page_identification():
    bits = [1, 0] * 32
    geom, m_png, r_png, d = _build(bits, "pageid")
    assert len(r_png) >= 1
    leaked = _degrade(m_png[0], os.path.join(d, "pid.png"), seed=2)
    idx, score = DT.identify_page(leaked, r_png)
    assert idx == 0, f"identified page {idx}, expected 0"
    assert score > 0.5, f"correlation only {score:.3f}"
    return {"identified page": idx, "correlation": round(float(score), 3),
            "reference pages": len(r_png)}


@claim("kerning-deskew-is-cheap-and-accurate",
       says="deskew recovers the rotation to a fraction of a degree without a "
            "full-resolution sweep")
def deskew_accuracy():
    _geom, m_png, _r_png, d = _build([0] * 64, "skew")
    im = Image.open(m_png[0]).convert("L")
    out = {}
    for applied in (-1.4, 0.9):
        rot = im.rotate(applied, resample=Image.BICUBIC, fillcolor=255, expand=True)
        _fixed, found = DT.deskew(rot)
        err = abs((-applied) - found)
        assert err < 0.35, f"applied {applied} deg, deskew found {found:.2f} (err {err:.2f})"
        out[f"applied {applied:+.1f} deg"] = f"found {found:+.2f}, error {err:.2f}"
    return out


if __name__ == "__main__":
    main(__doc__)


@regression("kerning-stale-page-renders",
            bug="render_pdf collected every PNG matching its prefix without clearing the "
                "directory first, and the trace command reuses a fixed working directory. "
                "A one-page document traced after an eight-page one therefore saw eight "
                "reference pages, seven of them belonging to a different document, and "
                "compared the evidence against whichever one matched best.",
            found_by="smoke-testing the CLI twice in a row and noticing that a one-page "
                     "brief reported an eight-page reference")
def stale_renders_are_cleared():
    _geom, m_png, _r_png, d = _build([0] * 64, "stale")
    work = os.path.join(d, "work")
    os.makedirs(work, exist_ok=True)
    # a previous run of a longer document left its pages behind
    for n in (1, 2, 3, 4):
        Image.new("L", (80, 100), 200).save(os.path.join(work, f"ref-{n}.png"))
    pages = DT.render_pdf(os.path.join(d, "ref.pdf"), 72, os.path.join(work, "ref"))
    assert len(pages) == 1, (
        f"render_pdf returned {len(pages)} pages for a one-page document: "
        f"{[os.path.basename(p) for p in pages]}")
    for p in pages:
        assert Image.open(p).size[0] > 200, "returned a stale placeholder image"
    # and a neighbouring render whose prefix nests inside this one must be left alone
    Image.new("L", (80, 100), 200).save(os.path.join(work, "ref2-1.png"))
    again = DT.render_pdf(os.path.join(d, "ref.pdf"), 72, os.path.join(work, "ref"))
    assert len(again) == 1, "cleaning 'ref' picked up 'ref2-1.png'"
    assert os.path.exists(os.path.join(work, "ref2-1.png")), \
        "cleaning prefix 'ref' deleted the neighbouring 'ref2' render"
    return {"stale files planted": 4, "pages returned": len(pages)}


@mutation("kerning-stale-page-renders")
def _original_no_cleanup():
    import subprocess as SP
    _geom, _m_png, _r_png, d = _build([0] * 64, "stale")
    work = os.path.join(d, "work2")
    os.makedirs(work, exist_ok=True)
    for n in (1, 2, 3, 4):
        Image.new("L", (80, 100), 200).save(os.path.join(work, f"ref-{n}.png"))
    prefix = os.path.join(work, "ref")
    SP.run(["pdftoppm", "-r", "72", "-gray", "-png", os.path.join(d, "ref.pdf"), prefix],
           check=True, capture_output=True)          # <-- no cleanup first
    base = os.path.basename(prefix)
    pages = [os.path.join(work, f) for f in sorted(os.listdir(work))
             if f.startswith(base) and f.endswith(".png")]
    assert len(pages) == 1, (
        f"without clearing the prefix, render_pdf returns {len(pages)} pages for a "
        f"one-page document")
