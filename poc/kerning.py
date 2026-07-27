#!/usr/bin/env python3
"""
CLOISTER — Layer T, analog channel: extract the kerning fingerprint from an IMAGE.

This is the channel that has to survive the analog hole. It carries no text-layer
information at all: the codeword lives in sub-perceptual displacement of inter-word
gaps, so it is recoverable from a screenshot, a print, or a photograph of a screen,
and it is untouched by OCR, copy-paste or PDF re-export.

Extraction is differential. Gaps were written in pairs summing to a constant, so for
each pair the detector only has to decide which of the two is wider. Word positions
are measured by intensity-weighted centroid, giving sub-pixel resolution, and the
reference render (which the document owner holds) is subtracted to cancel the
per-glyph side bearings that would otherwise bias the comparison.
"""
import json, math, os, subprocess, sys
import numpy as np
from PIL import Image


# ------------------------------------------------------------------ rasterising
def render(pdf, dpi, out_prefix):
    subprocess.run(["pdftoppm", "-r", str(dpi), "-gray", "-png", pdf, out_prefix],
                   check=True, capture_output=True)
    d = os.path.dirname(out_prefix) or "."
    base = os.path.basename(out_prefix)
    return [os.path.join(d, f) for f in sorted(os.listdir(d))
            if f.startswith(base) and f.endswith(".png")]


def ink(path):
    a = np.asarray(Image.open(path).convert("L"), dtype=np.float64)
    return 255.0 - a                     # ink weight, 0 = paper


# --------------------------------------------------------------- word geometry
def denoise(band):
    """Remove the paper level so added sensor noise cannot bias a centroid."""
    bg = np.percentile(band, 60)
    return np.clip(band - bg, 0, None)


def word_centroids(I, line, dpi, size=11.0, pad_pt=1.2, page_h=792.0):
    """
    Intensity-weighted x-centroid of every word on a line, measured inside a window
    computed analytically from the master layout. No ink segmentation is involved, so
    blur, noise, JPEG ringing, split glyphs and touching glyphs cannot shift a word
    index -- which is what destroys naive inter-word-spacing detectors.
    """
    sc = dpi / 72.0
    y = page_h - line["y_baseline_pt"]
    y0 = int(max(0, (y - 0.85 * size) * sc))
    y1 = int(min(I.shape[0], (y + 0.30 * size) * sc))
    if y1 - y0 < 3:
        return None
    band = denoise(I[y0:y1, :])
    cols = band.sum(axis=0)
    out = []
    for (a_pt, b_pt) in line["spans_pt"]:
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


# ------------------------------------------------------------------- detection
def recover(marked_pngs, ref_pngs, lines_meta, nbits, dpi):
    """
    Returns (bits, mask, diagnostics). mask[i] is False where position i could not be
    read, so damage becomes an erasure rather than a wrong bit -- the Tardos
    accusation tolerates erasures far better than flips.
    """
    bits = [0] * nbits
    mask = [False] * nbits
    margins = []
    npages = max(m["page"] for m in lines_meta) + 1
    diag = {"lines_used": 0, "lines_unreadable": 0}
    Im = {}
    Ir = {}
    for pi in range(npages):
        if pi < len(marked_pngs):
            Im[pi] = ink(marked_pngs[pi])
        if pi < len(ref_pngs):
            Ir[pi] = ink(ref_pngs[pi])
    for m in lines_meta:
        pi = m["page"]
        if pi not in Im or pi not in Ir:
            diag["lines_unreadable"] += 1; continue
        mc = word_centroids(Im[pi], m, dpi)
        rc = word_centroids(Ir[pi], m, dpi)
        if mc is None or rc is None:
            diag["lines_unreadable"] += 1; continue
        diag["lines_used"] += 1
        r = np.array(mc) - np.array(rc)
        r -= r[0]
        for k, bidx in enumerate(m["bit_indices"]):
            if 2 * k + 1 >= len(r):
                break
            d = r[2 * k + 1] - r[2 * k]
            bits[bidx] = 1 if d > 0 else 0
            mask[bidx] = True
            margins.append(abs(d))
    diag["median_margin_px"] = round(float(np.median(margins)), 3) if margins else 0.0
    return bits, mask, diag


# --------------------------------------------------------------------- attacks
def attack(png, kind, param, out):
    im = Image.open(png).convert("L")
    if kind == "none":
        im.save(out)
    elif kind == "jpeg":
        tmp = out.replace(".png", ".jpg")
        im.save(tmp, quality=param)
        Image.open(tmp).convert("L").save(out)
    elif kind == "rescale":
        w, h = im.size
        s = param
        im.resize((int(w * s), int(h * s)), Image.LANCZOS)\
          .resize((w, h), Image.LANCZOS).save(out)
    elif kind == "rotate":
        im.rotate(param, resample=Image.BICUBIC, fillcolor=255, expand=False)\
          .save(out)
    elif kind == "noise":
        a = np.asarray(im, dtype=np.float64)
        rng = np.random.default_rng(7)
        a = np.clip(a + rng.normal(0, param, a.shape), 0, 255)
        Image.fromarray(a.astype(np.uint8)).save(out)
    return out


def deskew(png, out, search=0.8, steps=17):
    """Maximise row-projection variance -- text lines are sharpest when level."""
    im = Image.open(png).convert("L")
    best, bang = None, 0.0
    for i in range(steps):
        ang = -search + 2 * search * i / (steps - 1)
        a = np.asarray(im.rotate(ang, resample=Image.BICUBIC, fillcolor=255),
                       dtype=np.float64)
        v = (255.0 - a).sum(axis=1).var()
        if best is None or v > best:
            best, bang = v, ang
    im.rotate(bang, resample=Image.BICUBIC, fillcolor=255).save(out)
    return bang


# ------------------------------------------------------------------ experiment
def run():
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import chaff_pdf
    truth = open("out/true_doc.txt").read()
    lex = open("out/decoy_doc.txt").read().split()
    rng = np.random.default_rng(20260725)
    os.makedirs("/tmp/k", exist_ok=True)
    results = {"capacity": {}, "delta_sweep": [], "dpi_sweep": [], "attacks": []}

    for dm in (10, 15, 25, 40):
        info = chaff_pdf.build(truth, f"/tmp/k/m{dm}.pdf", "R-0001-adi", lex,
                               bits=[1] * 8, delta_mille=dm)
        results["capacity"][dm] = {
            "bits_per_page": info["gaps_marked"], "delta_pt": info["delta_pt"],
            "delta_pct_of_space_advance": round(dm / (0.318 * 1000) * 100, 1)}

    ref = chaff_pdf.build(truth, "/tmp/k/ref.pdf", "R-0001-adi", lex,
                          bits=None, delta_mille=0)
    NB = 96
    payload = rng.integers(0, 2, NB).tolist()

    def trial(dm, dpi, kind="none", param=None, do_deskew=False):
        info = chaff_pdf.build(truth, "/tmp/k/mk.pdf", "R-0001-adi", lex,
                               bits=payload, delta_mille=dm)
        mp = render("/tmp/k/mk.pdf", dpi, "/tmp/k/mk")
        rp = render("/tmp/k/ref.pdf", dpi, "/tmp/k/rf")
        if kind != "none":
            out = []
            for i, p in enumerate(mp):
                o = f"/tmp/k/atk{i}.png"
                attack(p, kind, param, o)
                if do_deskew:
                    d = f"/tmp/k/dsk{i}.png"; deskew(o, d); o = d
                out.append(o)
            mp = out
        bits, mask, diag = recover(mp, rp, info["lines"], NB, dpi)
        read = [i for i in range(NB) if mask[i]]
        err = sum(1 for i in read if bits[i] != payload[i])
        return {"positions_read": len(read), "erasures": NB - len(read),
                "ber_on_read": round(err / max(1, len(read)), 4), **diag}

    for dm in (10, 15, 25, 40):
        r = trial(dm, 200); r.update({"delta_mille": dm, "dpi": 200})
        results["delta_sweep"].append(r); print("delta", dm, r, flush=True)
    for dpi in (110, 150, 200, 300):
        r = trial(25, dpi); r.update({"dpi": dpi, "delta_mille": 25})
        results["dpi_sweep"].append(r); print("dpi", dpi, r, flush=True)
    for kind, param, ds, label in [
        ("jpeg", 75, False, "JPEG q75 screenshot"),
        ("jpeg", 40, False, "JPEG q40 heavy recompression"),
        ("rescale", 0.5, False, "downscale 50% then restore"),
        ("noise", 8.0, False, "Gaussian sensor noise sigma 8"),
        ("rotate", 0.4, True, "0.4 deg rotation + deskew"),
        ("rotate", 0.4, False, "0.4 deg rotation, no deskew"),
    ]:
        r = trial(25, 300, kind, param, ds)
        r.update({"attack": label, "dpi": 300, "delta_mille": 25})
        results["attacks"].append(r); print("attack:", label, r, flush=True)

    json.dump(results, open("out/kerning.json", "w"), indent=1)
    return results


if __name__ == "__main__":
    run()
