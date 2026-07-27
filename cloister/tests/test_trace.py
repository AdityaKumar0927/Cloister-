"""
The whole trace path, end to end: render a marked copy, photograph it, recover the bits,
and name the recipient out of a roster.

This is the claim the whitepaper leads with, and it is the one no single module can
support on its own -- the renderer, the detector and the accusation test all have to be
right, and the failure mode when one of them is subtly wrong is a confident accusation of
the wrong person.

One parameter decides whether this works at all, and it is easy to get wrong: the
REDUNDANCY, meaning how many gaps a single page provides per code position. A page-filling
document gives about 205 marked gaps, so a 69-bit code is carried about three times over
on every page and one photograph observes the whole codeword. Choose a code longer than
the page can carry and a single page yields a fraction of the positions instead, which is
a different and much weaker regime. The suite asserts the redundancy it is testing at,
rather than leaving it implicit.
"""
import os
import sys
import tempfile

import numpy as np
from PIL import Image

sys.path.insert(0, "..")
sys.path.insert(0, ".")

from cloister import code as C                                    # noqa: E402
from cloister import decoy as D                                   # noqa: E402
from cloister import detect as DT                                 # noqa: E402
from cloister import render as R                                  # noqa: E402
from harness import claim, main, mutation, regression             # noqa: E402
from test_kerning import DPI, _degrade                            # noqa: E402

ROSTER = 40
M = C.code_length(1, 1e-6)          # 69 bits: single-leaker tracing
TRACES = 6

_PARA = (
    "The committee reviewed the outstanding items and agreed that the remaining "
    "questions should be settled before the schedule is published to the wider group. "
    "Several members asked for a written summary of the reasoning, which will be "
    "circulated with the next agenda and held under the usual terms of restricted "
    "circulation until the review has formally closed. ")

BODY = ([{"kind": "h1", "text": "Interim Findings, Restricted Circulation"}]
        + [{"kind": "p", "text": _PARA * 2} for _ in range(4)])

# paper level, noise sigma, illumination gradient, rotation, rescale
LIGHTINGS = [
    (255, 9.0, 0.0, 0.6, 0.87),      # flatbed scan
    (240, 11.0, 12.0, -0.4, 0.95),   # good phone photo
    (224, 12.0, 18.0, 0.8, 0.90),    # ordinary phone photo
    (210, 13.0, 18.0, -0.7, 1.05),   # dim room, slight upscale
    (255, 14.0, 0.0, 0.0, 0.80),     # screenshot, downscaled
    (200, 13.0, 20.0, 0.5, 0.92),    # dim and uneven
]

_REF = {}


def _reference(tmp):
    """
    The unmarked master, rasterised once. One reference serves every recipient because
    line breaking uses unperturbed advances (asserted in test_render).

    The layout map has to come from a MARKED render, though: bit_indices are only
    populated when a codeword is supplied, so an unmarked render tells the detector where
    the words are but not which gap carries which code position.
    """
    if "png" not in _REF:
        ref_pdf = os.path.join(tmp, "ref.pdf")
        R.protect(BODY, ref_pdf, D.Decoy("minutes", "master"), bits=None)
        _REF["png"] = DT.render_pdf(ref_pdf, DPI, os.path.join(tmp, "ref"))
        map_pdf = os.path.join(tmp, "map.pdf")
        _rep, geom = R.protect(BODY, map_pdf, D.Decoy("minutes", "master"),
                               bits=[0] * M)
        _REF["geom"] = geom
    return _REF["png"], _REF["geom"]


def _trace_once(code, thr, user, tmp, lighting, seed):
    """Mark one recipient's copy, photograph it, recover, accuse."""
    r_png, geom = _reference(tmp)
    marked = os.path.join(tmp, f"u{user}.pdf")
    R.protect(BODY, marked, D.Decoy("minutes", "master"), bits=code.word(user))
    m_png = DT.render_pdf(marked, DPI, os.path.join(tmp, f"m{user}"))

    paper, noise, grad, rot, scale = lighting[:5]
    vig = lighting[5] if len(lighting) > 5 else 0.0
    leaked = _degrade(m_png[0], os.path.join(tmp, f"leak{user}_{seed}.png"),
                      rotate=rot, scale=scale, noise=noise, seed=seed,
                      paper=paper, gradient=grad, vignette=vig)
    page, _score = DT.identify_page(leaked, r_png)
    fixed = DT.normalise(Image.open(leaked), r_png[page])
    bits, mask, diag = DT.recover({page: fixed}, r_png, geom, code.m, DPI)
    accused, S, nobs = code.accuse(bits, mask, thr)

    truth = code.word(user)
    read = [i for i in range(code.m) if mask[i]]
    ber = sum(1 for i in read if bits[i] != truth[i]) / max(1, len(read))
    innocent = [abs(S[i]) for i in range(code.n) if i != user]
    return {"user": user, "accused": accused, "nobs": nobs, "ber": ber,
            "score": float(abs(S[user])), "next_innocent": float(max(innocent)),
            "margin": float(abs(S[user]) / max(1e-9, max(innocent))),
            "redundancy": diag["redundancy"], "diag": diag}


@claim("trace-redundancy-regime",
       says="a page-filling document carries each code position about three times, so "
            "one photographed page observes the whole codeword")
def redundancy_regime():
    tmp = tempfile.mkdtemp(prefix="cloister-red-")
    _r_png, geom = _reference(tmp)
    per_page = {}
    for line in geom:
        per_page[line["page"]] = per_page.get(line["page"], 0) + len(line["bit_indices"])
    gaps = per_page.get(0, 0)
    assert gaps >= 2 * M, (
        f"page 0 carries {gaps} gaps for a {M}-bit code: redundancy {gaps / M:.2f}x, "
        f"too low for the single-page regime this suite tests")
    return {"code length": M, "gaps on page 0": gaps,
            "redundancy": f"{gaps / M:.2f}x", "pages": len(per_page)}


@claim("trace-end-to-end",
       says=f"{TRACES} of {TRACES} photographed single pages are traced to the correct "
            f"recipient out of a roster of {ROSTER}, with zero false accusations")
def trace_end_to_end():
    code = C.Code(ROSTER, M, 1, 4242)
    tmp = tempfile.mkdtemp(prefix="cloister-trace-")
    # Calibrate for the evidence a page actually yields, not for the full code length.
    probe = _trace_once(code, 6.0, 0, tmp, LIGHTINGS[0], seed=99)
    nobs = probe["nobs"]
    thr = code.calibrate(nobs, family_wise=1e-3, trials=1500, seed=3)

    correct, false, worst, detail = 0, 0, None, {}
    for k in range(TRACES):
        user = int(np.random.default_rng(70 + k).integers(0, ROSTER))
        r = _trace_once(code, thr, user, tmp, LIGHTINGS[k % len(LIGHTINGS)], seed=200 + k)
        named = bool(r["accused"]) and r["accused"][0] == user
        correct += 1 if named else 0
        false += len([a for a in r["accused"] if a != user])
        worst = r["margin"] if worst is None else min(worst, r["margin"])
        detail[f"trace {k} (user {user:>2})"] = (
            f"{'named' if named else 'MISSED'}  {r['nobs']}/{M} positions  "
            f"ber {r['ber']:.1%}  {r['margin']:.1f}x nearest innocent")
    assert correct == TRACES, f"only {correct}/{TRACES} traced correctly"
    assert false == 0, f"{false} false accusations"
    detail["calibrated threshold"] = f"{thr:.2f} sqrt(nobs) at {nobs} positions"
    detail["worst margin over nearest innocent"] = f"{worst:.1f}x"
    return detail


@claim("trace-innocent-recipients-are-not-accused",
       says="no innocent member of the roster is ever named, which is the property that "
            "makes a trace usable as evidence rather than as suspicion")
def innocent_recipients_not_accused():
    code = C.Code(ROSTER, M, 1, 4242)
    tmp = tempfile.mkdtemp(prefix="cloister-innocent-")
    probe = _trace_once(code, 6.0, 3, tmp, LIGHTINGS[0], seed=5)
    thr = code.calibrate(probe["nobs"], family_wise=1e-3, trials=1500, seed=3)
    out = {}
    for user, light in ((3, LIGHTINGS[1]), (17, LIGHTINGS[3])):
        r = _trace_once(code, thr, user, tmp, light, seed=6 + user)
        others = [a for a in r["accused"] if a != user]
        assert not others, f"holder {user}: named innocent recipients {others}"
        assert user in r["accused"], f"failed to name holder {user}"
        out[f"holder {user}"] = (f"named, {len(others)} innocents accused, "
                                 f"score {r['score']:.1f} vs next {r['next_innocent']:.1f}")
    return out


@claim("trace-fails-silent-not-wrong",
       says="past the detector's limit -- a dark, heavily downscaled, very noisy capture "
            "-- recovery degrades to chance, and at chance it names NOBODY rather than "
            "naming an innocent")
def beyond_the_limit_it_accuses_nobody():
    """
    The interesting question about a limit is not where it is but what happens at it. A
    detector that degrades into confident nonsense is worse than one that refuses, because
    the output of this pipeline is an accusation against a named person.

    Two conditions well past the operating envelope, chosen because they were measured to
    break recovery: paper at 170-180 with sensor noise of 20-26 grey levels AND a
    downscale to 70-80%, which leaves under 0.8 px of displacement per gap to measure.
    """
    code = C.Code(ROSTER, M, 1, 4242)
    tmp = tempfile.mkdtemp(prefix="cloister-limit-")
    probe = _trace_once(code, 6.0, 21, tmp, LIGHTINGS[0], seed=99)
    thr = code.calibrate(probe["nobs"], family_wise=1e-3, trials=1500, seed=3)
    out = {}
    for label, light in (("dark + downscaled 70%", (180, 20.0, 20.0, 1.2, 0.70)),
                         ("dark + very noisy", (170, 26.0, 24.0, -1.1, 0.80))):
        r = _trace_once(code, thr, 21, tmp, light, seed=44)
        wrong = [a for a in r["accused"] if a != 21]
        assert not wrong, (
            f"{label}: bit error rate {r['ber']:.0%} and it still named {wrong} -- "
            f"degrading into a false accusation is the one failure mode that matters")
        out[label] = (f"ber {r['ber']:.0%}, "
                      f"{'holder still named' if 21 in r['accused'] else 'nobody named'}, "
                      f"0 innocents accused")
    return out


@regression("trace-redundancy-is-combined-not-overwritten",
            bug="recover() assigned bits[bidx] on every repeat, so the last measurement "
                "of a code position silently overwrote all the earlier ones and the "
                "renderer's redundancy bought nothing. Repeats are now combined as "
                "signed evidence, which weights each measurement by its own margin.",
            found_by="this suite, when sizing the document so that one page carries the "
                     "whole codeword: the redundancy was visible in the layout map and "
                     "absent from the recovered bits")
def repeats_are_combined():
    code = C.Code(ROSTER, M, 1, 4242)
    tmp = tempfile.mkdtemp(prefix="cloister-red2-")
    r = _trace_once(code, 6.0, 21, tmp, LIGHTINGS[5], seed=44)
    assert r["redundancy"] >= 2.0, (
        f"redundancy {r['redundancy']} -- the test is not in the regime it claims")
    assert r["diag"]["combined_margin_px"] > 1.5 * r["diag"]["median_margin_px"], (
        f"combined margin {r['diag']['combined_margin_px']} is not larger than the "
        f"single-measurement margin {r['diag']['median_margin_px']}, so the repeats are "
        f"not being combined")
    assert r["ber"] < 0.02, f"bit error rate {r['ber']:.1%} on a dim photograph"
    return {"redundancy": f"{r['redundancy']}x",
            "single-gap margin": f"{r['diag']['median_margin_px']} px",
            "combined margin": f"{r['diag']['combined_margin_px']} px",
            "bit error rate": f"{r['ber']:.1%}"}


@mutation("trace-redundancy-is-combined-not-overwritten")
def _original_last_write_wins():
    """Recover with the original loop, which overwrites repeats instead of summing."""
    real = DT.recover

    def broken(marked_by_page, ref_pngs, geometry, m, dpi):
        bits, mask, margins = [0] * m, [False] * m, []
        diag = {"lines_used": 0, "lines_unreadable": 0}
        Im = {p: DT.ink(v) for p, v in marked_by_page.items()}
        Ir = {i: DT.ink(p) for i, p in enumerate(ref_pngs)}
        for line in geometry:
            pi = line["page"]
            if pi not in Im or pi not in Ir or not line["bit_indices"]:
                continue
            mc = DT.word_centroids(Im[pi], line, dpi)
            rc = DT.word_centroids(Ir[pi], line, dpi)
            if mc is None or rc is None:
                diag["lines_unreadable"] += 1
                continue
            diag["lines_used"] += 1
            r = np.array(mc) - np.array(rc)
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
                bits[bidx] = 1 if d > 0 else 0        # <-- the bug: overwrites
                mask[bidx] = True
                margins.append(abs(d))
        diag["positions_read"] = int(sum(mask))
        diag["median_margin_px"] = (round(float(np.median(margins)), 3)
                                    if margins else 0.0)
        diag["redundancy"] = 1.0
        diag["combined_margin_px"] = diag["median_margin_px"]
        return bits, mask, diag

    code = C.Code(ROSTER, M, 1, 4242)
    tmp = tempfile.mkdtemp(prefix="cloister-red3-")
    try:
        DT.recover = broken
        r = _trace_once(code, 6.0, 21, tmp, LIGHTINGS[5], seed=44)
    finally:
        DT.recover = real
    assert r["ber"] < 0.02, (
        f"overwriting repeats gives a {r['ber']:.1%} bit error rate on the same "
        f"photograph")


if __name__ == "__main__":
    main(__doc__)
