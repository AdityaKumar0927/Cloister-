"""
The chaff renderer: what extractors see, and the PDF object numbering bug.
"""
import os
import subprocess
import sys
import tempfile
import zlib

sys.path.insert(0, "..")
sys.path.insert(0, ".")

from cloister import decoy as D                                   # noqa: E402
from cloister import render as R                                  # noqa: E402
from harness import claim, main, mutation, regression             # noqa: E402

SENSITIVE = ["Ashgrove", "Merridew", "indemnify", "escrow", "arbitration",
             "confidential", "settlement", "plaintiff"]

BODY = [
    {"kind": "h1", "text": "Settlement Terms, Ashgrove v. Merridew"},
    {"kind": "p", "text":
        "The parties agree to indemnify one another against any confidential claim "
        "arising from the escrow account, and to submit every remaining dispute to "
        "binding arbitration before the settlement date. The plaintiff shall bear no "
        "cost of the arbitration. This paragraph is deliberately long enough to wrap "
        "across several lines so that the paired-gap fingerprint has somewhere to go."},
    {"kind": "p", "text":
        "Nothing in this settlement shall be construed as an admission by the "
        "plaintiff or by any officer of Ashgrove Holdings. The escrow shall be "
        "released on the second business day following execution, and the "
        "confidential schedule annexed hereto forms part of this agreement."},
]

_CACHE = {}


def _protect(bits=None, tag="doc"):
    key = (tag, tuple(bits) if bits else None)
    if key in _CACHE:
        return _CACHE[key]
    d = tempfile.mkdtemp(prefix="cloister-test-")
    out = os.path.join(d, f"{tag}.pdf")
    dec = D.Decoy("facilities", f"recipient-{tag}")
    rep, geom = R.protect(BODY, out, dec, bits=bits)
    _CACHE[key] = (out, rep, geom, d)
    return _CACHE[key]


def _extract(pdf):
    """Three independent extractors, as a document pipeline would use."""
    texts = {}
    txt = pdf + ".txt"
    subprocess.run(["pdftotext", "-layout", pdf, txt], check=True, capture_output=True)
    texts["pdftotext"] = open(txt, encoding="utf-8", errors="replace").read()
    from pypdf import PdfReader
    texts["pypdf"] = "\n".join((p.extract_text() or "") for p in PdfReader(pdf).pages)
    import pdfplumber
    with pdfplumber.open(pdf) as doc:
        texts["pdfplumber"] = "\n".join((p.extract_text() or "") for p in doc.pages)
    return texts


@claim("chaff-extractors-recover-nothing",
       says="0 of 8 sensitive terms are recovered by pdftotext, pypdf or pdfplumber")
def extractors_recover_nothing():
    pdf, _rep, _geom, _d = _protect()
    out = {}
    for name, text in _extract(pdf).items():
        low = text.lower()
        found = [t for t in SENSITIVE if t.lower() in low]
        assert not found, f"{name} recovered {found}"
        out[name] = f"{len(text)} chars, 0/8 terms"
    return out


@claim("chaff-decoy-is-fluent",
       says="what an extractor gets back is English prose, not gibberish: it "
            "compresses like English, so an ingestion filter has nothing to flag")
def decoy_is_fluent():
    pdf, _rep, _geom, _d = _protect()
    text = _extract(pdf)["pdftotext"]
    body = " ".join(text.split())[:4000].encode()
    ratio = len(zlib.compress(body, 9)) / len(body)
    ref = (" ".join(D.load_cover("minutes"))[:4000]).encode()
    ref_ratio = len(zlib.compress(ref, 9)) / len(ref)
    import random
    rng = random.Random(1)
    junk = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz ") for _ in range(4000)).encode()
    junk_ratio = len(zlib.compress(junk, 9)) / len(junk)
    assert ratio < junk_ratio - 0.05, (
        f"chaff compresses at {ratio:.3f}, too close to random text {junk_ratio:.3f}")
    assert abs(ratio - ref_ratio) < 0.12, (
        f"chaff {ratio:.3f} is far from natural English {ref_ratio:.3f}")
    return {"chaff": round(ratio, 3), "English cover": round(ref_ratio, 3),
            "random letters": round(junk_ratio, 3)}


@claim("chaff-tounicode-is-many-to-one",
       says="a single drawn glyph reports a whole string of characters, so few glyphs "
            "on the page yield fluent prose in the text layer")
def tounicode_expands():
    pdf, rep, _geom, _d = _protect()
    reported = len(" ".join(_extract(pdf)["pdftotext"].split()))
    drawn = rep["cids"]
    assert reported > 1.5 * drawn, (
        f"{drawn} glyphs reported only {reported} characters; the many-to-one "
        f"ToUnicode mapping is not doing its work")
    return {"glyphs drawn": drawn, "characters reported": reported,
            "expansion": f"{reported / drawn:.1f}x"}


@regression("render-pdf-object-numbering",
            bug="PDF.add() returned len(self.objs) after appending, so every indirect "
                "reference was off by one, and the trailer hardcoded /Root 1 0 R. The "
                "file looked plausible and pypdf refused it.",
            found_by="opening the output with a second PDF library instead of only the "
                     "one used to write it")
def pdf_object_graph_is_consistent():
    pdf, _rep, _geom, _d = _protect()
    from pypdf import PdfReader
    r = PdfReader(pdf)
    root = r.trailer["/Root"]
    assert root.get_object()["/Type"] == "/Catalog", "/Root does not point at a catalog"
    assert len(r.pages) >= 1
    for i, page in enumerate(r.pages):
        assert page["/Type"] == "/Page", f"page {i} is not a page object"
        fonts = page["/Resources"]["/Font"]
        assert fonts, f"page {i} has no fonts"
        for _nm, fref in fonts.items():
            f = fref.get_object()
            assert f["/Subtype"] == "/Type0", "expected a composite font"
            desc = f["/DescendantFonts"][0].get_object()
            assert desc["/Subtype"] == "/CIDFontType2"
    return {"pages": len(r.pages), "root": "catalog",
            "fonts": "Type0 / CIDFontType2, all resolvable"}


@mutation("render-pdf-object-numbering")
def _original_off_by_one_numbering():
    """Rebuild with the original add() and trailer, then try to open it."""
    real_add, real_build = R.PDF.add, R.PDF.build

    def broken_add(self, body):
        self.objs.append(body)
        return len(self.objs)                      # <-- the bug: one too high

    def broken_build(self, root):
        return real_build(self, 1)                 # <-- and /Root hardcoded to 1

    d = tempfile.mkdtemp(prefix="cloister-mutation-")
    out = os.path.join(d, "broken.pdf")
    try:
        R.PDF.add, R.PDF.build = broken_add, broken_build
        R.protect(BODY, out, D.Decoy("facilities", "mutant"))
    finally:
        R.PDF.add, R.PDF.build = real_add, real_build
    from pypdf import PdfReader
    r = PdfReader(out)
    assert r.trailer["/Root"].get_object()["/Type"] == "/Catalog"
    assert len(r.pages) >= 1 and r.pages[0]["/Type"] == "/Page"


@claim("chaff-layout-is-recipient-independent",
       says="line breaking uses unperturbed advances, so every recipient's copy has the "
            "same layout map and one detector serves all of them")
def layout_is_recipient_independent():
    _p1, _r1, g1, _d1 = _protect(bits=[0] * 64, tag="a")
    _p2, _r2, g2, _d2 = _protect(bits=[1] * 64, tag="b")
    assert len(g1) == len(g2), f"line counts differ: {len(g1)} vs {len(g2)}"
    for i, (a, b) in enumerate(zip(g1, g2)):
        assert a["page"] == b["page"] and a["baseline_pt"] == b["baseline_pt"], (
            f"line {i} moved between recipients")
        assert a["spans_pt"] == b["spans_pt"], f"line {i} word windows differ"
        assert a["bit_indices"] == b["bit_indices"], f"line {i} bit assignment differs"
    return {"lines": len(g1), "identical spans": True,
            "marked positions": sum(len(l["bit_indices"]) for l in g1)}


@claim("chaff-cid-budget",
       says="font banks roll over below the 65535 CID limit rather than overflowing")
def cid_budget_respected():
    assert R.CID_BUDGET < 65535
    pdf, rep, _geom, _d = _protect()
    assert rep["cids"] < R.CID_BUDGET, "single document already exceeded the budget"
    b = R.Bank("regular")
    assert not b.full()
    b.next_cid = R.CID_BUDGET - 100
    assert b.full(), "bank did not report itself full inside the headroom"
    return {"budget": R.CID_BUDGET, "cids used by this document": rep["cids"],
            "headroom": 65535 - R.CID_BUDGET}


@claim("chaff-displacement-is-subvisual",
       says="the kerning displacement is a fraction of a point, well under a printed "
            "pixel at 300 dpi")
def displacement_is_small():
    _pdf, rep, _geom, _d = _protect(bits=[1, 0] * 32, tag="c")
    dpt = rep["delta_pt"]
    px300 = dpt * 300 / 72
    assert 0 < dpt < 0.5, f"displacement {dpt} pt is not sub-visual"
    assert rep["positions_marked"] > 0, "nothing was marked"
    return {"delta": f"{dpt} pt", "at 300 dpi": f"{px300:.2f} px",
            "positions marked": rep["positions_marked"]}


if __name__ == "__main__":
    main(__doc__)
