#!/usr/bin/env python3
"""Consolidated measurement run for the CLOISTER whitepaper."""
import json, os, re, subprocess, sys, warnings, zlib, difflib
warnings.filterwarnings("ignore")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import chaff_pdf, decoy

norm = lambda s: re.sub(r"\s+", " ", s).strip().lower()
STOP = set("""the and for that with this from have been will not are was were has had our its
than then they them their there these those such been being upon which while whose would could
should shall must may might into over under about above after before between during without within
also only same each other more most some any all both few many much very when where what who whom
does did done doing because however therefore thus hereby herein said each per via
""".split())
toks = lambda s: [w for w in re.findall(r"[a-z]{4,}", norm(s)) if w not in STOP]


def recall(truth, got):
    tw = set(toks(truth))
    return round(len(tw & set(toks(got))) / max(1, len(tw)), 4)


def compressibility(s):
    b = norm(s).encode()
    return round(len(zlib.compress(b, 9)) / max(1, len(b)), 4)


def extract(pdf):
    out = {}
    out["pdftotext"] = subprocess.run(["pdftotext", "-layout", pdf, "-"],
                                      capture_output=True, text=True).stdout
    from pypdf import PdfReader
    out["pypdf"] = "\n".join(p.extract_text() or "" for p in PdfReader(pdf).pages)
    import pdfplumber
    with pdfplumber.open(pdf) as d:
        out["pdfplumber"] = "\n".join(p.extract_text() or "" for p in d.pages)
    return out


def ocr(pdf, dpi=200):
    subprocess.run(["pdftoppm", "-r", str(dpi), "-png", pdf, "/tmp/ocr"], check=True)
    pages = sorted(f for f in os.listdir("/tmp") if f.startswith("ocr") and f.endswith(".png"))
    txt = "\n".join(subprocess.run(["tesseract", f"/tmp/{p}", "-", "--psm", "6"],
                                   capture_output=True, text=True).stdout for p in pages)
    return txt, [f"/tmp/{p}" for p in pages]


truth = open("out/true_doc.txt").read()
lex = open("out/decoy_doc.txt").read().split()

# --- Variant A: CLOISTER chaff (fluent, topical, per-recipient decoy)
chaff_pdf.build(truth, "out/protected.pdf", "R-0001-adi", lex)
# --- Variant B: control = classic glyph-permutation / stripped-ToUnicode approach,
#     i.e. what prior-art "extraction-hostile PDF" tricks produce: gibberish.
import random
rnd = random.Random(7)
gib = "".join(rnd.choice("qwrtypsdfghjklzxcvbnm") if ch.isalpha() else ch for ch in truth)
open("/tmp/gib.txt", "w").write(gib)
_orig = decoy.generate
decoy.generate = lambda w, rid, extra=(): "".join(
    rnd.choice("qwrtypsdfghjklzxcvbnm") if c.isalpha() else c for c in w)
chaff_pdf.build(truth, "out/control_gibberish.pdf", "R-0001-adi", lex)
decoy.generate = _orig

results = {"variants": {}}
for name, pdf in (("cloister_chaff", "out/protected.pdf"),
                  ("control_gibberish", "out/control_gibberish.pdf")):
    ex = extract(pdf)
    o, pngs = ocr(pdf)
    v = {"paths": {}}
    for k, t in list(ex.items()) + [("ocr_200dpi", o)]:
        v["paths"][k] = {
            "chars_recovered": len(norm(t)),
            "content_word_recall": recall(truth, t),
            "compressibility": compressibility(t),
        }
    v["pdf_bytes"] = os.path.getsize(pdf)
    v["sample_extracted"] = norm(ex["pdftotext"])[:200]
    results["variants"][name] = v

results["reference"] = {
    "true_text_compressibility": compressibility(truth),
    "true_text_chars": len(norm(truth)),
}
from PIL import Image
im = Image.open(pngs[0])
tt = len(norm(truth)) / 4
it = im.width * im.height / 750
results["cost_of_forcing_vision"] = {
    "text_tokens_if_extractable": round(tt),
    "image_tokens_per_page": round(it),
    "multiplier": round(it / tt, 2),
    "page_png_bytes": os.path.getsize(pngs[0]),
}
print(json.dumps(results, indent=2))
