"""
Generate the demo artefacts the website's adversarial agent runs against.

Everything the browser demo shows is produced here, by the real tool, and committed as
JSON. Nothing on the site is typed in by hand -- including, importantly, the result that
is bad for us: OCR reads the page, and the OCR transcript in this file is real tesseract
output, not a concession written in prose.

    python3 evidence/make_demo.py
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "cloister"))

from cloister import code as codemod          # noqa: E402
from cloister import decoy as decoymod        # noqa: E402
from cloister import detect as detectmod      # noqa: E402
from cloister import render as rendermod      # noqa: E402

# A document with terms that are unambiguously the point of the document: if an attacker
# recovers these, the protection failed. Chosen to be checkable by exact match, so the
# scoring cannot flatter us.
SENSITIVE = [
    "Ashgrove", "Merridew", "4,750,000", "18.5%", "escrow", "indemnify",
    "arbitration", "privileged", "Kestrel Holdings", "2026-11-14",
]

BODY = [
    {"kind": "title", "text": "Settlement Memorandum — Privileged and Confidential"},
    {"kind": "h1", "text": "Ashgrove Industries v. Merridew Kestrel Holdings"},
    {"kind": "p", "text":
        "The parties have agreed in principle to resolve all outstanding claims for a "
        "total consideration of 4,750,000 dollars, of which 18.5% shall be retained in "
        "escrow until the conditions described below have been satisfied in full. This "
        "memorandum is privileged and is not to be circulated outside the working group "
        "before 2026-11-14."},
    {"kind": "p", "text":
        "Each party shall indemnify the other against any claim arising from the escrow "
        "account, and shall submit every remaining dispute to binding arbitration rather "
        "than to a court of first instance. Kestrel Holdings accepts no liability for the "
        "cost of that arbitration, and nothing in this memorandum constitutes an "
        "admission by Ashgrove Industries or by any of its officers."},
    {"kind": "p", "text":
        "The remaining schedules are annexed and form part of this agreement. They "
        "restate the payment timetable, the conditions attaching to release from escrow, "
        "and the notice provisions that apply if either party wishes to withdraw before "
        "the date given above. Counsel should read them together with the covering note."},
]


def run(cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw)


def main():
    tmp = tempfile.mkdtemp(prefix="cloister-demo-")
    m = codemod.code_length(1, 1e-6)
    code = codemod.Code(40, m, 1, 4242)
    row = 7

    protected = os.path.join(HERE, "demo-protected.pdf")
    rep, geom = rendermod.protect(
        BODY, protected, decoymod.Decoy("minutes", "demo-recipient-07"),
        bits=code.word(row))

    # 1. What a text extractor gets. Three independent readers must agree, otherwise the
    #    claim is about one library's quirk rather than about the file.
    txt = os.path.join(tmp, "extract.txt")
    run(["pdftotext", "-layout", protected, txt])
    with open(txt, encoding="utf-8", errors="replace") as fh:
        text_layer = " ".join(fh.read().split())

    from pypdf import PdfReader
    pypdf_text = " ".join(
        " ".join((p.extract_text() or "").split()) for p in PdfReader(protected).pages)
    import pdfplumber
    with pdfplumber.open(protected) as doc:
        plumber_text = " ".join(
            " ".join((p.extract_text() or "").split()) for p in doc.pages)

    # 2. What OCR gets. This is the result that goes against us and it is measured, not
    #    conceded in prose.
    pages = detectmod.render_pdf(protected, 300, os.path.join(tmp, "pg"))
    run(["tesseract", pages[0], os.path.join(tmp, "ocr"), "--psm", "6"])
    with open(os.path.join(tmp, "ocr.txt"), encoding="utf-8", errors="replace") as fh:
        ocr_text = " ".join(fh.read().split())

    def recovered(hay: str) -> list[str]:
        low = hay.lower()
        return [t for t in SENSITIVE if t.lower() in low]

    truth = " ".join(" ".join(b["text"].split()) for b in BODY)
    out = {
        "generated_by": "evidence/make_demo.py",
        "document": {
            "title": "Settlement Memorandum — Privileged and Confidential",
            "words": len(truth.split()),
            "pages": rep["pages"],
            "sensitive_terms": SENSITIVE,
            "true_text": truth,
        },
        "fingerprint": {
            "code_bits": m,
            "recipient_row": row,
            "roster": 40,
            "positions_marked": rep["positions_marked"],
            "redundancy": round(rep["positions_marked"] / m, 2),
            "delta_pt": rep["delta_pt"],
            "delta_px_at_300dpi": round(rep["delta_pt"] * 300 / 72, 2),
        },
        "channels": {
            "text_layer": {
                "label": "Text extraction (pdftotext, pypdf, pdfplumber)",
                "what_the_machine_sees": text_layer,
                "chars": len(text_layer),
                "recovered": recovered(text_layer),
                "agreement": {
                    "pdftotext_chars": len(text_layer),
                    "pypdf_chars": len(pypdf_text),
                    "pdfplumber_chars": len(plumber_text),
                    "all_three_recover_nothing": not (
                        recovered(text_layer) or recovered(pypdf_text)
                        or recovered(plumber_text)),
                },
            },
            "ocr": {
                "label": "OCR of the rendered page (tesseract, 300 dpi)",
                "what_the_machine_sees": ocr_text,
                "chars": len(ocr_text),
                "recovered": recovered(ocr_text),
            },
        },
    }
    out["headline"] = {
        "terms_total": len(SENSITIVE),
        "text_layer_recovered": len(out["channels"]["text_layer"]["recovered"]),
        "ocr_recovered": len(out["channels"]["ocr"]["recovered"]),
    }

    dest = os.path.join(HERE, "demo.json")
    with open(dest, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1, ensure_ascii=False)

    h = out["headline"]
    print(f"  document        {out['document']['words']} words, "
          f"{len(SENSITIVE)} sensitive terms")
    print(f"  text layer      {h['text_layer_recovered']}/{h['terms_total']} recovered "
          f"({out['channels']['text_layer']['chars']} chars of decoy prose)")
    print(f"  OCR             {h['ocr_recovered']}/{h['terms_total']} recovered "
          f"-- the page is readable, and the site says so")
    print(f"  fingerprint     {out['fingerprint']['positions_marked']} positions, "
          f"{out['fingerprint']['redundancy']}x redundancy, "
          f"{out['fingerprint']['delta_px_at_300dpi']} px at 300 dpi")
    print(f"  wrote           {os.path.relpath(dest, ROOT)}")


if __name__ == "__main__":
    main()
