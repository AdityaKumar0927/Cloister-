#!/usr/bin/env python3
"""Measure what each ingestion path actually recovers from a chaff-rendered PDF."""
import json, re, subprocess, sys, os, difflib

def norm(s):
    return re.sub(r"\s+", " ", s).strip().lower()

def words(s):
    return set(re.findall(r"[a-z]{4,}", norm(s)))

def sim(a, b):
    return difflib.SequenceMatcher(None, norm(a), norm(b)).ratio()

def recall(truth, got):
    tw = words(truth)
    return len(tw & words(got)) / max(1, len(tw))

truth = open("out/true_doc.txt").read()
decoy = open("out/decoy_doc.txt").read()
pdf = "out/protected.pdf"
res = {}

# --- Path 1: poppler pdftotext (what most file-upload pipelines use first)
res["pdftotext"] = subprocess.run(["pdftotext", "-layout", pdf, "-"],
                                  capture_output=True, text=True).stdout

# --- Path 2: pypdf (the default in LangChain/LlamaIndex document loaders)
import warnings; warnings.filterwarnings("ignore")
from pypdf import PdfReader
res["pypdf"] = "\n".join(p.extract_text() or "" for p in PdfReader(pdf).pages)

# --- Path 3: pdfplumber (common in RAG preprocessing)
import pdfplumber
with pdfplumber.open(pdf) as d:
    res["pdfplumber"] = "\n".join(p.extract_text() or "" for p in d.pages)

# --- Path 4: rasterise + OCR (the vision/multimodal fallback)
subprocess.run(["pdftoppm", "-r", "200", "-png", pdf, "out/page"], check=True)
png = sorted(f for f in os.listdir("out") if f.startswith("page") and f.endswith(".png"))
ocr = []
for p in png:
    ocr.append(subprocess.run(["tesseract", f"out/{p}", "-", "--psm", "6"],
                              capture_output=True, text=True).stdout)
res["ocr_200dpi"] = "\n".join(ocr)

rows = []
for k, v in res.items():
    rows.append({
        "path": k,
        "chars": len(norm(v)),
        "sim_to_TRUTH": round(sim(truth, v), 4),
        "sim_to_DECOY": round(sim(decoy, v), 4),
        "keyword_recall_TRUTH": round(recall(truth, v), 4),
        "keyword_recall_DECOY": round(recall(decoy, v), 4),
    })

# cost of the surviving path: text tokens vs image tokens
text_tokens = len(norm(truth)) / 4
img_bytes = sum(os.path.getsize(f"out/{p}") for p in png)
# Anthropic/OpenAI image token approximation: (w*h)/750 per tile-ish
from PIL import Image
im = Image.open(f"out/{png[0]}")
img_tokens = (im.width * im.height) / 750
print(json.dumps({
    "extraction_results": rows,
    "leak_of_true_text": {r["path"]: r["keyword_recall_TRUTH"] for r in rows},
    "cost": {
        "true_text_tokens_if_extractable": round(text_tokens),
        "image_tokens_per_page_if_forced_to_vision": round(img_tokens),
        "cost_multiplier": round(img_tokens / max(1, text_tokens), 2),
        "png_bytes_per_page": img_bytes // len(png),
        "pdf_bytes": os.path.getsize(pdf),
    },
    "sample_pdftotext_first_240": norm(res["pdftotext"])[:240],
    "sample_ocr_first_240": norm(res["ocr_200dpi"])[:240],
}, indent=2))
