"""Read a real document into blocks the renderer can lay out."""
from __future__ import annotations
import os
import re
import subprocess


def _md_blocks(text: str) -> list[dict]:
    blocks, buf = [], []

    def flush():
        if buf:
            blocks.append({"kind": "p", "text": " ".join(buf)})
            buf.clear()

    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            flush()
            continue
        m = re.match(r"^(#{1,3})\s+(.*)$", line)
        if m:
            flush()
            kind = {1: "title", 2: "h1", 3: "h2"}[len(m.group(1))]
            blocks.append({"kind": kind, "text": m.group(2).strip()})
            continue
        if re.match(r"^[-*+]\s+", line):
            flush()
            blocks.append({"kind": "p", "text": "— " + re.sub(r"^[-*+]\s+", "", line)})
            continue
        # an ALL-CAPS short line reads as a heading in legal and academic documents
        stripped = line.strip()
        if (len(stripped) < 90 and stripped.upper() == stripped
                and re.search(r"[A-Z]{4}", stripped)):
            flush()
            blocks.append({"kind": "h1", "text": stripped})
            continue
        buf.append(stripped)
    flush()
    return blocks


def _docx_blocks(path: str) -> list[dict]:
    import docx
    d = docx.Document(path)
    out = []
    for p in d.paragraphs:
        t = p.text.strip()
        if not t:
            continue
        style = (p.style.name or "").lower()
        if "title" in style:
            kind = "title"
        elif "heading 1" in style:
            kind = "h1"
        elif "heading" in style:
            kind = "h2"
        else:
            kind = "p"
        out.append({"kind": kind, "text": t})
    return out


def _pdf_blocks(path: str) -> list[dict]:
    txt = subprocess.run(["pdftotext", "-layout", path, "-"],
                         capture_output=True, text=True).stdout
    # rejoin hard-wrapped lines into paragraphs
    paras, buf = [], []
    for line in txt.splitlines():
        s = line.strip()
        if not s:
            if buf:
                paras.append(" ".join(buf)); buf = []
            continue
        buf.append(s)
    if buf:
        paras.append(" ".join(buf))
    return _md_blocks("\n\n".join(paras))


def read(path: str) -> list[dict]:
    ext = os.path.splitext(path)[1].lower()
    if ext == ".docx":
        blocks = _docx_blocks(path)
    elif ext == ".pdf":
        blocks = _pdf_blocks(path)
    else:
        with open(path, encoding="utf-8", errors="replace") as fh:
            blocks = _md_blocks(fh.read())
    if not blocks:
        raise ValueError(f"no text found in {path}")
    return blocks


def stats(blocks) -> dict:
    words = sum(len(b["text"].split()) for b in blocks)
    chars = sum(len(b["text"]) for b in blocks)
    return {"blocks": len(blocks), "words": words, "chars": chars}
