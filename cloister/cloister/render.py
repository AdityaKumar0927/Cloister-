"""
The chaff renderer.

Produces a PDF in which:
  * the glyphs drawn on the page are the true document, and
  * the characters any text extractor reports are fluent cover prose, and
  * the inter-word spacing carries a fingerprint recoverable from an image.

The first two are decoupled because glyph selection travels through the font's
CIDToGIDMap while character reporting travels through the ToUnicode CMap, and nothing
in the PDF format requires them to agree. The third is a sub-perceptual displacement
of inter-word gaps, applied in pairs that sum to a constant so line length is
invariant and displacement cannot accumulate.

CID space is 16 bits and this design consumes roughly one CID per glyph drawn, so
long documents are split across several Type0 font "banks", each with its own CID
space, switched at page boundaries.
"""
from __future__ import annotations
import io
import os
import struct
import zlib
from dataclasses import dataclass, field

from fontTools.ttLib import TTFont

FONT_DIR = "/usr/share/fonts/truetype/dejavu"
FACES = {"regular": os.path.join(FONT_DIR, "DejaVuSerif.ttf"),
         "bold": os.path.join(FONT_DIR, "DejaVuSerif-Bold.ttf")}
CID_BUDGET = 55000          # leave headroom below the 65535 hard limit

STYLES = {
    "title": dict(face="bold", size=15.5, before=0, after=13, lead=1.36),
    "h1":    dict(face="bold", size=12.5, before=15, after=6, lead=1.34),
    "h2":    dict(face="bold", size=11.0, before=12, after=4, lead=1.34),
    "p":     dict(face="regular", size=10.5, before=0, after=9, lead=1.46),
}


# ------------------------------------------------------------------ PDF plumbing
class PDF:
    def __init__(self):
        self.objs = [None]

    def add(self, body):
        self.objs.append(body)
        return len(self.objs) - 1

    def reserve(self):
        self.objs.append(None)
        return len(self.objs) - 1

    def put(self, num, body):
        self.objs[num] = body

    def build(self, root):
        out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
        offs = {}
        for i, body in enumerate(self.objs):
            if i == 0 or body is None:
                continue
            offs[i] = len(out)
            out += f"{i} 0 obj\n".encode()
            out += body if isinstance(body, bytes) else str(body).encode()
            out += b"\nendobj\n"
        xref = len(out)
        n = len(self.objs)
        out += f"xref\n0 {n}\n".encode()
        out += b"0000000000 65535 f \n"
        for i in range(1, n):
            out += (f"{offs.get(i,0):010d} 00000 n \n").encode()
        out += (f"trailer\n<< /Size {n} /Root {root} 0 R >>\n"
                f"startxref\n{xref}\n%%EOF\n").encode()
        return bytes(out)


def stream(extra, data):
    data = zlib.compress(data)
    return (f"<< {extra} /Filter /FlateDecode /Length {len(data)} >>\n"
            "stream\n").encode() + data + b"\nendstream"


# ------------------------------------------------------------------- font banks
class Bank:
    """One Type0 font: a private CID space mapping (glyph, reported string) pairs."""

    def __init__(self, face: str):
        self.face = face
        self.path = FACES[face]
        self.tt = TTFont(self.path, fontNumber=0)
        self.upem = self.tt["head"].unitsPerEm
        self.hmtx = self.tt["hmtx"].metrics
        order = self.tt.getGlyphOrder()
        idx = {g: i for i, g in enumerate(order)}
        self.gid_of = {cp: (idx[g], g) for cp, g in self.tt.getBestCmap().items()}
        self.pairs: dict[tuple[int, str], int] = {}
        self.cid_gid: dict[int, int] = {}
        self.cid_txt: dict[int, str] = {}
        self.cid_w: dict[int, int] = {}
        self.used: set[str] = set()
        self.next_cid = 1

    def full(self, headroom=4000):
        return self.next_cid + headroom > CID_BUDGET

    def cid(self, ch: str, reported: str) -> int:
        cp = ord(ch)
        if cp not in self.gid_of:
            cp = ord("?")
        key = (cp, reported)
        got = self.pairs.get(key)
        if got is not None:
            return got
        gid, gname = self.gid_of[cp]
        c = self.next_cid
        self.next_cid += 1
        self.pairs[key] = c
        self.cid_gid[c] = gid
        self.cid_txt[c] = reported
        self.cid_w[c] = round(self.hmtx[gname][0] * 1000 / self.upem)
        self.used.add(gname)
        return c

    def advance(self, ch: str) -> float:
        cp = ord(ch) if ord(ch) in self.gid_of else ord("?")
        _, gname = self.gid_of[cp]
        return self.hmtx[gname][0] / self.upem

    def width_of(self, cid: int) -> float:
        return self.cid_w[cid] / 1000.0

    def cid2gid(self) -> bytes:
        n = max(self.cid_gid) + 1 if self.cid_gid else 1
        b = bytearray(n * 2)
        for c, g in self.cid_gid.items():
            struct.pack_into(">H", b, c * 2, g)
        return bytes(b)

    def w_array(self) -> str:
        return "[" + " ".join(f"{c} [{self.cid_w[c]}]" for c in sorted(self.cid_w)) + "]"

    def tounicode(self) -> bytes:
        items = sorted(self.cid_txt.items())
        chunks = []
        for i in range(0, len(items), 100):
            grp = items[i:i + 100]
            body = ""
            for c, s in grp:
                s = s or " "
                hexs = "".join(f"{ord(x):04X}" for x in s[:32])
                body += f"<{c:04X}> <{hexs}>\n"
            chunks.append(f"{len(grp)} beginbfchar\n{body}endbfchar\n")
        return ("/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n"
                "/CIDSystemInfo << /Registry (Cloister) /Ordering (Chaff) "
                "/Supplement 0 >> def\n/CMapName /Cloister-Chaff def\n/CMapType 2 def\n"
                "1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n"
                + "".join(chunks) +
                "endcmap\nCMapName currentdict /CMap defineresource pop\nend\nend\n"
                ).encode()

    def subset(self) -> bytes:
        try:
            from fontTools import subset as fsub
            f = TTFont(self.path, fontNumber=0)
            opts = fsub.Options()
            opts.retain_gids = True
            opts.notdef_outline = True
            opts.drop_tables += ["GSUB", "GPOS", "GDEF", "kern", "morx", "FFTM"]
            s = fsub.Subsetter(options=opts)
            s.populate(glyphs=sorted(self.used) or [".notdef"])
            s.subset(f)
            buf = io.BytesIO()
            f.save(buf)
            return buf.getvalue()
        except Exception:
            buf = io.BytesIO()
            self.tt.save(buf)
            return buf.getvalue()


class BankSet:
    def __init__(self):
        self.banks: list[Bank] = []
        self.current: dict[str, Bank] = {}
        self.metrics = {f: Bank(f) for f in FACES}   # metrics-only, never emitted

    def get(self, face: str, roll=False) -> Bank:
        b = self.current.get(face)
        if b is None or roll and b.full():
            b = Bank(face)
            self.banks.append(b)
            self.current[face] = b
        return b

    def roll_if_needed(self):
        for face, b in list(self.current.items()):
            if b.full():
                self.current.pop(face)


# ------------------------------------------------------------------- line model
@dataclass
class Line:
    face: str
    size: float
    words: list = field(default_factory=list)     # list[list[int]] of CIDs
    spans: list = field(default_factory=list)     # unperturbed (x0, x1) in points
    bank: int = 0
    page: int = 0
    baseline: float = 0.0
    bits: list = field(default_factory=list)      # codeword indices consumed


def wrap_words(words: list[str], bank: Bank, size: float, maxw: float):
    """Greedy wrap on unperturbed advances; returns list of word-index groups."""
    sp = bank.advance(" ") * size
    lines, cur, w = [], [], 0.0
    for i, word in enumerate(words):
        ww = sum(bank.advance(c) for c in word) * size
        if cur and w + sp + ww > maxw:
            lines.append(cur)
            cur, w = [i], ww
        else:
            w += ww + (sp if cur else 0.0)
            cur.append(i)
    if cur:
        lines.append(cur)
    return lines


# ---------------------------------------------------------------------- renderer
class Renderer:
    PAGE = (612.0, 792.0)
    MARGIN = 72.0

    def __init__(self, blocks, decoy, bits=None, delta_mille=25, footer=None):
        self.blocks = blocks
        self.decoy = decoy
        self.bits = list(bits) if bits else None
        self.delta = delta_mille
        self.footer = footer
        self.banks = BankSet()
        self.lines: list[Line] = []
        self.pages: list[list[Line]] = []

    # -- pass 1: lay out the true text and attach decoy chunks -----------------
    def layout(self):
        from .decoy import chunk_for_glyphs
        W, H = self.PAGE
        maxw = W - 2 * self.MARGIN
        y = H - self.MARGIN
        page = 0
        bottom = self.MARGIN + 26
        for blk in self.blocks:
            st = STYLES.get(blk["kind"], STYLES["p"])
            size, lead = st["size"], st["size"] * st["lead"]
            self.banks.roll_if_needed()
            bank = self.banks.get(st["face"], roll=True)
            words = blk["text"].split()
            if not words:
                continue
            groups = wrap_words(words, bank, size, maxw)
            y -= st["before"]
            for g in groups:
                if y - lead < bottom:
                    page += 1
                    y = H - self.MARGIN
                    self.banks.roll_if_needed()
                    bank = self.banks.get(st["face"], roll=True)
                y -= lead
                ln = Line(face=st["face"], size=size, page=page, baseline=y,
                          bank=id(bank))
                x = self.MARGIN
                sp = bank.advance(" ") * size
                for k, wi in enumerate(g):
                    word = words[wi]
                    seg = self.decoy.segment(len(word))
                    chunks = chunk_for_glyphs(seg, len(word))
                    cids = [bank.cid(ch, chunks[j]) for j, ch in enumerate(word)]
                    ln.words.append(cids)
                    wpt = sum(bank.width_of(c) for c in cids) * size
                    ln.spans.append((round(x, 3), round(x + wpt, 3)))
                    x += wpt
                    if k < len(g) - 1:
                        ln.words.append([bank.cid(" ", " ")])
                        x += sp
                ln.bank_obj = bank
                self.lines.append(ln)
            y -= st["after"]
        # group into pages
        npages = (self.lines[-1].page + 1) if self.lines else 1
        self.pages = [[l for l in self.lines if l.page == p] for p in range(npages)]
        return self

    # -- pass 2: emit ---------------------------------------------------------
    def _line_tj(self, ln: Line, bit_at: list):
        """TJ array with the fingerprint in paired gaps. words alternate word/space."""
        # toks alternate word, space, word, space, ..., word.
        # gap g is the space at token index 2g+1, and its adjustment is emitted
        # immediately after that token. Pair k uses gaps 2k and 2k+1.
        toks = ln.words
        ngaps = (len(toks) - 1) // 2
        plan = {}
        if self.bits and ngaps >= 2:
            for k in range(ngaps // 2):
                b = self.bits[bit_at[0] % len(self.bits)]
                plan[4 * k + 1] = -self.delta if b else self.delta
                plan[4 * k + 3] = self.delta if b else -self.delta
                ln.bits.append(bit_at[0] % len(self.bits))
                bit_at[0] += 1
        parts = []
        for i, t in enumerate(toks):
            parts.append("<" + "".join(f"{c:04X}" for c in t) + ">")
            if i in plan:
                parts.append(f"{plan[i]:g}")
        return "[" + " ".join(parts) + "] TJ"

    def write(self, path):
        pdf = PDF()
        root = pdf.reserve()
        pagesobj = pdf.reserve()
        # emit every bank actually used
        used = {}
        for ln in self.lines:
            used[id(ln.bank_obj)] = ln.bank_obj
        res = {}
        for i, (bid, bank) in enumerate(used.items()):
            ttf = bank.subset()
            ff = pdf.add(stream(f"/Length1 {len(ttf)}", ttf))
            c2g = pdf.add(stream("", bank.cid2gid()))
            tou = pdf.add(stream("", bank.tounicode()))
            name = "DejaVuSerif" + ("-Bold" if bank.face == "bold" else "")
            fd = pdf.add(
                f"<< /Type /FontDescriptor /FontName /{name} /Flags 4 "
                "/FontBBox [-770 -347 2105 1109] /ItalicAngle 0 /Ascent 928 "
                f"/Descent -236 /CapHeight 700 /StemV 80 /FontFile2 {ff} 0 R >>")
            desc = pdf.add(
                f"<< /Type /Font /Subtype /CIDFontType2 /BaseFont /{name} "
                "/CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) "
                f"/Supplement 0 >> /FontDescriptor {fd} 0 R /DW 600 "
                f"/W {bank.w_array()} /CIDToGIDMap {c2g} 0 R >>")
            fobj = pdf.add(
                f"<< /Type /Font /Subtype /Type0 /BaseFont /{name} "
                f"/Encoding /Identity-H /DescendantFonts [{desc} 0 R] "
                f"/ToUnicode {tou} 0 R >>")
            res[bid] = (f"F{i}", fobj)

        bit_at = [0]
        kids = []
        W, H = self.PAGE
        for pno, pg in enumerate(self.pages):
            cs = [b"BT"]
            cur = None
            for ln in pg:
                nm = res[id(ln.bank_obj)][0]
                key = (nm, ln.size)
                if key != cur:
                    cs.append(f"/{nm} {ln.size:g} Tf".encode())
                    cur = key
                cs.append(f"1 0 0 1 {self.MARGIN:g} {ln.baseline:.2f} Tm".encode())
                cs.append(self._line_tj(ln, bit_at).encode())
            cs.append(b"ET")
            content = pdf.add(stream("", b"\n".join(cs)))
            fonts = " ".join(f"/{n} {o} 0 R" for n, o in res.values())
            kids.append(pdf.add(
                f"<< /Type /Page /Parent {pagesobj} 0 R /MediaBox [0 0 {W:g} {H:g}] "
                f"/Resources << /Font << {fonts} >> >> /Contents {content} 0 R >>"))
        pdf.put(pagesobj, "<< /Type /Pages /Kids ["
                + " ".join(f"{k} 0 R" for k in kids) + f"] /Count {len(kids)} >>")
        pdf.put(root, f"<< /Type /Catalog /Pages {pagesobj} 0 R >>")
        with open(path, "wb") as fh:
            fh.write(pdf.build(root))
        return self.report(path)

    def report(self, path):
        return {
            "path": path,
            "pages": len(self.pages),
            "bytes": os.path.getsize(path),
            "banks": len({id(l.bank_obj) for l in self.lines}),
            "cids": sum(b.next_cid - 1 for b in self.banks.banks),
            "positions_marked": sum(len(l.bits) for l in self.lines),
            "delta_mille": self.delta,
            "delta_pt": round(self.delta / 1000 * STYLES["p"]["size"], 4),
        }

    def geometry(self):
        """The layout map a detector needs. Identical for every recipient, because
        line breaking uses unperturbed advances."""
        return [{"page": l.page, "baseline_pt": round(l.baseline, 3),
                 "size": l.size, "spans_pt": l.spans, "bit_indices": l.bits}
                for l in self.lines if l.spans]


def protect(blocks, out_path, decoy, bits=None, delta_mille=25):
    r = Renderer(blocks, decoy, bits=bits, delta_mille=delta_mille).layout()
    rep = r.write(out_path)
    return rep, r.geometry()
