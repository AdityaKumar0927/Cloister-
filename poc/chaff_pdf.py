#!/usr/bin/env python3
"""
CLOISTER — Layer D (Degrade) + Layer T (Trace) renderer
=======================================================
Builds a PDF whose *visual* layer is the true document and whose *machine-readable
text layer* is a per-recipient decoy, and which simultaneously carries a fingerprint
in inter-word micro-kerning.

Two independent channels, one artefact:

  ToUnicode channel   -- what a text extractor reports. Carries the decoy, which is
                         itself keyed to the recipient. Dies if the document is
                         rasterised; survives copy-paste and every PDF text library.

  Kerning channel     -- sub-perceptual +/- displacement of each inter-word gap.
                         Carries the Tardos codeword. Survives printing,
                         screenshotting, photography and OCR, because it is a
                         property of the *image*, not of the text layer.

The glyph drawn comes from CIDToGIDMap; the character reported comes from ToUnicode.
Nothing in the PDF format requires them to agree, and no consistency check detects the
divergence without rasterising and running OCR.
"""
import hashlib, io, os, struct, sys, zlib, json
from fontTools.ttLib import TTFont

FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSerif.ttf"


# ----------------------------------------------------------------- PDF plumbing
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

    def build(self, root=1):
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
        out += f"trailer\n<< /Size {n} /Root {root} 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
        return bytes(out)


def stream(dict_extra, data, compress=True):
    if compress:
        data = zlib.compress(data)
        dict_extra = dict_extra + " /Filter /FlateDecode"
    return (f"<< {dict_extra} /Length {len(data)} >>\nstream\n").encode() + data + b"\nendstream"


# ------------------------------------------------------- chaff font construction
class ChaffFont:
    """Allocates one CID per (visible char, reported char) pair."""

    def __init__(self, path):
        self.path = path
        self.tt = TTFont(path, fontNumber=0)
        self.upem = self.tt["head"].unitsPerEm
        cmap = self.tt.getBestCmap()
        order = self.tt.getGlyphOrder()
        idx = {g: i for i, g in enumerate(order)}
        self.hmtx = self.tt["hmtx"].metrics
        self.gid_of = {cp: (idx[g], g) for cp, g in cmap.items()}
        self.pairs, self.cid_gid, self.cid_uni, self.cid_w = {}, {}, {}, {}
        self.used_glyphs = set()
        self.next_cid = 1

    def cid(self, vis_cp, rep_cp):
        key = (vis_cp, rep_cp)
        if key in self.pairs:
            return self.pairs[key]
        if vis_cp not in self.gid_of:
            vis_cp = ord("?")
        gid, gname = self.gid_of[vis_cp]
        c = self.next_cid
        self.next_cid += 1
        self.pairs[key] = c
        self.cid_gid[c] = gid
        self.cid_uni[c] = rep_cp
        self.cid_w[c] = round(self.hmtx[gname][0] * 1000 / self.upem)
        self.used_glyphs.add(gname)
        return c

    def width(self, cid):
        return self.cid_w[cid] / 1000.0

    def cid2gid_stream(self):
        n = max(self.cid_gid) + 1
        b = bytearray(n * 2)
        for c, g in self.cid_gid.items():
            struct.pack_into(">H", b, c * 2, g)
        return bytes(b)

    def w_array(self):
        return "[" + " ".join(f"{c} [{self.cid_w[c]}]" for c in sorted(self.cid_w)) + "]"

    def tounicode(self):
        items = sorted(self.cid_uni.items())
        chunks = []
        for i in range(0, len(items), 100):
            grp = items[i:i + 100]
            body = "".join(f"<{c:04X}> <{u:04X}>\n" for c, u in grp)
            chunks.append(f"{len(grp)} beginbfchar\n{body}endbfchar\n")
        return (
            "/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n"
            "/CIDSystemInfo << /Registry (Cloister) /Ordering (Chaff) /Supplement 0 >> def\n"
            "/CMapName /Cloister-Chaff def\n/CMapType 2 def\n1 begincodespacerange\n"
            "<0000> <FFFF>\nendcodespacerange\n" + "".join(chunks) +
            "endcmap\nCMapName currentdict /CMap defineresource pop\nend\nend\n"
        ).encode()

    def raw(self, subset=True):
        """Subset with retain_gids so the CIDToGIDMap stays valid."""
        if not subset:
            buf = io.BytesIO(); self.tt.save(buf); return buf.getvalue()
        try:
            from fontTools import subset as fsub
            f = TTFont(self.path, fontNumber=0)
            opts = fsub.Options()
            opts.retain_gids = True          # keeps original glyph IDs
            opts.notdef_outline = True
            opts.drop_tables += ["GSUB", "GPOS", "GDEF", "kern", "morx"]
            s = fsub.Subsetter(options=opts)
            s.populate(glyphs=sorted(self.used_glyphs))
            s.subset(f)
            buf = io.BytesIO(); f.save(buf); return buf.getvalue()
        except Exception:
            buf = io.BytesIO(); self.tt.save(buf); return buf.getvalue()


# ------------------------------------------------------------------- typesetting
def layout(pairs, font, size, maxw, cidf):
    """Greedy wrap. Returns lines, each a list of word-CID-lists."""
    space = cidf(" ", " ")
    spw = font.width(space) * size
    lines, cur, curw = [], [], 0.0
    for vw, dw in pairs:
        codes = [cidf(a, b) for a, b in zip(vw, dw)]
        w = sum(font.width(c) for c in codes) * size
        if cur and curw + spw + w > maxw:
            lines.append(cur); cur, curw = [codes], w
        else:
            cur.append(codes); curw += w + (spw if len(cur) else 0)
    if cur:
        lines.append(cur)
    return lines, space


def line_stream(words, space, bits, bit_at, delta_mille):
    """
    Emit one line as a TJ array, encoding the codeword in *paired* inter-word gaps.

    Gaps are taken two at a time. For bit 1 the pair becomes (base+d, base-d); for
    bit 0, (base-d, base+d). The pair sums to 2*base either way, so line length is
    invariant and displacement never accumulates along the line -- the perturbation
    stays strictly local and the right margin does not move. Detection is then a
    local differential comparison, which also cancels global scaling introduced by
    printing, screenshotting or photographing.

    A TJ adjustment of -n moves the following glyph right by n/1000 em, so -d widens
    the gap. At 11 pt, d = 25 is 0.275 pt (about 0.8 px at 200 dpi).
    """
    ngaps = len(words) - 1
    parts, used = [], []
    plan = [0.0] * max(0, ngaps)
    if bits and ngaps >= 2:
        for k in range(ngaps // 2):
            b = bits[bit_at[0] % len(bits)]
            plan[2 * k] = -delta_mille if b else delta_mille
            plan[2 * k + 1] = delta_mille if b else -delta_mille
            used.append({"bit_index": bit_at[0] % len(bits), "bit": int(b),
                         "gap_pair": (2 * k, 2 * k + 1)})
            bit_at[0] += 1
    for i, w in enumerate(words):
        hexs = "".join(f"{c:04X}" for c in w)
        if i < ngaps:
            parts.append(f"<{hexs}{space:04X}>")
            adj = plan[i]
            if adj:
                parts.append(f"{adj:g}")
        else:
            parts.append(f"<{hexs}>")
    return "[" + " ".join(parts) + "] TJ", used


# ------------------------------------------------------------------------ build
def build(true_text, out_path, recipient_id, extra_lex=(), bits=None,
          delta_mille=25, subset=True, decoy_on=True):
    """
    bits        : iterable of 0/1 -- the codeword laid into the kerning channel,
                  repeated cyclically across the document (the redundancy schedule).
    delta_mille : displacement magnitude in 1/1000 em. 0 disables the channel.
    decoy_on    : False renders the true text in the ToUnicode layer too (reference
                  build used by the detector).
    """
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import decoy as decoymod
    font = ChaffFont(FONT)
    size, leading = 11.0, 15.5
    W, H, M = 612, 792, 72
    maxw = W - 2 * M
    bits = list(bits) if bits else None

    def cidf(a, b):
        return font.cid(ord(a), ord(b))

    all_lines = []
    for para in [p.strip() for p in true_text.split("\n") if p.strip()]:
        words = para.split()
        pairs = []
        for i, w in enumerate(words):
            d = decoymod.generate(w, f"{recipient_id}|{i}", extra_lex) if decoy_on else w
            pairs.append((w, d))
        ls, space = layout(pairs, font, size, maxw, cidf)
        all_lines.extend(ls)
        all_lines.append([])

    per_page = int((H - 2 * M) / leading)
    pages, cur = [], []
    for ln in all_lines:
        cur.append(ln)
        if len(cur) >= per_page:
            pages.append(cur); cur = []
    if cur:
        pages.append(cur)

    pdf = PDF()
    root = pdf.reserve(); pagesobj = pdf.reserve(); fontobj = pdf.reserve()
    ttf = font.raw(subset=subset)
    ff = pdf.add(stream(f"/Length1 {len(ttf)}", ttf))
    c2g = pdf.add(stream("", font.cid2gid_stream()))
    tou = pdf.add(stream("", font.tounicode()))
    fd = pdf.add(
        "<< /Type /FontDescriptor /FontName /DejaVuSerif /Flags 4 "
        "/FontBBox [-770 -347 2105 1109] /ItalicAngle 0 /Ascent 928 /Descent -236 "
        f"/CapHeight 700 /StemV 80 /FontFile2 {ff} 0 R >>")
    desc = pdf.add(
        "<< /Type /Font /Subtype /CIDFontType2 /BaseFont /DejaVuSerif "
        "/CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> "
        f"/FontDescriptor {fd} 0 R /DW 600 /W {font.w_array()} /CIDToGIDMap {c2g} 0 R >>")
    pdf.put(fontobj,
        "<< /Type /Font /Subtype /Type0 /BaseFont /DejaVuSerif /Encoding /Identity-H "
        f"/DescendantFonts [{desc} 0 R] /ToUnicode {tou} 0 R >>")

    bit_at = [0]
    placed = []
    lines_meta = []
    kids = []
    for pi, pg in enumerate(pages):
        cs = [b"BT /F1 %.1f Tf %.1f TL 1 0 0 1 %.1f %.1f Tm" % (size, leading, M, H - M)]
        ybase = float(H - M)
        for ln in pg:
            if ln:
                txt, used = line_stream(ln, font.cid(32, 32), bits, bit_at, delta_mille)
                placed.extend(used)
                # unperturbed word x-intervals in PDF points: the detector recomputes
                # these from the master and integrates ink over each window, so it
                # never has to segment words out of the image.
                spans, x = [], float(M)
                spw = font.width(font.cid(32, 32)) * size
                for wi, wcodes in enumerate(ln):
                    wpt = sum(font.width(c) for c in wcodes) * size
                    spans.append((round(x, 3), round(x + wpt, 3)))
                    x += wpt + spw
                lines_meta.append({"page": pi, "nwords": len(ln),
                                   "bit_indices": [u["bit_index"] for u in used],
                                   "bit_values": [u["bit"] for u in used],
                                   "y_baseline_pt": round(ybase, 3),
                                   "spans_pt": spans})
                cs.append(txt.encode())
            ybase -= leading
            cs.append(b"T*")
        cs.append(b"ET")
        content = pdf.add(stream("", b"\n".join(cs)))
        kids.append(pdf.add(
            f"<< /Type /Page /Parent {pagesobj} 0 R /MediaBox [0 0 {W} {H}] "
            f"/Resources << /Font << /F1 {fontobj} 0 R >> >> /Contents {content} 0 R >>"))
    pdf.put(pagesobj, "<< /Type /Pages /Kids [" + " ".join(f"{k} 0 R" for k in kids) +
            f"] /Count {len(kids)} >>")
    pdf.put(root, f"<< /Type /Catalog /Pages {pagesobj} 0 R >>")
    with open(out_path, "wb") as f:
        f.write(pdf.build(root))
    return {"pages": len(pages), "cids": font.next_cid - 1,
            "bytes": os.path.getsize(out_path), "gaps_marked": len(placed),
            "delta_mille": delta_mille, "font_size": size,
            "delta_pt": round(delta_mille / 1000 * size, 4),
            "page_pt": (W, H), "leading": leading, "margin": M,
            "space_pt": None, "lines": lines_meta}


if __name__ == "__main__":
    true_text = open(sys.argv[1]).read()
    extra = open(sys.argv[2]).read().split() if sys.argv[2] != "-" else ()
    rid = sys.argv[4] if len(sys.argv) > 4 else "R-0001"
    print(json.dumps(build(true_text, sys.argv[3], rid, extra)))
