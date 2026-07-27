#!/usr/bin/env python3
"""Generate the whitepaper figures as standalone SVG (print/light mode)."""
import json, os

INK, INK2, MUTED = "#0b0b0b", "#52514e", "#898781"
GRID, BASE, SURF = "#e1e0d9", "#c3c2b7", "#fcfcfb"
S1, S2, S3 = "#2a78d6", "#eb6834", "#1baf7a"
CRIT, GOOD = "#d03b3b", "#0ca30c"
FONT = 'system-ui,-apple-system,"Segoe UI",sans-serif'


def head(w, h):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" '
            f'height="{h}" font-family=\'{FONT}\'>'
            f'<rect width="{w}" height="{h}" fill="{SURF}"/>')


def txt(x, y, s, size=12, fill=INK2, anchor="start", weight=400, mono=False):
    extra = ' font-variant-numeric="tabular-nums"' if mono else ""
    return (f'<text x="{x}" y="{y}" font-size="{size}" fill="{fill}" text-anchor="{anchor}" '
            f'font-weight="{weight}"{extra}>{s}</text>')


# ---------------------------------------------------------------- Fig 2: recall
def fig_recall(path):
    rows = [("pdftotext (poppler)", 0.0), ("pypdf", 0.0), ("pdfplumber", 0.0),
            ("rasterise + OCR / vision", 1.0)]
    W, H = 700, 214
    L, T, BW, BH, GAP = 208, 50, 330, 22, 14
    s = [head(W, H)]
    s.append(txt(0, 18, "Confidential content recovered from a CLOISTER-rendered document",
                 13.5, INK, weight=600))
    s.append(txt(0, 35, "share of 24 probed sensitive terms recovered by each ingestion path",
                 10.5, MUTED))
    bottom = T + len(rows) * (BH + GAP) - GAP + 4
    for i in range(0, 6):
        x = L + BW * i / 5
        s.append(f'<line x1="{x}" y1="{T-6}" x2="{x}" y2="{bottom}" stroke="{GRID}" stroke-width="1"/>')
        s.append(txt(x, bottom + 16, f"{i*20}%", 10, MUTED, "middle", mono=True))
    for i, (label, v) in enumerate(rows):
        y = T + i * (BH + GAP)
        s.append(txt(L - 12, y + BH * 0.68, label, 11.5, INK2, "end"))
        if v == 0:
            s.append(f'<line x1="{L}" y1="{y}" x2="{L}" y2="{y+BH}" stroke="{S1}" stroke-width="2.5"/>')
            s.append(txt(L + 9, y + BH * 0.68, "0.0%", 11, S1, weight=700, mono=True))
        else:
            w = BW * v
            s.append(f'<rect x="{L}" y="{y}" width="{w}" height="{BH}" rx="4" fill="{CRIT}"/>')
            s.append(txt(L + w - 9, y + BH * 0.68, "100%", 11, "#ffffff", "end", 700, mono=True))
    s.append(f'<line x1="{L}" y1="{T-6}" x2="{L}" y2="{bottom}" stroke="{BASE}" stroke-width="1"/>')
    s.append("</svg>")
    open(path, "w").write("".join(s))


# --------------------------------------------------- Fig 3: detectability of chaff
def fig_detect(path):
    rows = [("Original English document", 0.4947, MUTED),
            ("CLOISTER semantic chaff", 0.4627, S1),
            ("Classic glyph-permutation", 0.6073, S2)]
    W, H = 700, 210
    L, T, BW, BH, GAP = 220, 56, 300, 24, 20
    xmax = 0.70
    s = [head(W, H)]
    s.append(txt(0, 18, "Can an automated pipeline tell that it was fed a decoy?", 13.5, INK, weight=600))
    s.append(txt(0, 35, "zlib compression ratio of the recovered text", 10.5, MUTED))
    bottom = T + len(rows) * (BH + GAP) - GAP + 6
    bx1, bx2 = L + BW * 0.42 / xmax, L + BW * 0.52 / xmax
    s.append(f'<rect x="{bx1}" y="{T-4}" width="{bx2-bx1}" height="{bottom-T+4}" fill="{S1}" opacity="0.08"/>')
    for i, (label, v, col) in enumerate(rows):
        y = T + i * (BH + GAP)
        w = BW * v / xmax
        s.append(txt(L - 12, y + BH * 0.68, label, 11.5, INK2, "end"))
        s.append(f'<rect x="{L}" y="{y}" width="{w}" height="{BH}" rx="4" fill="{col}"'
                 + (' opacity="0.4"' if i == 0 else "") + '/>')
        s.append(txt(L + w + 9, y + BH * 0.68, f"{v:.3f}", 11.5, INK, weight=700, mono=True))
    s.append(f'<line x1="{L}" y1="{T-4}" x2="{L}" y2="{bottom}" stroke="{BASE}" stroke-width="1"/>')
    s.append(txt((bx1 + bx2) / 2, bottom + 17, "natural-language band", 10, MUTED, "middle"))
    s.append("</svg>")
    open(path, "w").write("".join(s))


# ------------------------------------------------------------- Fig 4: tracing
def fig_trace(path, sweep):
    W, H = 700, 320
    L, R, T, B = 58, 660, 96, 254
    xs = [0.05, 0.1, 0.2, 0.3, 0.5, 1.0]
    series = [(40, S3, "R = 40"), (12, S1, "R = 12"), (1, S2, "R = 1  (no redundancy)")]

    def px(v):
        return L + (R - L) * xs.index(v) / (len(xs) - 1)

    def py(p):
        return B - (B - T) * p

    s = [head(W, H)]
    s.append(txt(0, 18, "Naming the leaker from a partial copy", 13.5, INK, weight=600))
    s.append(txt(0, 35, "P(at least one of 5 colluders identified) - 1,000 recipients - m = 1,703 bits", 10.5, MUTED))
    s.append(txt(0, 50, "5-sigma two-sided accusation - 500 trials per point - majority-vote attack", 10.5, MUTED))
    # legend row
    lx = 0
    for Rv, col, label in series:
        s.append(f'<rect x="{lx}" y="{64}" width="10" height="10" rx="2" fill="{col}"/>')
        s.append(txt(lx + 15, 73, label, 10.5, INK2, weight=600))
        lx += 22 + len(label) * 6.0
    for g in (0, 0.25, 0.5, 0.75, 1.0):
        s.append(f'<line x1="{L}" y1="{py(g)}" x2="{R}" y2="{py(g)}" stroke="{GRID}" stroke-width="1"/>')
        s.append(txt(L - 9, py(g) + 4, f"{int(g*100)}%", 10, MUTED, "end", mono=True))
    for v in xs:
        s.append(txt(px(v), B + 18, f"{v*100:g}%", 10, MUTED, "middle", mono=True))
    s.append(txt((L + R) / 2, B + 38, "fraction of the document that leaked", 11, INK2, "middle"))
    s.append(f'<line x1="{L}" y1="{B}" x2="{R}" y2="{B}" stroke="{BASE}" stroke-width="1"/>')
    for Rv, col, label in series:
        d = {r["survival"]: r["P_majority"] for r in sweep if r["R"] == Rv}
        pts = [(px(v), py(d[v])) for v in xs]
        s.append('<polyline fill="none" stroke="%s" stroke-width="2" stroke-linejoin="round" '
                 'points="%s"/>' % (col, " ".join(f"{x:.1f},{y:.1f}" for x, y in pts)))
        for x, y in pts:
            s.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4.5" fill="{col}" stroke="{SURF}" stroke-width="2"/>')
        # direct label at the left end, where the three curves are well separated
        x0, y0 = pts[0]
        dy = 17 if Rv == 12 else -11
        s.append(txt(x0 + 17, y0 + dy, f"{d[0.05]*100:.0f}%", 10.5, col, weight=700, mono=True))
    s.append("</svg>")
    open(path, "w").write("".join(s))


# -------------------------------------------------------- Fig 1: architecture
def fig_arch(path):
    W, H = 700, 374
    s = [head(W, H)]
    s.append(txt(0, 18, "Where each layer intervenes", 14, INK, weight=600))
    s.append(txt(0, 36, "the document's journey, left to right, and what CLOISTER does at each stage", 11, MUTED))

    def box(x, y, w, h, title, lines, col, fill_op=0.06):
        o = [f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" fill="{col}" opacity="{fill_op}"/>',
             f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" fill="none" stroke="{col}" stroke-width="1.5"/>',
             txt(x + 12, y + 20, title, 11.5, INK, weight=700)]
        for i, ln in enumerate(lines):
            o.append(txt(x + 12, y + 38 + i * 14, ln, 10, INK2))
        return "".join(o)

    def arrow(x1, y1, x2, y2, col=MUTED, dash=False):
        d = ' stroke-dasharray="4 3"' if dash else ""
        return (f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{col}" stroke-width="1.5"'
                f'{d} marker-end="url(#a)"/>')

    s.append(f'<defs><marker id="a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" '
             f'markerHeight="6" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="{MUTED}"/></marker></defs>')

    s.append(box(0, 56, 158, 88, "1 · AT REST",
                 ["Envelope: X25519 +", "ML-KEM-768 hybrid;", "content key bound to a", "posture policy digest"], S1))
    s.append(box(190, 56, 158, 88, "2 · AT OPEN",
                 ["Membrane: keys released", "only into a runtime with", "no egress, no capture,", "no ptrace, no clipboard"], S1))
    s.append(box(380, 56, 158, 88, "3 · IF IT LEAVES",
                 ["Chaff: text layer is a", "fluent per-recipient", "decoy; only the raster", "carries the truth"], S2))
    s.append(box(552, 56, 148, 88, "4 · AFTER THE FACT",
                 ["Trace: Tardos codeword", "in every copy; probe", "suspect models for the", "canary"], S3))
    for x in (166, 356, 542):
        s.append(arrow(x, 100, x + 20, 100))

    s.append(txt(0, 178, "INGESTION PATHS THIS ADDRESSES", 10.5, INK, weight=700))
    paths = [
        ("Drag-and-drop into a consumer chatbot", "blocked at 2, degraded at 3", GOOD),
        ("Browser AI sidebar reading the open tab", "blocked at 2 (no capture, no DOM egress)", GOOD),
        ("Agent / MCP server with filesystem access", "blocked at 1 — envelope never opens for it", GOOD),
        ("Coding assistant indexing a repository", "blocked at 1", GOOD),
        ("OS-level assistant screenshotting the screen", "blocked at 2 via capture exclusion", GOOD),
        ("Enterprise suite auto-indexing the file store", "blocked at 1", GOOD),
        ("Recipient photographs the screen with a phone", "not prevented — traced at 4", CRIT),
        ("Recipient retypes or dictates the content", "not prevented — traced at 4 if verbatim", CRIT),
    ]
    for i, (p, effect, col) in enumerate(paths):
        y = 198 + i * 21
        s.append(f'<rect x="0" y="{y-11}" width="700" height="19" fill="{col}" opacity="0.05"/>')
        s.append(f'<circle cx="7" cy="{y-2}" r="3.5" fill="{col}"/>')
        s.append(txt(20, y + 2, p, 11, INK2))
        s.append(txt(698, y + 2, effect, 10.5, INK if col == GOOD else CRIT, "end",
                     600 if col == CRIT else 400))
    s.append("</svg>")
    open(path, "w").write("".join(s))


if __name__ == "__main__":
    os.makedirs("fig", exist_ok=True)
    sweep = json.load(open("out/sweep.json"))
    fig_arch("fig/arch.svg")
    fig_recall("fig/recall.svg")
    fig_detect("fig/detect.svg")
    fig_trace("fig/trace.svg", sweep)
    print("figures:", os.listdir("fig"))
