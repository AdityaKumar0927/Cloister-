"""cloister — command line interface for the format-only posture."""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
import os
import re
import subprocess
import sys
import warnings

warnings.filterwarnings("ignore")

from . import code as codemod
from . import decoy as decoymod
from . import detect as detectmod
from . import ingest as ingestmod
from . import render as rendermod

MANIFEST = "manifest.json"
REFERENCE = "_reference.pdf"


# ------------------------------------------------------------------- helpers
def read_roster(path: str | None) -> list[str]:
    if not path:
        return ["single-copy"]
    names = []
    with open(path, newline="", encoding="utf-8") as fh:
        sniff = fh.read(2048)
        fh.seek(0)
        if "," in sniff or "\t" in sniff:
            for row in csv.reader(fh):
                if row and row[0].strip():
                    names.append(row[0].strip())
        else:
            names = [l.strip() for l in fh if l.strip()]
    if names and names[0].lower() in ("name", "recipient", "recipients"):
        names = names[1:]
    if not names:
        raise ValueError(f"no recipients found in {path}")
    return names


def slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:48] or "copy"


def sha(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def content_words(s: str) -> set:
    STOP = set("the and for that with this from have been will not are was were has "
               "had our its than then they them their there these those such being "
               "upon which while whose would could should shall must may might into "
               "over under about above after before between during without within "
               "also only same each other more most some any all both few many much "
               "very when where what who whom does did done doing because however "
               "therefore thus said per via".split())
    return {w for w in re.findall(r"[a-z]{4,}", s.lower()) if w not in STOP}


# ------------------------------------------------------------------- protect
def cmd_protect(a):
    blocks = ingestmod.read(a.input)
    st = ingestmod.stats(blocks)
    names = read_roster(a.roster)
    os.makedirs(a.out, exist_ok=True)

    m = codemod.code_length(a.collusion, a.eps1)

    # One reference render: same geometry and same codeword-position assignment as
    # every recipient copy, but zero displacement. The detector subtracts it to cancel
    # per-glyph side bearings, so it must exist and must stay private.
    ref_decoy = decoymod.Decoy(a.cover, "__reference__")
    ref_rep, geometry = rendermod.protect(
        blocks, os.path.join(a.out, REFERENCE), ref_decoy,
        bits=[0] * m, delta_mille=0)
    positions_per_doc = sum(len(l["bit_indices"]) for l in geometry)
    if positions_per_doc == 0:
        raise SystemExit("document is too short to carry a fingerprint "
                         "(needs at least two inter-word gaps on a line)")
    print(f"  document      {st['words']:,} words · {ref_rep['pages']} page(s) · "
          f"{st['blocks']} blocks")
    print(f"  recipients    {len(names)}")
    print(f"  code          m = {m} bits (collusion {a.collusion}, eps1 {a.eps1:g})")
    print(f"  capacity      {positions_per_doc} positions per copy "
          f"({positions_per_doc / m * 100:.0f}% of the codeword)")
    print(f"  screening     {a.candidates} candidate codes …", flush=True)
    code, chosen, tried = codemod.screen(
        max(len(names), 2), m, a.collusion, positions_per_doc,
        candidates=a.candidates, family_wise=a.family_wise)
    print(f"  chosen        seed {chosen['seed']} · threshold "
          f"{chosen['threshold']}σ · detection {chosen['detection']:.3f} · "
          f"false accusations {chosen['fp_per_trial']:.5f}/trial")

    copies = []
    for i, name in enumerate(names):
        dec = decoymod.Decoy(a.cover, f"{name}|{i}")
        path = os.path.join(a.out, f"{i:04d}-{slug(name)}.pdf")
        rep, geo = rendermod.protect(blocks, path, dec, bits=code.word(i),
                                     delta_mille=a.delta)
        copies.append({"row": i, "recipient": name,
                       "file": os.path.basename(path), "sha256": sha(path),
                       "pages": rep["pages"], "bytes": rep["bytes"]})
        if i == 0:
            first = rep
        if (i + 1) % 25 == 0 or i + 1 == len(names):
            print(f"  rendered      {i + 1}/{len(names)}", flush=True)

    manifest = {
        "version": 1,
        "source": {"path": os.path.abspath(a.input), "sha256": sha(a.input), **st},
        "cover": a.cover,
        "render": {"delta_mille": a.delta, "delta_pt": first["delta_pt"],
                   "pages": first["pages"], "banks": first["banks"],
                   "cids": first["cids"]},
        "code": {"n_users": max(len(names), 2), "m": m, "collusion": a.collusion,
                 "eps1": a.eps1, "seed": chosen["seed"],
                 "threshold_sigma": chosen["threshold"],
                 "family_wise": a.family_wise,
                 "expected_detection": chosen["detection"],
                 "expected_false_accusations": chosen["fp_per_trial"],
                 "candidates_tried": tried},
        "capacity": {"positions_per_copy": positions_per_doc,
                     "coverage_of_codeword": round(positions_per_doc / m, 4)},
        "reference": REFERENCE,
        "geometry": geometry,
        "copies": copies,
    }
    with open(os.path.join(a.out, MANIFEST), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=1)
    print(f"\n  wrote         {len(copies)} protected copies + {MANIFEST} to {a.out}/")
    print(f"  keep {MANIFEST} and {REFERENCE} private — they are what makes tracing "
          f"possible")
    return 0


# ------------------------------------------------------------------- verify
def cmd_verify(a):
    man = json.load(open(os.path.join(a.dir, MANIFEST), encoding="utf-8"))
    if not os.path.exists(man["source"]["path"]):
        raise SystemExit(f"source document not found: {man['source']['path']}")
    truth = " ".join(b["text"] for b in ingestmod.read(man["source"]["path"]))

    # Terms distinctive to the source: content words that do NOT occur anywhere in the
    # cover corpus. Generic vocabulary shared by any two English documents ("office",
    # "records", "estimate") is not a leak, and counting it overstates exposure --
    # these are the words whose appearance would actually tell a reader something.
    cover_vocab = set()
    for sent in decoymod.load_cover(man["cover"]):
        cover_vocab |= content_words(sent)
    tw = content_words(truth)
    distinctive = tw - cover_vocab
    digits = set(re.findall(r"\d[\d,./-]*", truth))

    rows = []
    targets = [c for c in man["copies"] if not a.only or a.only in c["file"]]
    for c in targets[: a.limit]:
        path = os.path.join(a.dir, c["file"])
        got = subprocess.run(["pdftotext", "-layout", path, "-"],
                             capture_output=True, text=True).stdout
        gw = content_words(got)
        hits = sorted(distinctive & gw)
        dhits = sorted(digits & set(re.findall(r"\d[\d,./-]*", got)))
        rows.append((c["recipient"], len(got.split()),
                     len(tw & gw) / max(1, len(tw)),
                     len(hits) / max(1, len(distinctive)), hits, dhits))
    print(f"  source has {len(tw)} content words, of which {len(distinctive)} are "
          f"distinctive (absent from the '{man['cover']}' cover)")
    print(f"  and {len(digits)} distinct numeric strings\n")
    print(f"  {'recipient':<26}{'reported':>10}{'generic overlap':>17}"
          f"{'DISTINCTIVE LEAKED':>21}{'numbers':>9}")
    for name, nw, gen, dist, hits, dhits in rows:
        print(f"  {name[:25]:<26}{nw:>10,}{gen:>17.1%}{dist:>21.1%}{len(dhits):>9}")
    worst = max(r[3] for r in rows)
    wd = max(len(r[5]) for r in rows)
    print(f"\n  worst case across {len(rows)} copies: {worst:.1%} of distinctive terms, "
          f"{wd} numeric strings")
    leaked = sorted({h for r in rows for h in r[4]})
    if leaked:
        print(f"  leaked terms: {', '.join(leaked[:12])}")
    else:
        print("  no distinctive term from the source appears in any copy's text layer")
    return 0


# ------------------------------------------------------------------- trace
def cmd_trace(a):
    d = os.path.dirname(os.path.abspath(a.manifest))
    man = json.load(open(a.manifest, encoding="utf-8"))
    cfg = man["code"]
    code = codemod.Code(cfg["n_users"], cfg["m"], cfg["collusion"], cfg["seed"])
    ref = os.path.join(d, man["reference"])
    tmp = a.workdir or "/tmp/cloister-trace"
    os.makedirs(tmp, exist_ok=True)

    ref_pages = detectmod.render_pdf(ref, a.dpi, os.path.join(tmp, "ref"))
    leaked = detectmod.pages_of(a.evidence, a.dpi, os.path.join(tmp, "lk"))
    print(f"  evidence      {len(leaked)} page image(s) · reference {len(ref_pages)} page(s)")

    from PIL import Image
    by_page = {}
    for i, p in enumerate(leaked):
        pi, conf = (i, None) if a.page is None else (a.page - 1, None)
        if a.page is None and len(ref_pages) > 1:
            pi, conf = detectmod.identify_page(p, ref_pages)
        pi = max(0, min(pi, len(ref_pages) - 1))
        im = Image.open(p)
        if a.normalise:
            im = detectmod.normalise(im, ref_pages[pi])
        q = os.path.join(tmp, f"norm{i}.png")
        im.save(q)
        by_page[pi] = q
        note = f" (profile match {conf})" if conf is not None else ""
        print(f"  page {i + 1} of evidence → master page {pi + 1}{note}")

    bits, mask, diag = detectmod.recover(by_page, ref_pages,
                                         man["geometry"], cfg["m"], a.dpi)
    print(f"  recovered     {diag['positions_read']} of {cfg['m']} codeword positions"
          f" · {diag['lines_used']} lines read, {diag['lines_unreadable']} unreadable")
    print(f"  measurement   {diag['redundancy']}x redundancy"
          f" · median gap margin {diag['median_margin_px']} px"
          f" · combined {diag['combined_margin_px']} px")
    if (diag["median_margin_px"] > 3.0
            and diag["positions_read"] > 0):
        # A margin far larger than the embedded displacement is measurement error being
        # read as signal, usually a misregistered page. Say so rather than accusing.
        print("  WARNING       gap margins are much larger than the embedded "
              "displacement;\n                this evidence is probably misregistered "
              "and the result is unreliable")
    if diag["positions_read"] == 0:
        print("\n  no fingerprint recoverable from this evidence")
        return 2

    thr = a.threshold if a.threshold is not None else cfg["threshold_sigma"]
    accused, S, nobs = code.accuse(bits, mask, thr)
    byrow = {c["row"]: c["recipient"] for c in man["copies"]}
    import math
    print(f"  threshold     {thr}σ → {thr * math.sqrt(nobs):.1f} on {nobs} positions")
    if not accused:
        top = sorted(range(cfg["n_users"]), key=lambda i: -abs(S[i]))[:3]
        print("\n  NO ACCUSATION — no score crossed the calibrated threshold.")
        print("  closest candidates (not an accusation):")
        for i in top:
            print(f"    {byrow.get(i, f'row {i}'):<30} score {abs(S[i]):.1f}")
        return 1
    print(f"\n  TRACED to {len(accused)} recipient(s):")
    for i in accused:
        print(f"    {byrow.get(i, f'row {i}'):<30} score {abs(S[i]):.1f}")
    others = [abs(S[i]) for i in range(cfg["n_users"]) if i not in accused]
    if others:
        print(f"\n  highest non-accused score: {max(others):.1f} "
              f"(margin {abs(S[accused[0]]) - max(others):.1f})")
    return 0


# ------------------------------------------------------------------- accessible
def cmd_accessible(a):
    """Emit a plain true-text PDF for assistive technology (see whitepaper §10.3)."""
    man = json.load(open(os.path.join(a.dir, MANIFEST), encoding="utf-8"))
    blocks = ingestmod.read(man["source"]["path"])

    class Plain:
        def segment(self, n):
            return None
    out = os.path.join(a.dir, "_accessible.pdf")
    # a decoy that reports the true text is just the identity mapping
    class Identity:
        def segment(self, n):
            return "\x00" * n
    r = rendermod.Renderer(blocks, Identity(), bits=None, delta_mille=0)
    # patch: report each glyph as itself
    orig = rendermod.Bank.cid
    def cid_self(self, ch, reported):
        return orig(self, ch, ch)
    rendermod.Bank.cid = cid_self
    try:
        r.layout().write(out)
    finally:
        rendermod.Bank.cid = orig
    got = subprocess.run(["pdftotext", out, "-"], capture_output=True, text=True).stdout
    print(f"  wrote {out}")
    print(f"  extractable text: {len(got.split()):,} words (true content, no chaff)")
    print("  release this only to an attested assistive-technology client, or on "
          "request under the format-only posture")
    return 0


# ---------------------------------------------------------- envelope / membrane
def cmd_keygen(a):
    from cloister import envelope as E
    from cryptography.hazmat.primitives.asymmetric import ed25519
    dev = E.DeviceIdentity()
    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, "device.pub"), "wb") as fh:
        fh.write(dev.export_public())
    import pickle
    with open(os.path.join(a.out, "device.PRIVATE"), "wb") as fh:
        fh.write(pickle.dumps({"x": dev.x_sk.private_bytes_raw(),
                               "k_ek": dev.k_ek, "k_dk": dev.k_dk}))
    sk = ed25519.Ed25519PrivateKey.generate()
    with open(os.path.join(a.out, "signer.PRIVATE"), "wb") as fh:
        fh.write(sk.private_bytes_raw())
    with open(os.path.join(a.out, "signer.pub"), "wb") as fh:
        fh.write(sk.public_key().public_bytes_raw())
    print(f"  device public key   {len(dev.export_public())} bytes "
          f"(X25519 32 + ML-KEM-768 1184)")
    print(f"  wrote device.pub, signer.pub and two PRIVATE files to {a.out}/")
    print("  in deployment the device private keys are non-exportable and sealed to the")
    print("  platform root of trust; here they are ordinary files, which is the one part")
    print("  this tool cannot demonstrate on its own")
    return 0


def _load_keys(d):
    import pickle
    from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
    from cloister import envelope as E
    raw = pickle.loads(open(os.path.join(d, "device.PRIVATE"), "rb").read())
    dev = E.DeviceIdentity.__new__(E.DeviceIdentity)
    dev.x_sk = x25519.X25519PrivateKey.from_private_bytes(raw["x"])
    dev.k_ek, dev.k_dk = raw["k_ek"], raw["k_dk"]
    sk = ed25519.Ed25519PrivateKey.from_private_bytes(
        open(os.path.join(d, "signer.PRIVATE"), "rb").read())
    return dev, sk


def cmd_seal(a):
    import cbor2
    from cloister import envelope as E
    dev, sk = _load_keys(a.keys)
    pol = E.make_policy(a.matter, lease_seconds=a.lease)
    if a.relax:
        for k in a.relax:
            if k not in pol["require"]:
                raise SystemExit(f"unknown posture predicate {k!r}; "
                                 f"choose from {', '.join(E.POSTURE)}")
            pol["require"].pop(k)
    data = open(a.input, "rb").read()
    env = E.seal(data, dev.public(), pol, sk)
    open(a.out, "wb").write(env)
    print(f"  sealed {a.input} ({len(data):,} B) -> {a.out} ({len(env):,} B)")
    print(f"  overhead        {len(env) - len(data):,} bytes, constant in document size")
    print(f"  suite           {E.SUITE}")
    print(f"  policy requires {', '.join(sorted(pol['require'])) or '(nothing)'}")
    print(f"  lease           {pol['lease_seconds']} s")
    print("  the policy digest is inside the key derivation: editing it destroys the key")
    return 0


def cmd_open(a):
    from cloister import envelope as E
    dev, sk = _load_keys(a.keys)
    log = E.TransparencyLog(os.path.join(a.keys, "leases.log"))
    prove = E.strict_posture({k: True for k in E.POSTURE}) if a.assume_posture \
        else E.live_posture()
    import cbor2
    env = open(a.envelope, "rb").read()
    policy = cbor2.loads(cbor2.loads(env)["hdr"])["policy"]
    try:
        lease = E.Lease.issue(policy, log=log)
        pt = E.unseal(env, dev, sk.public_key(), prove, lease=lease)
    except E.PostureViolation as e:
        print(f"  DENIED before any key was derived: {e}")
        print("  the runtime does not satisfy the policy. Run this inside the membrane")
        print("  (cloister membrane -- ...) or pass --assume-posture to bypass the gate")
        print("  for testing, which is exactly what a real deployment must not allow.")
        return 3
    out = a.out or (a.envelope + ".opened")
    open(out, "wb").write(pt)
    print(f"  opened -> {out} ({len(pt):,} B)")
    print(f"  lease           {lease.remaining():.0f} s remaining")
    print(f"  transparency log head  {log.head[:32]}…  ({len(log.entries)} entries, "
          f"chain {'verifies' if log.verify() else 'BROKEN'})")
    return 0


def cmd_membrane(a):
    from cloister import membrane as M
    ok, why = M.supported()
    if not ok:
        raise SystemExit(why)
    if not a.argv:
        rep = M.enter()
        obs = M.observe()
        print(f"  entered the membrane: {rep}")
        for k, v in obs.items():
            print(f"    {k:<20} {v}")
        return 0
    print(f"  launching {' '.join(a.argv)} inside the membrane "
          f"({len(M.DENY)} syscalls denied, filter inherited across execve)")
    return M.run_confined(list(a.argv))


# --------------------------------------------------------------- authorship (A)
def _profiles():
    import random
    from cloister import authorship as A

    def honest(rng, target):
        t, now, written = A.EditTrail(), 0, 0
        while written < target:
            for _ in range(rng.randint(4, 26)):
                n = rng.randint(3, 14); now += rng.randint(110, 800)
                t.add(now, "ins", n); written += n
            if rng.random() < 0.45:
                d = rng.randint(5, 90); now += rng.randint(300, 2500)
                t.add(now, "del", d); written -= min(d, written)
            if rng.random() < 0.3:
                now += rng.randint(45_000, 480_000)
        return t

    def pasted(rng, target):
        t, now = A.EditTrail(), 1000
        t.add(now, "paste", target, src="clipboard")
        for _ in range(rng.randint(8, 25)):
            now += rng.randint(1500, 9000)
            t.add(now, "ins" if rng.random() < 0.6 else "del", rng.randint(2, 25))
        return t

    def chunked(rng, target):
        t, now = A.EditTrail(), 500
        for _ in range(12):
            now += rng.randint(4000, 30_000)
            t.add(now, "paste", target // 12, src="clipboard")
        return t

    return {"honest": honest, "pasted": pasted, "chunked": chunked}


def cmd_trail(a):
    """Stand in for the editor plug-in: synthesise an edit trail for demonstration."""
    import random
    fn = _profiles()[a.profile]
    t = fn(random.Random(a.seed), a.chars)
    with open(a.out, "w", encoding="utf-8") as fh:
        fh.write(t.to_json())
    st = t.stats()
    print(f"  wrote {a.out}  profile={a.profile}  events={st['event_count']}")
    print(f"  max insertion {st['max_insertion']} ch · unattested paste "
          f"{st['unattested_paste_total']} ch · elapsed {st['elapsed_seconds']//60} min "
          f"· revised {st['revision_chars']} ch")
    print("  (in deployment this file is produced by an attested editor, not by this "
          "command)")
    return 0


def cmd_attest(a):
    from cloister import authorship as A
    trail = A.EditTrail.from_json(open(a.trail, encoding="utf-8").read())
    editor = A.Editor()
    att, openings = editor.attest(trail, A.bind_submission(a.submission))
    os.makedirs(a.out, exist_ok=True)
    json.dump(att, open(os.path.join(a.out, "attestation.json"), "w"), indent=1)
    json.dump(openings, open(os.path.join(a.out, "openings.PRIVATE.json"), "w"), indent=1)
    with open(os.path.join(a.out, "editor.pub"), "w") as fh:
        fh.write(editor.public_bytes().hex())
    print(f"  attested {a.submission}")
    print(f"  trail root      {att['body']['trail_root'][:32]}…")
    print(f"  submission      {att['body']['submission_sha256'][:32]}…")
    print(f"  editor pubkey   {editor.public_bytes().hex()[:32]}…")
    print(f"  wrote attestation.json, editor.pub and openings.PRIVATE.json to {a.out}/")
    print("  openings.PRIVATE.json stays with the author — it is the witness for the "
          "proofs and must never be handed over")
    return 0


def _parse_policy(items, base):
    from cloister import authorship as A
    pol = dict(base)
    for it in items or []:
        k, _, v = it.partition("=")
        if not v:
            raise SystemExit(f"policy must be name=value, got {it!r}")
        pol[k.strip()] = int(v)
    return pol


def cmd_credential(a):
    from cloister import authorship as A
    att = json.load(open(os.path.join(a.dir, "attestation.json"), encoding="utf-8"))
    openings = json.load(open(os.path.join(a.dir, "openings.PRIVATE.json"),
                              encoding="utf-8"))
    base = A.ELAPSED_POLICY if a.with_time_floor else A.DEFAULT_POLICY
    pol = _parse_policy(a.policy, base)
    cred = A.build_credential(att, openings, pol)
    out = a.out or os.path.join(a.dir, "credential.json")
    json.dump(cred, open(out, "w"), separators=(",", ":"))
    print(f"  policy: {pol}")
    for k in pol:
        state = "proved" if k in cred["proofs"] else \
            f"NOT PROVED — {cred['unproven'].get(k, 'unknown')}"
        print(f"    {k:<34} {state}")
    print(f"  wrote {out} ({os.path.getsize(out)/1024:.0f} KB)")
    print("  the credential contains commitments and proofs only: no keystrokes, "
          "no timings, no text")
    return 0


def cmd_check(a):
    from cloister import authorship as A
    cred = json.load(open(a.credential, encoding="utf-8"))
    trusted = None
    if a.trusted:
        trusted = {open(a.trusted).read().strip() if os.path.exists(a.trusted)
                   else a.trusted.strip()}
    pol = _parse_policy(a.policy, cred["policy"])
    v = A.check_credential(cred, pol, trusted)
    print(f"  editor            {v['editor']}")
    print(f"  attestation       {'VALID' if v['attestation_valid'] else 'INVALID'}"
          f"{'' if trusted else '  (no trusted key pinned — supply --trusted)'}")
    print(f"  submission hash   {v['submission_sha256']}")
    print(f"  trail root        {v['trail_root'][:48]}…")
    print("  predicates:")
    for k, ok in v["predicates"].items():
        note = v["unproven"].get(k, "")
        print(f"    {'MET   ' if ok else 'NOT MET'} {k:<34} {note}")
    print()
    if v["all_predicates_met"]:
        print("  VERDICT: the author offered a complete authorship credential.")
        print("  This attests a writing process. It is not a statement about whether")
        print("  any text was machine-generated — see LIMITS in authorship.py.")
    else:
        print("  VERDICT: credential incomplete. This is NOT evidence of misconduct;")
        print("  it means the stated predicates were not established. Absence of a")
        print("  credential is absence of evidence, not evidence of absence.")
    return 0 if v["all_predicates_met"] else 1


# ------------------------------------------------------------------- main
def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="cloister",
        description="Protect documents against machine ingestion, and trace leaks.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("protect", help="render per-recipient protected copies")
    p.add_argument("input")
    p.add_argument("--out", "-o", default="protected")
    p.add_argument("--roster", "-r", help="CSV or newline list of recipient names")
    p.add_argument("--cover", "-c", default="facilities",
                   choices=decoymod.available_covers() or ["facilities"])
    p.add_argument("--delta", type=int, default=25,
                   help="kerning displacement in 1/1000 em (default 25 = 0.26 pt)")
    p.add_argument("--collusion", type=int, default=1,
                   help="coalition size the code must resist (default 1)")
    p.add_argument("--eps1", type=float, default=1e-6)
    p.add_argument("--candidates", type=int, default=8)
    p.add_argument("--family-wise", type=float, default=1e-3)
    p.set_defaults(fn=cmd_protect)

    p = sub.add_parser("verify", help="check that copies diverge from their text layer")
    p.add_argument("dir")
    p.add_argument("--limit", type=int, default=8)
    p.add_argument("--only")
    p.set_defaults(fn=cmd_verify)

    p = sub.add_parser("trace", help="identify which recipient's copy leaked")
    p.add_argument("evidence", help="a PDF, or an image of a page")
    p.add_argument("--manifest", "-m", required=True)
    p.add_argument("--dpi", type=int, default=300)
    p.add_argument("--threshold", type=float, default=None)
    p.add_argument("--no-normalise", dest="normalise", action="store_false")
    p.add_argument("--page", type=int, default=None,
                   help="force which master page the evidence is (1-based)")
    p.add_argument("--workdir")
    p.set_defaults(fn=cmd_trace)

    p = sub.add_parser("accessible", help="emit a true-text copy for assistive tech")
    p.add_argument("dir")
    p.set_defaults(fn=cmd_accessible)

    p = sub.add_parser("keygen", help="generate a device identity and a signing key")
    p.add_argument("--out", default="keys")
    p.set_defaults(fn=cmd_keygen)

    p = sub.add_parser("seal", help="seal a file into a posture-gated envelope")
    p.add_argument("input")
    p.add_argument("--keys", default="keys")
    p.add_argument("--out", "-o", required=True)
    p.add_argument("--matter", default="unspecified")
    p.add_argument("--lease", type=int, default=900)
    p.add_argument("--relax", action="append", metavar="PREDICATE",
                   help="drop a posture requirement (repeatable)")
    p.set_defaults(fn=cmd_seal)

    p = sub.add_parser("open", help="open an envelope, if the runtime posture allows")
    p.add_argument("envelope")
    p.add_argument("--keys", default="keys")
    p.add_argument("--out", "-o")
    p.add_argument("--assume-posture", action="store_true",
                   help="bypass the posture gate (testing only)")
    p.set_defaults(fn=cmd_open)

    p = sub.add_parser("membrane", help="run a command inside the confined runtime")
    p.add_argument("argv", nargs="*")
    p.set_defaults(fn=cmd_membrane)

    p = sub.add_parser("trail", help="synthesise an edit trail (stands in for an editor)")
    p.add_argument("--profile", choices=["honest", "pasted", "chunked"], default="honest")
    p.add_argument("--chars", type=int, default=6000)
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--out", default="trail.json")
    p.set_defaults(fn=cmd_trail)

    p = sub.add_parser("attest", help="editor side: commit and sign trail statistics")
    p.add_argument("--trail", required=True)
    p.add_argument("--submission", required=True)
    p.add_argument("--out", default="authorship")
    p.set_defaults(fn=cmd_attest)

    p = sub.add_parser("credential", help="author side: prove the policy in zero knowledge")
    p.add_argument("dir")
    p.add_argument("--out")
    p.add_argument("--policy", action="append", metavar="NAME=VALUE")
    p.add_argument("--with-time-floor", action="store_true",
                   help="add a wall-clock floor (off by default: it fails fast writers)")
    p.set_defaults(fn=cmd_credential)

    p = sub.add_parser("check", help="instructor side: verify a credential")
    p.add_argument("credential")
    p.add_argument("--trusted", help="pinned editor public key, or a path to it")
    p.add_argument("--policy", action="append", metavar="NAME=VALUE")
    p.set_defaults(fn=cmd_check)

    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
