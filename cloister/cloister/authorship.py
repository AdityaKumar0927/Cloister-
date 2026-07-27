"""
Layer A — authorship provenance.

The academic case is usually framed backwards. A professor's requirement is not "the
student must be unable to feed this to a model" -- that is unachievable. It is "the
submission must be the student's own work". Those are different claims, and only the
second is provable.

Detection attempts the second claim by inspecting the artefact, which does not work:
the signal is weak, the cost of a false positive is an accused student, and the bias
falls on non-native English writers. So this layer attests the *process* instead, and
inverts the burden: a student who wrote normally can offer positive evidence, and
nobody has to run a classifier over their prose.

Two separate trust problems, which need two different mechanisms, and conflating them
is the mistake a naive design makes:

  * Protecting the STUDENT from the institution. A keystroke log is surveillance and no
    institution should hold one. So the trail never leaves the student's device, and
    only zero-knowledge predicates over it are disclosed ("no single insertion exceeded
    400 characters"), never the log, the timings, or the text.

  * Protecting the INSTITUTION from the student. Zero-knowledge proofs supply no
    integrity on their own -- a student could commit to whatever statistics suit them
    and prove things about those. So an attested editor computes the statistics, commits
    to them, and signs the commitments together with the trail root and the submission
    hash. The student then chooses which of those signed commitments to open in zero
    knowledge. The proofs are privacy; the signature is integrity.

What this cannot do is in `LIMITS` at the bottom of this file, and it is not a short
list.
"""
from __future__ import annotations
import hashlib
import json
import statistics
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from . import zk

# statistics the editor commits to, and the width each is range-proved at
STATS = {
    "max_insertion": 12,          # largest single insertion, characters
    "unattested_paste_total": 14,  # total characters pasted from an unattested source
    "elapsed_seconds": 24,        # wall time from first to last event
    "revision_chars": 16,         # inserted-then-deleted: evidence of actual editing
    "event_count": 20,
}


def _canon(o) -> bytes:
    return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()


# --------------------------------------------------------------------- the trail
class EditTrail:
    """
    A hash-chained log of edit events. Each event is
        {"t": ms since start, "op": "ins"|"del"|"paste", "n": chars, "src": str|None}
    `src` names the provenance of a paste: "attested" for a paste from another
    CLOISTER-attested document, otherwise the origin is unknown and it counts against
    the unattested total.
    """

    def __init__(self):
        self.events: list[dict] = []
        self.chain = hashlib.sha256(b"cloister/trail/v1").digest()

    def add(self, t_ms: int, op: str, n: int, src: str | None = None):
        ev = {"t": int(t_ms), "op": op, "n": int(n)}
        if src:
            ev["src"] = src
        self.events.append(ev)
        self.chain = hashlib.sha256(self.chain + _canon(ev)).digest()
        return self

    def to_json(self) -> str:
        return json.dumps({"version": 1, "events": self.events}, separators=(",", ":"))

    @classmethod
    def from_json(cls, text: str) -> "EditTrail":
        t = cls()
        for ev in json.loads(text)["events"]:
            t.add(ev["t"], ev["op"], ev["n"], ev.get("src"))
        return t

    # -- Merkle commitment, for selective disclosure of a single challenged event ---
    def leaves(self) -> list[bytes]:
        return [hashlib.sha256(b"leaf" + _canon(e)).digest() for e in self.events]

    def root(self) -> str:
        ls = self.leaves() or [hashlib.sha256(b"empty").digest()]
        while len(ls) > 1:
            nxt = []
            for i in range(0, len(ls), 2):
                a = ls[i]
                b = ls[i + 1] if i + 1 < len(ls) else a
                nxt.append(hashlib.sha256(b"node" + a + b).digest())
            ls = nxt
        return ls[0].hex()

    def path(self, index: int) -> list[str]:
        ls = self.leaves()
        out, i = [], index
        while len(ls) > 1:
            nxt = []
            for j in range(0, len(ls), 2):
                a = ls[j]
                b = ls[j + 1] if j + 1 < len(ls) else a
                if j == (i // 2) * 2:
                    out.append((b if i % 2 == 0 else a).hex())
                nxt.append(hashlib.sha256(b"node" + a + b).digest())
            ls, i = nxt, i // 2
        return out

    # -- statistics ----------------------------------------------------------------
    def stats(self) -> dict:
        ins = [e for e in self.events if e["op"] in ("ins", "paste")]
        dels = [e for e in self.events if e["op"] == "del"]
        total_ins = sum(e["n"] for e in ins)
        total_del = sum(e["n"] for e in dels)
        pastes = [e for e in self.events if e["op"] == "paste"]
        unatt = [e for e in pastes if e.get("src") != "attested"]
        ts = [e["t"] for e in self.events]
        gaps = [b - a for a, b in zip(ts, ts[1:])] if len(ts) > 1 else [0]
        typed = [g for g in gaps if 0 < g < 3000]
        return {
            "max_insertion": max((e["n"] for e in ins), default=0),
            "unattested_paste_total": sum(e["n"] for e in unatt),
            "elapsed_seconds": int((max(ts) - min(ts)) / 1000) if ts else 0,
            "revision_chars": min(total_del, (1 << STATS["revision_chars"]) - 1),
            "event_count": len(self.events),
            # not committed; reported locally so the student can see what would be shown
            "_total_inserted": total_ins,
            "_paste_count": len(pastes),
            "_unattested_paste_count": len(unatt),
            "_median_gap_ms": int(statistics.median(typed)) if typed else 0,
            "_gap_cv": round(statistics.pstdev(typed) / statistics.mean(typed), 3)
            if len(typed) > 2 and statistics.mean(typed) > 0 else 0.0,
        }


# ---------------------------------------------------------------- the attestation
class Editor:
    """Stands in for an attested editor. In deployment this key lives in a signed
    application whose identity the institution pins; here it is a plain Ed25519 key."""

    def __init__(self, name="cloister-editor/0.2", sk: bytes | None = None):
        self.name = name
        self.sk = (ed25519.Ed25519PrivateKey.from_private_bytes(sk) if sk
                   else ed25519.Ed25519PrivateKey.generate())

    def public_bytes(self) -> bytes:
        return self.sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def attest(self, trail: EditTrail, submission_sha256: str) -> tuple[dict, dict]:
        """
        Returns (attestation, openings). The attestation is public and carries only
        commitments. The openings stay with the student and are what let them prove
        predicates later; handing them over would defeat the point.
        """
        st = trail.stats()
        commitments, openings = {}, {}
        for key in STATS:
            v = int(st[key])
            r = zk.rand_scalar()
            C, _ = zk.commit(v, r)
            commitments[key] = format(C, "x")
            openings[key] = {"v": v, "r": format(r, "x")}
        # event_count is committed like every other statistic and deliberately NOT
        # repeated in the clear: the number of edits a person made is exactly the kind
        # of incidental detail this layer exists to keep out of institutional hands.
        body = {
            "editor": self.name,
            "trail_root": trail.root(),
            "submission_sha256": submission_sha256,
            "commitments": commitments,
            "stat_widths": STATS,
        }
        sig = self.sk.sign(_canon(body))
        return ({"body": body, "sig": sig.hex(),
                 "editor_pubkey": self.public_bytes().hex()}, openings)


def verify_attestation(att: dict, trusted_pubkeys: set[str] | None = None) -> bool:
    try:
        pk = att["editor_pubkey"]
        if trusted_pubkeys is not None and pk not in trusted_pubkeys:
            return False
        ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk)).verify(
            bytes.fromhex(att["sig"]), _canon(att["body"]))
        return True
    except Exception:
        return False


# ------------------------------------------------------------------- the credential
# The default policy deliberately contains no time or rhythm predicate.
#
# A wall-clock floor looks like an obvious check and is a bad one: a fluent writer who
# knows what they want to say can produce a thousand words in fifteen minutes, and a
# floor of half an hour fails them while a padded session passes. It penalises speed and
# rewards leaving the editor open. Rhythm statistics are worse -- they misfire on
# dictation, on motor impairment, and on drafting in a second language, and machine-paced
# replay is easy to make human-looking anyway.
#
# What is left is what actually discriminates: the size of the largest single insertion,
# and how much text arrived from a source that could not be attested. Those catch the
# shortcut that is actually taken. ELAPSED_POLICY below is available for an instructor
# who wants a time floor, with the caveat attached.
DEFAULT_POLICY = {
    "max_insertion_atmost": 400,
    "unattested_paste_total_atmost": 1200,
    "revision_chars_atleast": 200,
}

ELAPSED_POLICY = dict(DEFAULT_POLICY, elapsed_seconds_atleast=1800)


def build_credential(att: dict, openings: dict, policy: dict) -> dict:
    """
    The student decides which predicates to prove. Each proof is bound to the
    commitment the editor signed, so the values cannot be swapped for convenient ones.
    A predicate the student cannot satisfy is reported as unproven rather than faked --
    the prover refuses false statements.
    """
    proofs, unproven = {}, {}
    widths = att["body"]["stat_widths"]
    for pname, bound in policy.items():
        stat, _, kind = pname.rpartition("_")
        o = openings.get(stat)
        if o is None:
            unproven[pname] = "no such statistic"
            continue
        v, r = o["v"], int(o["r"], 16)
        ctx = f"{att['body']['trail_root']}|{att['body']['submission_sha256']}|{pname}"
        try:
            if kind == "atmost":
                proofs[pname] = zk.prove_bound_fixed(v, r, bound, ctx)
            elif kind == "atleast":
                proofs[pname] = zk.prove_atleast_fixed(
                    v, r, bound, ctx, nbits=widths.get(stat, 24))
            else:
                unproven[pname] = f"unknown predicate kind {kind!r}"
        except ValueError as e:
            unproven[pname] = str(e)
    return {"attestation": att, "policy": policy,
            "proofs": {k: zk._enc(v) for k, v in proofs.items()},
            "unproven": unproven}


def check_credential(cred: dict, policy: dict | None = None,
                     trusted_pubkeys: set[str] | None = None) -> dict:
    """Instructor side. Returns a verdict; never a probability that prose was generated."""
    att = cred["attestation"]
    out = {"attestation_valid": verify_attestation(att, trusted_pubkeys),
           "submission_sha256": att["body"]["submission_sha256"],
           "trail_root": att["body"]["trail_root"],
           "editor": att["body"]["editor"],
           "predicates": {}, "unproven": dict(cred.get("unproven", {}))}
    want = policy or cred["policy"]
    for pname, bound in want.items():
        stat, _, kind = pname.rpartition("_")
        Chex = att["body"]["commitments"].get(stat)
        pf = cred["proofs"].get(pname)
        if Chex is None or pf is None:
            out["predicates"][pname] = False
            out["unproven"].setdefault(pname, "no proof supplied")
            continue
        pf = zk._dec(pf)
        # the claimed bound in the proof must be the one the policy asked for
        claimed = pf.get("bound") if kind == "atmost" else pf.get("floor")
        if claimed != bound:
            out["predicates"][pname] = False
            out["unproven"][pname] = (f"proof states {kind} {claimed}, "
                                      f"policy requires {bound}")
            continue
        C = int(Chex, 16)
        ctx = f"{att['body']['trail_root']}|{att['body']['submission_sha256']}|{pname}"
        ok = (zk.verify_bound_fixed(C, pf, ctx) if kind == "atmost"
              else zk.verify_atleast_fixed(C, pf, ctx))
        out["predicates"][pname] = bool(ok)
    out["all_predicates_met"] = (out["attestation_valid"]
                                 and bool(out["predicates"])
                                 and all(out["predicates"].values()))
    return out


def bind_submission(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


LIMITS = """
What this layer does NOT establish, stated plainly because a provenance credential
invites over-reading:

1. It attests a PROCESS, not an ORIGIN. A student who reads model output on a phone and
   retypes it at human pace produces a trail that satisfies every predicate. That is the
   fundamental limit and no amount of statistics closes it. The value is that the effort
   is real, the shortcut is no longer free, and the honest student is no longer at the
   mercy of a classifier.
2. It depends entirely on the editor being attested. Without a signed, pinned editor
   identity, a student can synthesise a plausible trail directly. The zero-knowledge
   proofs supply privacy, never integrity.
3. Timing statistics are weak evidence and are deliberately NOT part of the default
   policy. Machine-paced replay is easy to make human-looking, and real human typing is
   wildly variable -- a policy that flagged unusual rhythm would misfire on students
   with motor impairments, on those using dictation, and on anyone drafting in a second
   language. The same objection applies to a wall-clock floor, which is why the default
   policy has none: in testing, a simulated honest session that produced a thousand
   words in thirteen minutes failed a thirty-minute floor. That is a fast writer, not a
   cheat, and a control that cannot tell the difference should not ship enabled.
4. It must be optional. A mandatory provenance regime with no alternative assessment
   route reproduces the false-accusation harm it was built to replace. A student who
   declines should be offered another route, not treated as suspect.
5. Absence of a credential is not evidence of misconduct. It means no credential was
   offered.
"""
