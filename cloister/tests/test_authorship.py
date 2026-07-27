"""
Does the authorship layer actually separate honest writing from the shortcut?

Four simulated writing sessions, all producing a submission of about the same length:

  honest        typed at human pace over an hour, with normal deletion and revision
  paste_bulk    a single large paste, then light editing
  paste_chunked a dozen medium pastes, as if pasted paragraph by paragraph
  retyped       model output read off a second screen and typed in by hand

The fourth is the one that defeats this layer, and the test asserts that it does. A
test suite that only demonstrated success would be advertising, not evidence.
"""
import random
import sys

sys.path.insert(0, "..")

from cloister import authorship as A
from cloister import zk


def honest(rng, target=6000):
    """Human-paced composition: bursts of typing, pauses, deletions, rewrites."""
    t = A.EditTrail()
    now, written = 0, 0
    while written < target:
        burst = rng.randint(30, 220)
        for _ in range(burst // rng.randint(3, 9) + 1):
            n = rng.randint(3, 14)
            now += rng.randint(120, 900)
            t.add(now, "ins", n)
            written += n
        if rng.random() < 0.45:                       # revise
            d = rng.randint(5, 90)
            now += rng.randint(300, 2500)
            t.add(now, "del", d)
            written -= min(d, written)
        if rng.random() < 0.35:                       # step away, reread, think
            now += rng.randint(45_000, 600_000)
    return t


def paste_bulk(rng, target=6000):
    t = A.EditTrail()
    now = 1000
    t.add(now, "paste", target, src="clipboard")
    for _ in range(rng.randint(8, 25)):               # cosmetic touch-ups
        now += rng.randint(1500, 9000)
        t.add(now, "ins" if rng.random() < 0.6 else "del", rng.randint(2, 25))
    return t


def paste_chunked(rng, target=6000, chunks=12):
    t = A.EditTrail()
    now = 500
    for _ in range(chunks):
        now += rng.randint(4000, 30_000)
        t.add(now, "paste", target // chunks, src="clipboard")
        for _ in range(rng.randint(0, 4)):
            now += rng.randint(800, 4000)
            t.add(now, "ins", rng.randint(2, 18))
    return t


def retyped(rng, target=6000):
    """The attack this layer cannot detect: human-paced entry of text from elsewhere.
    Fewer deletions than genuine composition, but otherwise indistinguishable."""
    t = A.EditTrail()
    now, written = 0, 0
    while written < target:
        n = rng.randint(4, 16)
        now += rng.randint(140, 700)
        t.add(now, "ins", n)
        written += n
        if rng.random() < 0.06:
            d = rng.randint(2, 20)
            now += rng.randint(200, 1200)
            t.add(now, "del", d)
    return t


def honest_fast(rng, target=6000):
    """A fluent writer who knows what they want to say: same output, no long pauses.
    Included because it is the case a wall-clock floor gets wrong."""
    t = A.EditTrail()
    now, written = 0, 0
    while written < target:
        for _ in range(rng.randint(4, 20)):
            n = rng.randint(4, 16)
            now += rng.randint(90, 400)
            t.add(now, "ins", n)
            written += n
        if rng.random() < 0.4:
            d = rng.randint(5, 60)
            now += rng.randint(200, 1200)
            t.add(now, "del", d)
            written -= min(d, written)
    return t


SCENARIOS = {"honest": honest, "honest_fast": honest_fast, "paste_bulk": paste_bulk,
             "paste_chunked": paste_chunked, "retyped": retyped}


def run(seed=3, verbose=True):
    rng = random.Random(seed)
    editor = A.Editor()
    trusted = {editor.public_bytes().hex()}
    policy = dict(A.DEFAULT_POLICY)
    results = {}
    for name, fn in SCENARIOS.items():
        trail = fn(rng)
        st = trail.stats()
        att, openings = editor.attest(trail, submission_sha256="deadbeef" * 8)
        cred = A.build_credential(att, openings, policy)
        verdict = A.check_credential(cred, policy, trusted)
        results[name] = {"stats": st, "verdict": verdict,
                         "credential_bytes": len(zk.json.dumps(cred))}
        if verbose:
            met = verdict["all_predicates_met"]
            print(f"\n  {name}")
            print(f"    events {st['event_count']:>5}  max insertion {st['max_insertion']:>5}  "
                  f"unattested paste {st['unattested_paste_total']:>5}  "
                  f"elapsed {st['elapsed_seconds']//60:>3} min  revised {st['revision_chars']:>4} ch")
            for p, ok in verdict["predicates"].items():
                note = verdict["unproven"].get(p, "")
                print(f"    {'PASS' if ok else 'FAIL'}  {p:<34} {note}")
            print(f"    → {'CREDENTIAL COMPLETE' if met else 'INCOMPLETE'}"
                  f"   ({results[name]['credential_bytes']/1024:.0f} KB)")
    return results


from harness import claim, main, mutation, regression              # noqa: E402


@claim("authorship-separates-honest-from-pasted",
       says="honest composition and a fluent fast writer both earn a full credential; "
            "bulk and chunked pasting both fail; retyped model output PASSES, and the "
            "suite records that limit rather than hiding it")
def separation():
    res = run(verbose=False)
    ok = {k: v["verdict"]["all_predicates_met"] for k, v in res.items()}
    assert ok["honest"] is True, "honest composition must produce a full credential"
    assert ok["honest_fast"] is True, "a fast honest writer must also pass"
    assert ok["paste_bulk"] is False, "a single bulk paste must fail"
    assert ok["paste_chunked"] is False, "chunked pasting must fail"
    assert ok["retyped"] is True, (
        "retyped model output is expected to PASS -- this layer attests process, not "
        "origin, and the test records that limit rather than hiding it")
    return {k: ("credential complete" if v else "incomplete") for k, v in ok.items()}


@claim("authorship-credential-size",
       says="a credential is tens of KB, small enough to attach to a submission")
def credential_size():
    res = run(verbose=False)
    sizes = {k: v["credential_bytes"] for k, v in res.items()}
    assert max(sizes.values()) < 400_000, f"credentials are too large: {sizes}"
    return {k: f"{v / 1024:.0f} KB" for k, v in sizes.items()}


@regression("authorship-event-count-not-in-cleartext",
            bug="the attestation body repeated event_count in the clear alongside its "
                "commitment. How many edits a person made is exactly the incidental "
                "detail this layer exists to keep out of institutional hands, and it was "
                "being published for free.",
            found_by="reading the attestation body as an instructor would receive it, "
                     "rather than only checking that the proofs verified")
def no_statistic_in_cleartext():
    rng = random.Random(3)
    editor = A.Editor()
    trail = honest(rng)
    att, _openings = editor.attest(trail, "ab" * 32)
    body = att["body"]
    st = trail.stats()
    # Search everything EXCEPT the commitments. A commitment is 512 hex characters, and a
    # three-digit decimal turns up inside one by chance more often than not, so including
    # them makes this check fire at random rather than on a leak.
    clear = zk.json.dumps({k: v for k, v in body.items() if k != "commitments"})
    leaked = [k for k in A.STATS if k in body]
    leaked += [f"{k}={int(st[k])}" for k in A.STATS
               if int(st[k]) > 50 and str(int(st[k])) in clear]
    assert not leaked, f"attestation body leaks {leaked}"
    assert set(body["commitments"]) == set(A.STATS), "not every statistic is committed"
    for k, c in body["commitments"].items():
        assert len(c) > 400 and all(ch in "0123456789abcdef" for ch in c), (
            f"commitment for {k} does not look like a group element")
    return {"statistics committed": len(A.STATS),
            "statistics in cleartext": 0,
            "body keys": sorted(k for k in body)}


@mutation("authorship-event-count-not-in-cleartext")
def _original_published_event_count():
    rng = random.Random(3)
    editor = A.Editor()
    trail = honest(rng)
    att, _openings = editor.attest(trail, "ab" * 32)
    body = dict(att["body"], event_count=trail.stats()["event_count"])  # <-- the bug
    st = trail.stats()
    clear = zk.json.dumps({k: v for k, v in body.items() if k != "commitments"})
    leaked = [k for k in A.STATS if k in body]
    leaked += [f"{k}={int(st[k])}" for k in A.STATS
               if int(st[k]) > 50 and str(int(st[k])) in clear]
    assert not leaked, f"attestation body leaks {leaked}"


@regression("authorship-no-wall-clock-floor-by-default",
            bug="the default policy required a minimum elapsed time. It failed an honest "
                "fluent writer who produced the same work in 3 minutes that a deliberate "
                "writer took 65 minutes over -- turning writing speed into suspicion. It "
                "is now opt-in, with the caveat attached.",
            found_by="simulating a fast honest writer, a case the original scenario set "
                      "did not contain")
def default_policy_has_no_time_predicate():
    assert not any("elapsed" in k for k in A.DEFAULT_POLICY), (
        f"DEFAULT_POLICY contains a time predicate: {sorted(A.DEFAULT_POLICY)}")
    editor = A.Editor()
    trusted = {editor.public_bytes().hex()}
    out = {}
    for label, fn in (("deliberate", honest), ("fluent", honest_fast)):
        trail = fn(random.Random(3))
        att, op = editor.attest(trail, "cafe" * 16)
        v = A.check_credential(A.build_credential(att, op, A.DEFAULT_POLICY),
                               A.DEFAULT_POLICY, trusted)
        mins = trail.stats()["elapsed_seconds"] // 60
        assert v["all_predicates_met"], f"{label} writer failed the default policy"
        out[f"{label} writer"] = f"{mins} min, credential complete"
    return out


@mutation("authorship-no-wall-clock-floor-by-default")
def _original_default_time_floor():
    editor = A.Editor()
    trusted = {editor.public_bytes().hex()}
    for label, fn in (("deliberate", honest), ("fluent", honest_fast)):
        trail = fn(random.Random(3))
        att, op = editor.attest(trail, "cafe" * 16)
        v = A.check_credential(A.build_credential(att, op, A.ELAPSED_POLICY),
                               A.ELAPSED_POLICY, trusted)      # <-- floor in the default
        assert v["all_predicates_met"], (
            f"{label} writer failed a default policy carrying a 30-minute floor "
            f"({trail.stats()['elapsed_seconds'] // 60} min elapsed)")


@claim("authorship-trail-is-tamper-evident",
       says="the editor signs the trail's Merkle root, so editing, inserting or dropping "
            "an event makes the trail stop matching its own attestation")
def trail_is_tamper_evident():
    rng = random.Random(9)
    editor = A.Editor()
    trusted = {editor.public_bytes().hex()}
    trail = honest(rng, target=1200)
    att, _op = editor.attest(trail, "ff" * 32)
    signed_root = att["body"]["trail_root"]
    assert A.verify_attestation(att, trusted), "a fresh attestation does not verify"
    assert trail.root() == signed_root

    out = {"events": len(trail.events), "signed root": signed_root[:16] + "..."}
    for label, mutate in (
            ("edit an event", lambda t: t.events.__setitem__(
                3, dict(t.events[3], n=99999))),
            ("drop an event", lambda t: t.events.pop(5)),
            ("insert an event", lambda t: t.events.insert(
                7, {"t": 1, "op": "paste", "n": 5000}))):
        t2 = A.EditTrail.from_json(trail.to_json())
        mutate(t2)
        assert t2.root() != signed_root, f"{label} did not change the root"
        out[label] = "root no longer matches the attestation"
    # the attestation itself still verifies -- it is the trail that no longer matches,
    # which is the right division: the signature covers a commitment, not the log
    assert A.verify_attestation(att, trusted)
    return out


if __name__ == "__main__":
    main(__doc__)


def _demo():
    print("Authorship provenance — separation test")
    res = run()
    print("\n  " + "-" * 68)
    ok = {k: v["verdict"]["all_predicates_met"] for k, v in res.items()}
    for k, v in ok.items():
        print(f"  {k:<15} {'credential complete' if v else 'incomplete'}")
    assert ok["honest"] is True, "honest composition must produce a full credential"
    assert ok["honest_fast"] is True, "a fast honest writer must also pass"
    assert ok["paste_bulk"] is False, "a single bulk paste must fail"
    assert ok["paste_chunked"] is False, "chunked pasting must fail"
    assert ok["retyped"] is True, (
        "retyped model output is expected to PASS — this layer attests process, "
        "not origin, and the test records that limit rather than hiding it")
    print("\n  All assertions hold, including the one that documents the limit:")
    print("  retyped model output passes. Process attestation cannot see origin.")

    # what an opt-in time floor does to each kind of honest writer
    print("\n  Opt-in 30-minute floor, applied to two honest sessions:")
    editor = A.Editor(); trusted = {editor.public_bytes().hex()}
    for label, fn in (("deliberate writer", honest), ("fluent writer", honest_fast)):
        trail = fn(random.Random(3))
        att, op = editor.attest(trail, "cafe" * 16)
        v = A.check_credential(A.build_credential(att, op, A.ELAPSED_POLICY),
                               A.ELAPSED_POLICY, trusted)
        mins = trail.stats()["elapsed_seconds"] // 60
        met = v["predicates"].get("elapsed_seconds_atleast")
        print(f"    {label:<19} {mins:>3} min  floor {'met' if met else 'FAILED'}"
              f"  → credential {'complete' if v['all_predicates_met'] else 'INCOMPLETE'}")
    print("    Same work, same output, opposite verdicts. A floor turns writing speed")
    print("    into suspicion, which is why it is off by default.")
