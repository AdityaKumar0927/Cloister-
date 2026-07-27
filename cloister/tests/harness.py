"""
A test harness with one unusual rule.

Every regression test in this suite must also demonstrate that it *would have caught the
bug*. A regression test that merely asserts the current behaviour is worth very little:
it passes on the fixed code and it would also have passed on the broken code in most of
the ways a test can be written badly. Six of the security properties this project claims
were silently false at some point, and in every case the reason was the same -- nothing
exercised the condition that made them false.

So a regression test here registers two callables:

    check()    exercises the fixed implementation and asserts the property holds
    mutate()   reconstructs the ORIGINAL BROKEN implementation and asserts it fails

If mutate() does not fail, the test is reported as TOOTHLESS rather than passing, and the
suite exits non-zero. This is mutation testing narrowed to the mutations that actually
happened, which is the subset that has already proven it can get past review.

Ordinary claim tests register check() alone. Those correspond to numbers reported in the
whitepaper, and their job is to make the paper falsifiable by anyone who runs `make test`.
"""
from __future__ import annotations

import contextlib
import io
import json
import sys
import time
import traceback
import warnings

warnings.filterwarnings("ignore")     # third-party deprecation noise breaks the columns

CLAIMS: list[dict] = []


def claim(name: str, says: str):
    """A measured property the whitepaper reports. check() must raise to fail."""
    def deco(fn):
        CLAIMS.append({"kind": "claim", "name": name, "says": says,
                       "check": fn, "mutate": None, "file": fn.__module__})
        return fn
    return deco


def regression(name: str, bug: str, found_by: str):
    """
    A bug found by measurement. The decorated function asserts the property now holds;
    a separate function decorated @mutation(name) reconstructs the original broken
    implementation and must fail. `bug` states what was wrong, `found_by` states what
    exercised it -- both are printed, because "why did nothing catch this" is the useful
    part of a regression test.
    """
    def deco(fn):
        CLAIMS.append({"kind": "regression", "name": name, "says": bug,
                       "found_by": found_by, "check": fn, "mutate": None,
                       "file": fn.__module__})
        return fn
    return deco


def mutation(name: str):
    """Attach the original broken implementation to a named regression test."""
    def deco(fn):
        for c in CLAIMS:
            if c["name"] == name:
                c["mutate"] = fn
                return fn
        raise KeyError(f"no regression named {name!r} to attach a mutation to")
    return deco


def _snapshot() -> dict:
    """
    Record which function object every cloister module attribute currently points at.

    Mutations here work by monkeypatching -- that is the only honest way to reconstruct a
    fixed function's broken predecessor -- and a mutation whose restore is wrong leaves the
    broken version installed for every test that runs afterwards. That failure does not
    look like a leak: it looks like five unrelated tests regressing at once, in a different
    file, and the real cause is a `finally` clause several hundred lines away. So the
    harness checks after every test rather than trusting each mutation's cleanup.
    """
    return {name: {k: v for k, v in vars(m).items() if callable(v)}
            for name, m in list(sys.modules.items())
            if name.startswith("cloister.") and m is not None}


def _restore(snap: dict) -> list:
    leaked = []
    for name, attrs in snap.items():
        m = sys.modules.get(name)
        if m is None:
            continue
        for k, v in attrs.items():
            if vars(m).get(k) is not v:
                leaked.append(f"{name.split('.')[-1]}.{k}")
                setattr(m, k, v)
    return leaked


def _quiet(fn):
    """Third-party libraries print to stdout when they meet a malformed input, which is
    exactly what a mutation feeds them. Capture it; surface it only on failure."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        out = fn()
    return out, buf.getvalue()


def _run_one(c, verbose=True):
    t0 = time.time()
    rec = {"name": c["name"], "kind": c["kind"], "says": c["says"]}
    if c.get("found_by"):
        rec["found_by"] = c["found_by"]
    snap = _snapshot()
    try:
        detail, noise = _quiet(c["check"])
        rec["detail"] = detail if isinstance(detail, dict) else {}
        if noise.strip():
            rec["stdout"] = noise.strip()[:2000]
        rec["status"] = "pass"
    except Exception as e:
        rec["status"] = "FAIL"
        rec["error"] = f"{type(e).__name__}: {e}"
        rec["traceback"] = traceback.format_exc(limit=6)
        rec["seconds"] = round(time.time() - t0, 2)
        return rec

    if c["kind"] == "regression":
        if c["mutate"] is None:
            rec["status"] = "TOOTHLESS"
            rec["error"] = "no mutation registered; cannot show the test has power"
        else:
            try:
                _quiet(c["mutate"])
            except AssertionError as e:
                rec["mutation"] = f"reproduced the original failure: {e}"
            except Exception as e:
                rec["mutation"] = f"original failed with {type(e).__name__}: {e}"
            else:
                rec["status"] = "TOOTHLESS"
                rec["error"] = ("the original broken implementation PASSED this test, "
                                "so the test would not have caught the bug")

    leaked = _restore(snap)
    if leaked and rec["status"] == "pass":
        rec["status"] = "LEAKY"
        rec["error"] = ("left patched module state behind, which would have corrupted "
                        f"every later test: {', '.join(sorted(set(leaked)))}")
    elif leaked:
        rec["leaked"] = sorted(set(leaked))
    rec["seconds"] = round(time.time() - t0, 2)
    return rec


def run(select=None, verbose=True, only_module=None) -> dict:
    results = []
    order = [c for c in CLAIMS
             if (select is None or select in c["name"])
             and (only_module is None or c["file"] == only_module)]
    width = max((len(c["name"]) for c in order), default=10)
    for c in order:
        if verbose:
            sys.stdout.write(f"  {c['name']:<{width}}  ")
            sys.stdout.flush()
        r = _run_one(c, verbose)
        results.append(r)
        if verbose:
            mark = {"pass": "PASS", "FAIL": "FAIL", "TOOTHLESS": "TOOTHLESS",
                    "LEAKY": "LEAKY"}[r["status"]]
            extra = ""
            if r["status"] == "pass" and c["kind"] == "regression":
                extra = "  (mutation reproduces the bug)"
            print(f"{mark:<9} {r['seconds']:>6.2f}s{extra}")
            if r["status"] != "pass":
                print(f"      {r['error']}")
            elif verbose and r.get("detail"):
                for k, v in r["detail"].items():
                    print(f"      {k}: {v}")
    n_pass = sum(1 for r in results if r["status"] == "pass")
    return {"results": results, "passed": n_pass, "total": len(results),
            "ok": n_pass == len(results)}


def main(module_doc=None):
    """Run only the tests defined in the file being executed. Test modules import each
    other for fixtures, and importing a module registers its claims."""
    if module_doc:
        print(module_doc.strip().splitlines()[0])
    summary = run(only_module="__main__")
    print(f"\n  {summary['passed']}/{summary['total']} passed")
    if not summary["ok"]:
        for r in summary["results"]:
            if r["status"] != "pass":
                print(f"  {r['status']}  {r['name']}")
    print(json.dumps({"passed": summary["passed"], "total": summary["total"]}))
    sys.exit(0 if summary["ok"] else 1)
