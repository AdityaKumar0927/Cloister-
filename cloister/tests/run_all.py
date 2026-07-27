"""
Run every claim and every regression in the suite, and write the result to JSON.

Two exit conditions matter, and they are different:

  FAIL       a claim the whitepaper makes is no longer true
  TOOTHLESS  a regression test passed, but the ORIGINAL BROKEN CODE would have passed it
             too, so the test does not actually protect anything

The second is the one that is easy to ship by accident, and it is the reason each
regression test here carries the bug it was written for. See harness.py.

    python3 run_all.py               everything
    python3 run_all.py --fast        skip the modules that rasterise pages
    python3 run_all.py kerning       only tests whose name contains "kerning"
"""
import json
import os
import sys
import time

sys.path.insert(0, "..")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import harness                                                    # noqa: E402

# Order matters only for reading the output: cheap and cryptographic first, then the
# modules that rasterise PDFs and take real time.
MODULES = ["test_zk", "test_code", "test_envelope", "test_membrane",
           "test_authorship", "test_render", "test_kerning", "test_trace"]
SLOW = {"test_render", "test_kerning", "test_trace"}


def main(argv):
    fast = "--fast" in argv
    select = next((a for a in argv[1:] if not a.startswith("-")), None)
    mods = [m for m in MODULES if not (fast and m in SLOW)]

    print("CLOISTER regression suite")
    print("  every claim the whitepaper makes, and every bug found by measurement")
    print("  a regression test that its own bug would have passed is reported TOOTHLESS\n")

    t0 = time.time()
    imported = []
    for m in mods:
        __import__(m)
        imported.append(m)

    by_module = {}
    all_results = []
    for m in imported:
        group = [c for c in harness.CLAIMS if c["file"] == m]
        if not group:
            continue
        shown = [c for c in group if select is None or select in c["name"]]
        if not shown:
            continue
        print(f"{m}")
        saved, harness.CLAIMS = harness.CLAIMS, shown
        try:
            summary = harness.run(select=None, verbose=True)
        finally:
            harness.CLAIMS = saved
        by_module[m] = summary
        all_results.extend(summary["results"])
        print()

    n = len(all_results)
    ok = sum(1 for r in all_results if r["status"] == "pass")
    failed = [r for r in all_results if r["status"] == "FAIL"]
    toothless = [r for r in all_results if r["status"] == "TOOTHLESS"]
    leaky = [r for r in all_results if r["status"] == "LEAKY"]
    regressions = [r for r in all_results if r["kind"] == "regression"]

    print("-" * 78)
    print(f"  {ok}/{n} passed in {time.time() - t0:.0f}s "
          f"({len(regressions)} regression tests, "
          f"{n - len(regressions)} measured claims)")
    for r in failed:
        print(f"  FAIL       {r['name']}: {r['error']}")
    for r in toothless:
        print(f"  TOOTHLESS  {r['name']}: {r['error']}")
    for r in leaky:
        print(f"  LEAKY      {r['name']}: {r['error']}")

    if not failed and not toothless and not leaky and select is None and not fast:
        print("\n  Bugs this suite locks in, each found by measurement rather than review:")
        for r in regressions:
            print(f"    - {r['name']}")
            print(f"        found by: {r.get('found_by', 'n/a')}")

    out = {"passed": ok, "total": n, "seconds": round(time.time() - t0, 1),
           "failed": [r["name"] for r in failed],
           "toothless": [r["name"] for r in toothless],
           "leaky": [r["name"] for r in leaky],
           "results": [{k: v for k, v in r.items() if k != "traceback"}
                       for r in all_results]}
    dest = os.path.join("..", "..", "out", "regression.json")
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(dest, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1)
    print(f"\n  wrote {os.path.normpath(dest)}")
    return 0 if not (failed or toothless or leaky) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
