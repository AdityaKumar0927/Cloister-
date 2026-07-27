"""
Layer P2, the membrane: what the kernel actually enforces, tested by trying to escape it
rather than by asserting that a sandbox was applied.
"""
import json
import os
import subprocess
import sys
import textwrap

sys.path.insert(0, "..")
sys.path.insert(0, ".")

from cloister import membrane as MB                                # noqa: E402
from harness import claim, main, mutation, regression              # noqa: E402

SRC = os.path.abspath("..")


def _in_child(body: str, harden=True, timeout=60):
    """
    Run `body` inside the membrane in a fresh interpreter, after an execve, and return the
    JSON it prints. Testing across execve is the point: a filter that does not survive
    exec covers only the launcher, not the renderer it launches.
    """
    script = textwrap.dedent(f"""
        import json, os, sys
        sys.path.insert(0, {SRC!r})
        os.environ["CLOISTER_TEST_NO_HARDEN"] = {"0" if harden else "1"!r}
        from cloister import membrane as MB
        {"" if harden else "MB.harden = lambda: False"}
        {body}
    """)
    stage = textwrap.dedent(f"""
        import os, sys
        sys.path.insert(0, {SRC!r})
        from cloister import membrane as MB
        MB.enter()
        os.execv(sys.executable, [sys.executable, "-c", {script!r}])
    """)
    p = subprocess.run([sys.executable, "-c", stage], capture_output=True, text=True,
                       timeout=timeout)
    line = [l for l in p.stdout.splitlines() if l.startswith("{")]
    if not line:
        raise RuntimeError(f"child produced no result: {p.stdout!r} {p.stderr[-400:]!r}")
    return json.loads(line[-1])


@claim("membrane-refuses-unsupported-platforms",
       says="the module refuses to install rather than silently applying nothing, because "
            "the syscall numbers it uses are x86_64-specific")
def refuses_unsupported():
    ok, why = MB.supported()
    assert isinstance(ok, bool) and why
    assert len(MB.DENY) == 16, f"expected 16 denied syscalls, found {len(MB.DENY)}"
    prog, arr = MB.build_filter()
    # 4 preamble instructions + one jump per syscall + allow + deny
    assert prog.len == 4 + len(MB.DENY) + 2, f"filter has {prog.len} instructions"
    return {"platform supported": ok, "denied syscalls": len(MB.DENY),
            "filter instructions": prog.len,
            "landlock abi": MB.landlock_abi() or "unavailable"}


@claim("membrane-blocks-egress-across-execve",
       says="every socket family is refused inside the membrane, and the filter survives "
            "execve so it covers the renderer and anything it launches")
def egress_blocked_after_exec():
    if not MB.supported()[0]:
        return {"skipped": MB.supported()[1]}
    r = _in_child("""
        import socket
        res = {}
        for name, fam, typ in (("inet", socket.AF_INET, socket.SOCK_STREAM),
                               ("unix", socket.AF_UNIX, socket.SOCK_STREAM),
                               ("netlink", socket.AF_NETLINK, socket.SOCK_RAW),
                               ("inet6", socket.AF_INET6, socket.SOCK_DGRAM)):
            try:
                socket.socket(fam, typ).close()
                res[name] = "ALLOWED"
            except OSError as e:
                res[name] = e.errno
        res["seccomp_mode"] = MB.libc.prctl(MB.PR_GET_SECCOMP, 0, 0, 0, 0)
        print(json.dumps(res))
    """)
    assert r["seccomp_mode"] == 2, "the filter did not survive execve"
    for fam in ("inet", "unix", "netlink", "inet6"):
        assert r[fam] != "ALLOWED", f"{fam} sockets were allowed inside the membrane"
    return {"seccomp mode after exec": r["seccomp_mode"],
            "socket families refused": "inet, unix, netlink, inet6",
            "errno": r["inet"]}


@claim("membrane-is-one-way",
       says="the membrane cannot be left: seccomp filters and no_new_privs cannot be "
            "removed once set, which is what makes 'enter first, then ask for a key' "
            "meaningful")
def membrane_is_one_way():
    if not MB.supported()[0]:
        return {"skipped": MB.supported()[1]}
    r = _in_child("""
        res = {}
        # try to install a permissive filter on top: allowed, but it cannot widen
        import ctypes
        allow_all, arr = MB.build_filter(deny={})
        rc = MB.libc.prctl(MB.PR_SET_SECCOMP, 2, ctypes.byref(allow_all), 0, 0)
        res["install_permissive_rc"] = rc
        import socket
        try:
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).close()
            res["socket_after"] = "ALLOWED"
        except OSError as e:
            res["socket_after"] = e.errno
        res["no_new_privs"] = MB.libc.prctl(MB.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
        print(json.dumps(res))
    """)
    assert r["socket_after"] != "ALLOWED", (
        "adding a permissive filter re-opened egress: filters are supposed to intersect")
    assert r["no_new_privs"] == 1, "no_new_privs was not set"
    return {"stacking a permissive filter": "does not widen the restriction",
            "socket still refused": r["socket_after"], "no_new_privs": 1}


@claim("membrane-reports-unverifiable-predicates-as-false",
       says="capture exclusion, clipboard gating and renderer attestation are not "
            "implemented here, so they are reported False and a policy requiring them "
            "fails closed rather than being optimistically assumed")
def unverifiable_predicates_fail_closed():
    obs = MB.observe()
    for k in ("capture_excluded", "clipboard_gated", "attested_renderer"):
        assert obs[k] is False, f"{k} was optimistically reported {obs[k]}"
    from cloister import envelope as E
    assert set(obs) == set(E.POSTURE), "observed predicates do not match the policy set"
    return {k: obs[k] for k in E.POSTURE}


@regression("membrane-dumpable-across-execve",
            bug="PR_SET_DUMPABLE does not survive execve -- the kernel resets it to 1 -- "
                "while the seccomp filter does. Reading /proc/<pid>/mem is an ordinary "
                "file read, not a syscall a filter can distinguish, so dumpable=0 is the "
                "only thing stopping a same-uid process inspecting the reader's memory. "
                "Losing it across exec silently reopened that path while the posture "
                "report still said the process was protected.",
            found_by="reading the dumpable flag in the child AFTER exec instead of before")
def dumpable_survives_exec():
    if not MB.supported()[0]:
        return {"skipped": MB.supported()[1]}
    r = _in_child("""
        res = {"seccomp": MB.libc.prctl(MB.PR_GET_SECCOMP, 0, 0, 0, 0),
               "dumpable_raw": MB.libc.prctl(MB.PR_GET_DUMPABLE, 0, 0, 0, 0)}
        obs = MB.observe()
        res["dumpable_after_observe"] = MB.libc.prctl(MB.PR_GET_DUMPABLE, 0, 0, 0, 0)
        res["ptrace_blocked"] = obs["ptrace_blocked"]
        print(json.dumps(res))
    """)
    assert r["seccomp"] == 2, "the filter did not survive execve"
    assert r["dumpable_raw"] == 1, (
        "the kernel did not reset dumpable across execve, so this platform does not "
        "reproduce the condition the fix is for")
    assert r["dumpable_after_observe"] == 0, "harden() did not re-assert dumpable"
    assert r["ptrace_blocked"] is True, (
        "posture reports ptrace_blocked False after exec even though the filter survived")
    return {"dumpable inherited from exec": r["dumpable_raw"],
            "after observe() re-asserts": r["dumpable_after_observe"],
            "ptrace_blocked": r["ptrace_blocked"]}


@mutation("membrane-dumpable-across-execve")
def _original_no_reassert():
    """observe() without the harden() call, which is how it was written."""
    if not MB.supported()[0]:
        raise AssertionError("platform cannot run the membrane at all")
    r = _in_child("""
        obs = MB.observe()
        print(json.dumps({"ptrace_blocked": obs["ptrace_blocked"],
                          "dumpable": MB.libc.prctl(MB.PR_GET_DUMPABLE, 0, 0, 0, 0)}))
    """, harden=False)
    assert r["dumpable"] == 0 and r["ptrace_blocked"] is True, (
        f"without re-asserting, the process after exec has dumpable={r['dumpable']} and "
        f"reports ptrace_blocked={r['ptrace_blocked']}")


@claim("membrane-run-confined-propagates-exit-status",
       says="run_confined is usable as a launcher: it reports the child's exit status "
            "rather than swallowing it")
def run_confined_status():
    if not MB.supported()[0]:
        return {"skipped": MB.supported()[1]}
    ok = MB.run_confined([sys.executable, "-c", "raise SystemExit(0)"])
    bad = MB.run_confined([sys.executable, "-c", "raise SystemExit(7)"])
    assert ok == 0 and bad == 7, f"exit statuses were {ok} and {bad}"
    return {"clean exit": ok, "failing exit": bad}


if __name__ == "__main__":
    main(__doc__)
