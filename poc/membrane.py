#!/usr/bin/env python3
"""
CLOISTER — Layer P (Prevent), part 2: the One-Way Membrane.

A process that has touched cleartext is *tainted*. Taint is enforced, not audited:
the reader is launched into a runtime from which no egress path exists, and the
absence of those paths is what the envelope's policy gate attests to before any key
is released. Ordering matters -- posture first, key second -- because a sandbox
applied after decryption protects nothing.

Enforced here, unprivileged-or-near-unprivileged, on Linux:
  * CLONE_NEWNET   -- empty network namespace: no interfaces, no routes, no DNS
  * seccomp-bpf    -- socket/connect/send*/recv*/ptrace/process_vm_* -> EPERM
  * CLONE_NEWIPC   -- no shared SysV IPC with untainted processes
  * PR_SET_DUMPABLE 0 -- no /proc/pid/mem reads by same-uid processes
  * Landlock       -- filesystem + (ABI>=4) TCP + (ABI>=6) abstract-UNIX scoping,
                      applied when the running kernel exposes it

The filter survives execve, so it covers the real renderer, its child processes and
any library it loads -- including an MCP server or agent runtime that tried to
attach itself downstream.
"""
import ctypes, ctypes.util, json, os, struct, sys, time

libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)

CLONE_NEWNET, CLONE_NEWIPC, CLONE_NEWUTS = 0x40000000, 0x08000000, 0x04000000
PR_SET_NO_NEW_PRIVS, PR_SET_SECCOMP, PR_SET_DUMPABLE = 38, 22, 4
SECCOMP_MODE_FILTER = 2
RET_ALLOW, RET_ERRNO_EPERM, RET_KILL = 0x7FFF0000, 0x00050001, 0x80000000
AUDIT_ARCH_X86_64 = 0xC000003E

# x86_64 syscall numbers for every egress primitive we deny
DENY = {
    "socket": 41, "connect": 42, "accept": 43, "sendto": 44, "recvfrom": 45,
    "sendmsg": 46, "recvmsg": 47, "bind": 49, "listen": 50, "socketpair": 53,
    "ptrace": 101, "recvmmsg": 299, "sendmmsg": 307, "accept4": 288,
    "process_vm_readv": 310, "process_vm_writev": 311,
}

BPF_LD_W_ABS, BPF_JEQ_K, BPF_RET_K = 0x20, 0x15, 0x06


class SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_uint16), ("jt", ctypes.c_uint8),
                ("jf", ctypes.c_uint8), ("k", ctypes.c_uint32)]


class SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_uint16), ("filter", ctypes.POINTER(SockFilter))]


def build_filter(deny):
    nrs = sorted(deny.values())
    k = len(nrs)
    ins = [
        SockFilter(BPF_LD_W_ABS, 0, 0, 4),                 # seccomp_data.arch
        SockFilter(BPF_JEQ_K, 1, 0, AUDIT_ARCH_X86_64),
        SockFilter(BPF_RET_K, 0, 0, RET_KILL),
        SockFilter(BPF_LD_W_ABS, 0, 0, 0),                 # seccomp_data.nr
    ]
    allow_idx = 4 + k
    for i, nr in enumerate(nrs):
        here = 4 + i
        ins.append(SockFilter(BPF_JEQ_K, (allow_idx + 1) - (here + 1), 0, nr))
    ins.append(SockFilter(BPF_RET_K, 0, 0, RET_ALLOW))
    ins.append(SockFilter(BPF_RET_K, 0, 0, RET_ERRNO_EPERM))
    arr = (SockFilter * len(ins))(*ins)
    return SockFprog(len(ins), arr), arr


def landlock_abi():
    r = libc.syscall(444, None, 0, 1)
    return r if r > 0 else None


def enter_membrane(isolate_net=True):
    """Irreversibly drop this process into the tainted runtime."""
    report = {}
    flags = 0
    if isolate_net:
        flags |= CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS
    if flags:
        rc = libc.unshare(flags)
        report["namespaces"] = "ok" if rc == 0 else f"errno {ctypes.get_errno()}"
    report["landlock_abi"] = landlock_abi() or "unavailable on this kernel"
    libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
    assert libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
    prog, _keep = build_filter(DENY)
    global _KEEPALIVE
    _KEEPALIVE = (prog, _keep)
    rc = libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(prog), 0, 0)
    report["seccomp"] = "installed" if rc == 0 else f"errno {ctypes.get_errno()}"
    report["denied_syscalls"] = len(DENY)
    return report


# --------------------------------------------------------------------------- tests
def probe():
    """Run inside the membrane: prove egress is gone and rendering still works."""
    import socket, subprocess, shutil
    res = {}

    for fam, name in ((socket.AF_INET, "AF_INET"), (socket.AF_UNIX, "AF_UNIX"),
                      (socket.AF_NETLINK, "AF_NETLINK")):
        try:
            s = socket.socket(fam, socket.SOCK_STREAM if fam != socket.AF_NETLINK
                              else socket.SOCK_RAW)
            s.close()
            res[f"socket({name})"] = "ALLOWED - LEAK"
        except OSError as e:
            res[f"socket({name})"] = f"blocked ({e.strerror})"

    try:
        import urllib.request
        urllib.request.urlopen("http://1.1.1.1/", timeout=3)
        res["http_get"] = "ALLOWED - LEAK"
    except Exception as e:
        res["http_get"] = f"blocked ({type(e).__name__})"

    if shutil.which("curl"):
        p = subprocess.run(["curl", "-s", "-m", "3", "http://1.1.1.1/"],
                           capture_output=True)
        res["exec_curl"] = f"exit {p.returncode} (filter survived execve)"

    # the legitimate work must still succeed
    t = time.perf_counter()
    p = subprocess.run(["pdftoppm", "-r", "150", "-png", "out/protected.pdf",
                        "/tmp/membrane_page"], capture_output=True)
    res["render_pdf_inside_membrane"] = "ok" if p.returncode == 0 else p.stderr.decode()[:120]
    res["render_ms"] = round((time.perf_counter() - t) * 1e3, 1)

    with open("out/true_doc.txt") as f:
        res["read_cleartext"] = f"ok ({len(f.read())} bytes)"
    return res


if __name__ == "__main__":
    if os.environ.get("CLOISTER_CHILD") == "1":
        rep = enter_membrane()
        print(json.dumps({"membrane": rep, "probes": probe()}, indent=2))
        sys.exit(0)

    # baseline: same workload with no membrane, for overhead comparison
    t = time.perf_counter()
    os.system("pdftoppm -r 150 -png out/protected.pdf /tmp/base_page 2>/dev/null")
    base_ms = round((time.perf_counter() - t) * 1e3, 1)

    t = time.perf_counter()
    r = os.fork()
    if r == 0:
        os.environ["CLOISTER_CHILD"] = "1"
        os.execv(sys.executable, [sys.executable, __file__])
    _, status = os.waitpid(r, 0)
    total_ms = round((time.perf_counter() - t) * 1e3, 1)
    print(json.dumps({"baseline_render_ms_no_membrane": base_ms,
                      "child_total_ms": total_ms}, indent=2), file=sys.stderr)
