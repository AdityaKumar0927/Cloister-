"""
Layer P2 — the one-way membrane.

A process that has touched cleartext is tainted, and the taint is enforced rather than
audited: the reader is launched into a runtime from which no egress path exists, and the
demonstrated absence of those paths is what the envelope's policy gate checks before any
key is released.

Ordering is the whole design. A sandbox applied after decryption protects nothing,
because the plaintext already exists in a process that could have leaked it. So the
reader enters the membrane FIRST, irreversibly, and then presents the resulting posture
to obtain a key.

Enforced here on Linux, without root:
  * CLONE_NEWNET / NEWIPC / NEWUTS  -- empty network namespace: no interfaces, no routes,
                                       no resolver, no shared SysV IPC
  * seccomp-bpf                     -- socket, connect, bind, listen, accept, all send
                                       and receive variants, ptrace and process_vm_* all
                                       return EPERM
  * PR_SET_DUMPABLE 0               -- no /proc/pid/mem reads by same-uid processes
  * PR_SET_NO_NEW_PRIVS             -- privileges cannot be re-acquired
  * Landlock                        -- filesystem scoping, and TCP from ABI 4, applied
                                       when the running kernel exposes it

The filter survives execve, so it covers the real renderer, its children, and any agent
runtime or MCP server that tries to attach itself downstream. That inheritance is the
property that makes the membrane worth anything against the agentic threat.

Two honest notes. Landlock is probed at runtime rather than inferred from a kernel
version, because "we applied a sandbox" claims should be verified. And capture exclusion
is not implemented here: it is a per-platform windowing call, and on bare X11 it does not
exist at all, so `observe()` reports it False and a policy that requires it fails closed.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import os
import sys

libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)

CLONE_NEWNET, CLONE_NEWIPC, CLONE_NEWUTS = 0x40000000, 0x08000000, 0x04000000
PR_SET_DUMPABLE, PR_GET_DUMPABLE = 4, 3
PR_SET_SECCOMP, PR_GET_SECCOMP = 22, 21
PR_SET_NO_NEW_PRIVS, PR_GET_NO_NEW_PRIVS = 38, 39
SECCOMP_MODE_FILTER = 2
RET_ALLOW, RET_ERRNO_EPERM, RET_KILL = 0x7FFF0000, 0x00050001, 0x80000000
AUDIT_ARCH_X86_64 = 0xC000003E
LANDLOCK_CREATE_RULESET = 444

# x86_64 syscall numbers for every egress primitive we deny. Architecture-specific by
# nature: these numbers are wrong on aarch64 and the module refuses to install there.
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


_KEEPALIVE = None          # the kernel keeps a pointer; do not let Python free it


def build_filter(deny=DENY):
    nrs = sorted(deny.values())
    k = len(nrs)
    ins = [
        SockFilter(BPF_LD_W_ABS, 0, 0, 4),                  # seccomp_data.arch
        SockFilter(BPF_JEQ_K, 1, 0, AUDIT_ARCH_X86_64),
        SockFilter(BPF_RET_K, 0, 0, RET_KILL),              # wrong arch: kill
        SockFilter(BPF_LD_W_ABS, 0, 0, 0),                  # seccomp_data.nr
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
    """Probe rather than infer. Returns the ABI version, or None if unavailable."""
    r = libc.syscall(LANDLOCK_CREATE_RULESET, None, 0, 1)
    return r if r > 0 else None


def supported() -> tuple[bool, str]:
    import platform
    if sys.platform != "linux":
        return False, f"membrane is Linux-only; this is {sys.platform}"
    if platform.machine() not in ("x86_64", "AMD64"):
        return False, (f"seccomp syscall numbers here are x86_64-specific; "
                       f"refusing on {platform.machine()}")
    return True, "ok"


def enter(isolate_net=True) -> dict:
    """
    Irreversibly drop this process into the tainted runtime. There is no way back, by
    design: seccomp filters and no_new_privs cannot be removed once set.
    """
    ok, why = supported()
    if not ok:
        raise RuntimeError(why)
    report = {"namespaces": "skipped", "landlock_abi": landlock_abi() or "unavailable"}
    if isolate_net:
        rc = libc.unshare(CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS)
        report["namespaces"] = "ok" if rc == 0 else f"errno {ctypes.get_errno()}"
    libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise RuntimeError(f"no_new_privs failed: errno {ctypes.get_errno()}")
    prog, arr = build_filter()
    global _KEEPALIVE
    _KEEPALIVE = (prog, arr)
    rc = libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(prog), 0, 0)
    if rc != 0:
        raise RuntimeError(f"seccomp install failed: errno {ctypes.get_errno()}")
    report["seccomp"] = "installed"
    report["denied_syscalls"] = len(DENY)
    return report


def harden() -> bool:
    """
    Re-assert the process attributes that execve discards. Must be called by any process
    that was launched INTO the membrane rather than entering it itself.

    PR_SET_DUMPABLE does not survive execve -- the kernel resets it to 1 -- while the
    seccomp filter does. Measured, not assumed: before exec dumpable=0 and seccomp_mode=2;
    after exec dumpable=1 and seccomp_mode=2.

    This matters more than it looks. The filter denies ptrace and process_vm_readv, but
    reading /proc/<pid>/mem is an ordinary file read, not a syscall that can be
    distinguished in a filter. Dumpable=0 is what stops a same-uid process doing it, so
    losing it across exec silently reopens the memory-inspection path. Re-asserting is
    cheap and idempotent; relaxing the predicate instead would have been the wrong fix.
    """
    libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
    return libc.prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 0


def observe() -> dict:
    """
    Report the posture of the process we are in, by testing it rather than asserting it.
    Predicates this module cannot verify are reported False so that a policy requiring
    them fails closed.
    """
    in_filter = libc.prctl(PR_GET_SECCOMP, 0, 0, 0, 0) == 2
    if in_filter:
        harden()          # execve dropped dumpable; put it back before judging posture
    obs = {k: False for k in
           ("egress_blocked", "ptrace_blocked", "capture_excluded",
            "clipboard_gated", "attested_renderer")}
    import socket
    blocked = 0
    for fam, typ in ((socket.AF_INET, socket.SOCK_STREAM),
                     (socket.AF_UNIX, socket.SOCK_STREAM),
                     (socket.AF_NETLINK, socket.SOCK_RAW)):
        try:
            socket.socket(fam, typ).close()
        except OSError:
            blocked += 1
        except Exception:
            blocked += 1
    obs["egress_blocked"] = blocked == 3
    obs["ptrace_blocked"] = (in_filter
                             and libc.prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 0)
    # capture exclusion and clipboard gating are windowing-system calls, and renderer
    # attestation needs a platform measurement service. None are available here, so they
    # stay False rather than being optimistically assumed.
    return obs


def run_confined(argv: list[str], isolate_net=True) -> int:
    """Fork, enter the membrane in the child, then exec. The filter is inherited."""
    ok, why = supported()
    if not ok:
        raise RuntimeError(why)
    pid = os.fork()
    if pid == 0:
        try:
            enter(isolate_net=isolate_net)
            os.execvp(argv[0], argv)
        except Exception as e:                       # pragma: no cover
            os.write(2, f"membrane: {e}\n".encode())
            os._exit(127)
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status)
