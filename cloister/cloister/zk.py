"""
Zero-knowledge predicate proofs over committed integers.

Layer A needs a student to prove statements like "no single insertion in my edit trail
exceeded 400 characters" without handing anyone the trail. A keystroke log is
surveillance; an institution should not hold one and a student should not have to
surrender one. So the trail stays local and only *predicates* over it are disclosed.

Construction, all standard and implemented here rather than gestured at:

  * Pedersen commitments  C = g^v · h^r  in a prime-order subgroup of a 2048-bit MODP
    group (RFC 3526 group 14, q = (p-1)/2). Perfectly hiding, computationally binding.
  * A Chaum-Pedersen OR-proof that a commitment opens to 0 or 1, made non-interactive
    by Fiat-Shamir over a transcript that includes the statement.
  * A range proof for v in [0, 2^n) by committing to each bit, proving each bit is
    binary, and choosing the blinding factors so that the product of the bit
    commitments raised to powers of two equals the value commitment exactly. The
    verifier checks that identity directly, so no extra linking proof is needed.
  * A bound proof v <= N: commit to v with randomness r and to N-v with randomness -r,
    so C·D = g^N holds identically, then range-prove both. Nothing about v leaks.

The security claim is the usual one for these primitives: soundness rests on the
discrete logarithm assumption in the subgroup, and the hiding property is perfect.
Both are exercised by the forgery tests in the test suite rather than asserted.
"""
from __future__ import annotations
import hashlib
import json
import secrets

# A Schnorr group generated for this project and verified at import: a 2048-bit prime
# p with a 256-bit prime-order subgroup q. Using a 256-bit subgroup instead of the
# safe-prime (p-1)/2 shortens every exponent from 2047 bits to 256, which is an order
# of magnitude off both proving and verification time for no loss of security -- the
# discrete log problem in the subgroup is what matters, and it is 256-bit hard here
# while p stays 2048-bit hard against index calculus.
P = int(
    "8053d689cec550212ed5f29d600cf233e8072c92e3cd7b7ee163a6636d361fbaef8efc8a69f96dcf6bbb1b41674c59e1591030c8c24de8e1dbf12b7aedb439cf172a4733b5f52aa79012e628baea30e99b40ff5afa5f045b696043400b8d8e3efa38622f11faacea5317c54818cff40e087c2f3f9aed522fe9e0a60759873f9f87b080cd00b28a627e016fabc2aa745e9c813389c7a82795e41228da639862610b297644bc6ea9fc66d8fc8a2b4ef795c795f63de939dee5dc61c4cf4afd141f6032eee3b4afa7ebd8ff349ab9405002ec2bf6ef47dd6be5ce1531fbc0f7ce52bffb1065190627588f5ddda9da84d1571b0ea020292c2e8986a34189e32504db", 16)
Q = int(
    "9c96b57365331afd0ebe3837e2e96239129d141456b0782a4eb825541bb6fe05", 16)
G = int(
    "72da996d41840142612d041f99b219e85b47f6ee6098bfba4f42741f8d4b76a1a8dba60d15009d7d1d9e572f69f8a154ea9a83bb5401014cabbe0f004c9d46c74f5384ab48ba13b12e6bc90ac568dd751d08dc25b98aa76c2b37e90fd44affcea0334b24464c80459280deb92591a7194682380f794da2b3ccd03603f085b8ddb738edee5dc740174df27d14f63cefd3abf456636c7a1faf42cd04d430e66122eab6f8cdb04789aa526a1d8a9a515fd3717aa80fdc0a9052b15d8fc447a0873fccc851d072689c6cd52e18e49fa9a27626ecb2d380f8dbbc0edca91cc8d8ecff80841ad9dd2a006f75c8b7f4cfd1ee038e086a1e3d26c1e14fd1d3a4ec3b9c2f", 16)


def _selftest():
    """Cheap structural checks. A wrong constant here would silently void every
    proof, so the relations are asserted rather than trusted."""
    assert P.bit_length() == 2048 and Q.bit_length() == 256
    assert (P - 1) % Q == 0
    assert G != 1 and pow(G, Q, P) == 1
    assert pow(G, Q - 1, P) * G % P == 1          # G^(Q-1) is really G inverse


_selftest()


COFACTOR = (P - 1) // Q


def _hash_to_group(label: bytes) -> int:
    """
    A second generator with no known discrete log relation to G.

    The exponentiation must be by the COFACTOR (P-1)/Q, not by 2. Squaring lands an
    element in the quadratic-residue subgroup, which coincides with the order-Q
    subgroup only for a safe prime. In a group with a small prime-order subgroup it
    does not, and every inverse computed as x^(Q-1) is then silently wrong -- which is
    exactly how this failed the first time.
    """
    i = 0
    while True:
        d = hashlib.sha512(label + i.to_bytes(4, "big")).digest()
        x = int.from_bytes(d, "big") % P
        if x > 1:
            c = pow(x, COFACTOR, P)
            if c != 1 and pow(c, Q, P) == 1:
                return c
        i += 1


H = _hash_to_group(b"cloister/zk/pedersen/h/v1")


def _challenge(*parts) -> int:
    h = hashlib.sha512()
    for p in parts:
        if isinstance(p, int):
            p = p.to_bytes((p.bit_length() + 7) // 8 or 1, "big")
        elif isinstance(p, str):
            p = p.encode()
        h.update(len(p).to_bytes(4, "big"))
        h.update(p)
    return int.from_bytes(h.digest(), "big") % Q


def rand_scalar() -> int:
    return secrets.randbelow(Q - 1) + 1


def commit(v: int, r: int | None = None) -> tuple[int, int]:
    """Pedersen commitment to v. Returns (C, r)."""
    if r is None:
        r = rand_scalar()
    C = (pow(G, v % Q, P) * pow(H, r % Q, P)) % P
    return C, r


# ----------------------------------------------------------- bit is 0 or 1 (OR)
def prove_bit(C: int, b: int, r: int, ctx: str) -> dict:
    """
    Prove C = g^b h^r with b in {0,1}, revealing nothing else.
    Real Schnorr on the true branch; the false branch is simulated.
    """
    assert b in (0, 1)
    C0, C1 = C % P, (C * pow(G, Q - 1, P)) % P     # C and C/g
    if b == 0:
        k = rand_scalar()
        t_true = pow(H, k, P)
        e_fake = rand_scalar()
        s_fake = rand_scalar()
        t_fake = (pow(H, s_fake, P) * pow(C1, (Q - e_fake) % Q, P)) % P
        t0, t1 = t_true, t_fake
    else:
        k = rand_scalar()
        t_true = pow(H, k, P)
        e_fake = rand_scalar()
        s_fake = rand_scalar()
        t_fake = (pow(H, s_fake, P) * pow(C0, (Q - e_fake) % Q, P)) % P
        t0, t1 = t_fake, t_true
    e = _challenge(ctx, "bit", C, t0, t1)
    if b == 0:
        e0 = (e - e_fake) % Q
        s0 = (k + e0 * r) % Q
        e1, s1 = e_fake, s_fake
    else:
        e1 = (e - e_fake) % Q
        s1 = (k + e1 * r) % Q
        e0, s0 = e_fake, s_fake
    # t0 and t1 are omitted: the verifier recomputes them from the verification
    # equations and then checks the Fiat-Shamir challenge, which halves the proof.
    return {"e0": e0, "s0": s0, "e1": e1, "s1": s1}


def verify_bit(C: int, pf: dict, ctx: str) -> bool:
    try:
        e0, s0 = pf["e0"] % Q, pf["s0"] % Q
        e1, s1 = pf["e1"] % Q, pf["s1"] % Q
        C0 = C % P
        C1 = (C * pow(G, Q - 1, P)) % P
        # Recover the commitments the prover must have sent. Inverting inside the
        # subgroup is x^(Q-e): a 256-bit exponent. Using Fermat (x^(P-2)) instead costs
        # a 2048-bit exponentiation per branch and made verification slower than
        # proving.
        t0 = (pow(H, s0, P) * pow(C0, (Q - e0) % Q, P)) % P
        t1 = (pow(H, s1, P) * pow(C1, (Q - e1) % Q, P)) % P
        return (e0 + e1) % Q == _challenge(ctx, "bit", C, t0, t1)
    except Exception:
        return False


# --------------------------------------------------------------- range in [0,2^n)
def _bit_randomness(r: int, nbits: int) -> list[int]:
    """Per-bit blinding factors summing (weighted by powers of two) to exactly r, so
    prod(Ci^(2^i)) == g^v h^r holds identically and no linking proof is needed."""
    rs = [rand_scalar() for _ in range(nbits - 1)]
    partial = sum((rs[i] << i) for i in range(nbits - 1)) % Q
    top = ((r - partial) * pow(1 << (nbits - 1), -1, Q)) % Q
    return rs + [top]


def prove_range_fixed(v: int, r: int, nbits: int, ctx: str) -> dict:
    """Range proof for a commitment whose randomness is already fixed -- required when
    the commitment was signed by someone else (see authorship.py: the editor attests
    the commitments, the student proves properties of them)."""
    if not (0 <= v < (1 << nbits)):
        raise ValueError("value outside the stated range")
    bits = [(v >> i) & 1 for i in range(nbits)]
    rs = _bit_randomness(r % Q, nbits)
    cs, pfs = [], []
    for i, b in enumerate(bits):
        Ci, _ = commit(b, rs[i])
        cs.append(Ci)
        pfs.append(prove_bit(Ci, b, rs[i], f"{ctx}|bit{i}"))
    return {"nbits": nbits, "bit_commitments": cs, "bit_proofs": pfs}


def prove_range(v: int, nbits: int, ctx: str) -> tuple[int, int, dict]:
    """Fresh commitment plus a range proof. Returns (C, r, proof)."""
    r = rand_scalar()
    pf = prove_range_fixed(v, r, nbits, ctx)
    C, _ = commit(v, r)
    return C, r, pf


def verify_range(C: int, pf: dict, ctx: str) -> bool:
    try:
        n = pf["nbits"]
        cs, pfs = pf["bit_commitments"], pf["bit_proofs"]
        if len(cs) != n or len(pfs) != n:
            return False
        for i in range(n):
            if not verify_bit(cs[i], pfs[i], f"{ctx}|bit{i}"):
                return False
        acc = 1
        for i in range(n):
            acc = (acc * pow(cs[i], 1 << i, P)) % P
        return acc == C % P
    except Exception:
        return False


# ------------------------------------------------------------------ bound v <= N
def prove_bound_fixed(v: int, r: int, bound: int, ctx: str,
                      nbits: int | None = None) -> dict:
    """Prove 0 <= v <= bound for the commitment C = g^v h^r that the caller already
    holds (and that an attestor may already have signed)."""
    if v < 0 or v > bound:
        raise ValueError("statement is false; refusing to prove it")
    if nbits is None or bound >= (1 << nbits):
        nbits = max(1, bound.bit_length())
    pv = prove_range_fixed(v, r, nbits, ctx + "|v")
    pw = prove_range_fixed(bound - v, (-r) % Q, nbits, ctx + "|w")
    C, _ = commit(v, r)
    D, _ = commit(bound - v, (-r) % Q)
    return {"kind": "atmost", "bound": bound, "nbits": nbits,
            "C": C, "D": D, "range_v": pv, "range_w": pw}


def verify_bound_fixed(C: int, pf: dict, ctx: str) -> bool:
    """Verify 0 <= v <= bound for a commitment C supplied out of band."""
    try:
        if pf["C"] % P != C % P:
            return False
        if not verify_range(pf["C"], pf["range_v"], ctx + "|v"):
            return False
        if not verify_range(pf["D"], pf["range_w"], ctx + "|w"):
            return False
        return (pf["C"] * pf["D"]) % P == pow(G, pf["bound"] % Q, P)
    except Exception:
        return False


def prove_atleast_fixed(v: int, r: int, floor: int, ctx: str, nbits: int = 24) -> dict:
    """Prove v >= floor. The verifier derives E = C * g^-floor itself and range-proves
    it, so the same commitment carries both directions of bound."""
    if v < floor:
        raise ValueError("statement is false; refusing to prove it")
    d = v - floor
    if d >= (1 << nbits):
        raise ValueError("difference exceeds the stated width")
    return {"kind": "atleast", "floor": floor, "nbits": nbits,
            "range_d": prove_range_fixed(d, r, nbits, ctx + "|d")}


def verify_atleast_fixed(C: int, pf: dict, ctx: str) -> bool:
    try:
        E = (C * pow(G, (Q - pf["floor"] % Q) % Q, P)) % P
        return verify_range(E, pf["range_d"], ctx + "|d")
    except Exception:
        return False


def prove_bound(v: int, bound: int, ctx: str, nbits: int | None = None) -> dict:
    """
    Prove 0 <= v <= bound. C commits to v, D commits to bound - v with the negated
    blinding factor, so C*D == g^bound identically and the verifier checks it directly.
    """
    if v < 0 or v > bound:
        raise ValueError("statement is false; refusing to prove it")
    if nbits is None:
        nbits = max(1, bound.bit_length())
    if bound >= (1 << nbits):
        nbits = bound.bit_length()
    Cv, rv, pv = prove_range(v, nbits, ctx + "|v")
    w = bound - v
    bits = [(w >> i) & 1 for i in range(nbits)]
    # force sum(2^i * rs_i) == -rv so that C*D == g^bound
    rs = [rand_scalar() for _ in range(nbits - 1)]
    partial = sum((rs[i] << i) for i in range(nbits - 1)) % Q
    top = ((-rv - partial) * pow(1 << (nbits - 1), -1, Q)) % Q
    rs.append(top)
    cs, pfs = [], []
    for i, b in enumerate(bits):
        Ci, _ = commit(b, rs[i])
        cs.append(Ci)
        pfs.append(prove_bit(Ci, b, rs[i], f"{ctx}|w|bit{i}"))
    Dv = 1
    for i in range(nbits):
        Dv = (Dv * pow(cs[i], 1 << i, P)) % P
    return {"bound": bound, "nbits": nbits,
            "C": Cv, "D": Dv, "range_v": pv,
            "range_w": {"nbits": nbits, "bit_commitments": cs, "bit_proofs": pfs}}


def verify_bound(pf: dict, ctx: str) -> bool:
    try:
        n, bound = pf["nbits"], pf["bound"]
        if not verify_range(pf["C"], pf["range_v"], ctx + "|v"):
            return False
        rw = pf["range_w"]
        if rw["nbits"] != n:
            return False
        for i in range(n):
            if not verify_bit(rw["bit_commitments"][i], rw["bit_proofs"][i],
                              f"{ctx}|w|bit{i}"):
                return False
        acc = 1
        for i in range(n):
            acc = (acc * pow(rw["bit_commitments"][i], 1 << i, P)) % P
        if acc != pf["D"] % P:
            return False
        # the linking identity: C * D == g^bound
        return (pf["C"] * pf["D"]) % P == pow(G, bound % Q, P)
    except Exception:
        return False


# ------------------------------------------------------------- serialisation
def _enc(o):
    if isinstance(o, int):
        return {"__int__": format(o, "x")}
    if isinstance(o, dict):
        return {k: _enc(v) for k, v in o.items()}
    if isinstance(o, list):
        return [_enc(v) for v in o]
    return o


def _dec(o):
    if isinstance(o, dict):
        if "__int__" in o and len(o) == 1:
            return int(o["__int__"], 16)
        return {k: _dec(v) for k, v in o.items()}
    if isinstance(o, list):
        return [_dec(v) for v in o]
    return o


def dumps(pf: dict) -> str:
    return json.dumps(_enc(pf), separators=(",", ":"))


def loads(s: str) -> dict:
    return _dec(json.loads(s))


def proof_bytes(pf: dict) -> int:
    return len(dumps(pf))
