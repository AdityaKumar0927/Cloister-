"""
Zero-knowledge predicate proofs: claims, and the subgroup bug that voided all of them.
"""
import hashlib
import sys
import time

sys.path.insert(0, "..")
sys.path.insert(0, ".")

from cloister import zk                                          # noqa: E402
from harness import claim, main, mutation, regression             # noqa: E402


# ----------------------------------------------------------------- the group itself
@regression("zk-subgroup-generator",
            bug="_hash_to_group squared into the quadratic-residue subgroup instead of "
                "exponentiating by the cofactor. In a 2048-bit prime with a 256-bit "
                "prime-order subgroup those are different groups, so every inverse "
                "computed as x^(Q-1) was silently wrong and no proof verified.",
            found_by="every predicate proof failing at once, with no error raised")
def zk_second_generator_is_in_the_prime_order_subgroup():
    assert pow(zk.H, zk.Q, zk.P) == 1, "H is not in the order-Q subgroup"
    assert zk.H != 1
    assert pow(zk.H, zk.Q - 1, zk.P) * zk.H % zk.P == 1, "H^(Q-1) is not H inverse"
    # and the property that makes it usable: a proof round-trips
    C, r = zk.commit(1)
    assert zk.verify_bit(C, zk.prove_bit(C, 1, r, "ctx"), "ctx")
    return {"H mod Q order": "1 (correct)", "cofactor bits": zk.COFACTOR.bit_length()}


@mutation("zk-subgroup-generator")
def _original_squared_into_the_wrong_subgroup():
    """The first implementation, restored verbatim: square instead of cofactor-exponentiate."""
    i = 0
    while True:
        d = hashlib.sha512(b"cloister/zk/pedersen/h/v1" + i.to_bytes(4, "big")).digest()
        x = int.from_bytes(d, "big") % zk.P
        if x > 1:
            h = pow(x, 2, zk.P)          # <-- the bug
            if h != 1:
                break
        i += 1
    assert pow(h, zk.Q, zk.P) == 1, "squaring did not land in the order-Q subgroup"

    # and the consequence: with that H, a correctly-constructed proof does not verify
    real_H = zk.H
    try:
        zk.H = h
        C, r = zk.commit(0)
        ok = zk.verify_bit(C, zk.prove_bit(C, 0, r, "ctx"), "ctx")
    finally:
        zk.H = real_H
    assert ok, "proofs built on the squared generator do not verify"


@claim("zk-proofs-verify", says="every predicate proof verifies on honest inputs")
def all_predicates_verify():
    out = {}
    C, r = zk.commit(7)
    assert zk.verify_range(C, zk.prove_range_fixed(7, r, 8, "r"), "r")
    out["range [0,2^8)"] = "verifies"

    C, r = zk.commit(120)
    assert zk.verify_bound_fixed(C, zk.prove_bound_fixed(120, r, 400, "b"), "b")
    out["bound v<=400"] = "verifies"

    C, r = zk.commit(5000)
    assert zk.verify_atleast_fixed(C, zk.prove_atleast_fixed(5000, r, 1800, "a"), "a")
    out["atleast v>=1800"] = "verifies"
    return out


@claim("zk-forgeries-rejected",
       says="7 of 7 forgery attempts are rejected, including context substitution")
def forgeries_rejected():
    C, r = zk.commit(1)
    good = zk.prove_bit(C, 1, r, "ctx")
    rejected = 0
    forgeries = [
        ("wrong context", lambda: zk.verify_bit(C, good, "other-ctx")),
        ("wrong commitment", lambda: zk.verify_bit((C * 3) % zk.P, good, "ctx")),
        ("tweak e0", lambda: zk.verify_bit(C, dict(good, e0=(good["e0"] + 1) % zk.Q), "ctx")),
        ("tweak s1", lambda: zk.verify_bit(C, dict(good, s1=(good["s1"] + 1) % zk.Q), "ctx")),
        ("zero out", lambda: zk.verify_bit(C, {k: 0 for k in good}, "ctx")),
        ("missing field", lambda: zk.verify_bit(C, {"e0": good["e0"]}, "ctx")),
    ]
    for _name, fn in forgeries:
        assert fn() is False, f"forgery accepted: {_name}"
        rejected += 1
    # the substantive one: a commitment to 2 must not be provable as a bit, even by a
    # prover who knows the opening and follows the protocol claiming b=1
    C2, r2 = zk.commit(2)
    bad = zk.prove_bit(C2, 1, r2, "ctx")
    assert zk.verify_bit(C2, bad, "ctx") is False, "a commitment to 2 verified as a bit"
    rejected += 1
    return {"forgeries rejected": f"{rejected}/7"}


@regression("zk-verify-exponent-size",
            bug="verification inverted group elements with Fermat's little theorem, "
                "pow(x, P-2, P) -- a 2048-bit exponent -- which made verifying slower "
                "than proving. Inside a prime-order subgroup the inverse is x^(Q-e), a "
                "256-bit exponent.",
            found_by="timing the verifier and the prover side by side")
def verify_is_not_slower_than_prove():
    C, r = zk.commit(1)
    reps = 60
    t0 = time.time()
    for _ in range(reps):
        pf = zk.prove_bit(C, 1, r, "ctx")
    t_prove = (time.time() - t0) / reps
    t0 = time.time()
    for _ in range(reps):
        zk.verify_bit(C, pf, "ctx")
    t_verify = (time.time() - t0) / reps
    assert t_verify < 1.6 * t_prove, (
        f"verify {t_verify * 1e3:.2f}ms vs prove {t_prove * 1e3:.2f}ms: the verifier is "
        f"doing large-exponent work")
    return {"prove": f"{t_prove * 1e3:.2f} ms/bit", "verify": f"{t_verify * 1e3:.2f} ms/bit",
            "ratio": round(t_verify / t_prove, 2)}


@mutation("zk-verify-exponent-size")
def _original_used_a_2048_bit_exponent():
    """Fermat inversion, as originally written."""
    C, r = zk.commit(1)
    pf = zk.prove_bit(C, 1, r, "ctx")

    def verify_fermat(C, pf, ctx):
        e0, s0, e1, s1 = pf["e0"], pf["s0"], pf["e1"], pf["s1"]
        C0 = C % zk.P
        C1 = (C * pow(zk.G, zk.Q - 1, zk.P)) % zk.P
        t0 = (pow(zk.H, s0, zk.P) * pow(pow(C0, e0, zk.P), zk.P - 2, zk.P)) % zk.P
        t1 = (pow(zk.H, s1, zk.P) * pow(pow(C1, e1, zk.P), zk.P - 2, zk.P)) % zk.P
        return (e0 + e1) % zk.Q == zk._challenge(ctx, "bit", C, t0, t1)

    reps = 25
    t0 = time.time()
    for _ in range(reps):
        zk.prove_bit(C, 1, r, "ctx")
    t_prove = (time.time() - t0) / reps
    t0 = time.time()
    for _ in range(reps):
        assert verify_fermat(C, pf, "ctx")
    t_verify = (time.time() - t0) / reps
    assert t_verify < 1.6 * t_prove, (
        f"Fermat verify {t_verify * 1e3:.2f}ms vs prove {t_prove * 1e3:.2f}ms")


@claim("zk-proof-size", says="a full authorship credential is a few tens of KB, not MB")
def proof_size():
    C, r = zk.commit(5000)
    pf = zk.prove_atleast_fixed(5000, r, 1800, "a", nbits=24)
    n = zk.proof_bytes(pf)
    assert 2_000 < n < 60_000, f"unexpected proof size {n}"
    round_tripped = zk.loads(zk.dumps(pf))
    assert zk.verify_atleast_fixed(C, round_tripped, "a"), "proof broke in serialisation"
    return {"atleast proof (24 bit)": f"{n / 1024:.1f} KB", "serialisation": "round-trips"}


if __name__ == "__main__":
    main(__doc__)
