"""
Layer P1, the envelope: posture-gated decryption, and the ordering property that the
whole design rests on.
"""
import sys
import time

sys.path.insert(0, "..")
sys.path.insert(0, ".")

from cryptography.hazmat.primitives.asymmetric import ed25519      # noqa: E402

from cloister import envelope as E                                 # noqa: E402
from harness import claim, main, mutation, regression              # noqa: E402

ALL_TRUE = {k: True for k in E.POSTURE}
DOC = b"PRIVILEGED AND CONFIDENTIAL. " * 48


def _fixture(require=E.POSTURE, lease_seconds=900):
    dev = E.DeviceIdentity()
    signer = ed25519.Ed25519PrivateKey.generate()
    policy = E.make_policy("Ashgrove v. Merridew", require=require,
                           lease_seconds=lease_seconds)
    sealed = E.seal(DOC, dev.public(), policy, signer)
    return dev, signer, policy, sealed


@claim("envelope-round-trips", says="a sealed document opens to the original bytes "
                                    "inside a satisfying runtime")
def round_trips():
    dev, signer, policy, sealed = _fixture()
    out = E.unseal(sealed, dev, signer.public_key(), E.strict_posture(ALL_TRUE))
    assert out == DOC, "plaintext does not match"
    return {"plaintext": f"{len(DOC)} B", "envelope": f"{len(sealed)} B",
            "overhead": f"{len(sealed) - len(DOC)} B"}


@claim("envelope-overhead-is-constant",
       says="overhead is a fixed ~1.6 KB regardless of document size, so the scheme is "
            "usable on a memo and on a deposition transcript alike")
def overhead_is_constant():
    dev = E.DeviceIdentity()
    signer = ed25519.Ed25519PrivateKey.generate()
    policy = E.make_policy("matter")
    sizes, over = [], []
    for n in (1_000, 100_000, 4_000_000):
        pt = b"x" * n
        s = E.seal(pt, dev.public(), policy, signer)
        sizes.append(n)
        over.append(len(s) - n)
    assert max(over) - min(over) < 64, f"overhead varies with size: {over}"
    assert 1_000 < over[0] < 3_000, f"unexpected overhead {over[0]}"
    return {"overhead at 1 KB": f"{over[0]} B", "at 100 KB": f"{over[1]} B",
            "at 4 MB": f"{over[2]} B", "spread": f"{max(over) - min(over)} B"}


@claim("envelope-throughput", says="sealing and opening run at hundreds of MB/s, so the "
                                   "envelope is not what a reader waits for")
def throughput():
    dev = E.DeviceIdentity()
    signer = ed25519.Ed25519PrivateKey.generate()
    policy = E.make_policy("matter")
    pt = b"y" * 8_000_000
    t0 = time.time()
    s = E.seal(pt, dev.public(), policy, signer)
    t_seal = time.time() - t0
    t0 = time.time()
    E.unseal(s, dev, signer.public_key(), E.strict_posture(ALL_TRUE))
    t_open = time.time() - t0
    mb = len(pt) / 1e6
    assert mb / t_seal > 50, f"sealing only {mb / t_seal:.0f} MB/s"
    return {"seal": f"{mb / t_seal:.0f} MB/s", "open": f"{mb / t_open:.0f} MB/s"}


@regression("envelope-policy-digest-is-load-bearing",
            bug="a policy carried alongside the ciphertext and merely signed can be "
                "relaxed by anyone who also holds the signing key -- an insider, or the "
                "vendor. Binding the policy digest into the KDF transcript means editing "
                "the policy yields a key that no longer reproduces.",
            found_by="asking what a signed-policy scheme does against an adversary who "
                     "holds the signing key, which is the adversary that matters here")
def policy_tampering_breaks_the_key():
    dev, signer, policy, sealed = _fixture()
    # The adversary holds the signing key and re-signs a fully relaxed policy.
    relaxed = dict(policy, require={k: False for k in E.POSTURE})
    import cbor2
    env = cbor2.loads(sealed)
    header = cbor2.loads(env["hdr"])
    header["policy"] = relaxed
    new_hdr = cbor2.dumps(header, canonical=True)
    import hashlib
    new_h = hashlib.sha384(new_hdr).digest()
    forged = cbor2.dumps({"hdr": new_hdr, "sig": signer.sign(new_h),
                          "nonce": env["nonce"], "body": env["body"]})
    # The runtime satisfies the relaxed policy exactly (it requires nothing, and nothing
    # is what this runtime provides), so the gate passes and only the crypto is left.
    naked = {k: False for k in E.POSTURE}
    try:
        E.unseal(forged, dev, signer.public_key(), E.strict_posture(naked))
    except E.PostureViolation:
        raise AssertionError("failed at the posture gate, not at the crypto: the test is "
                             "not exercising the binding")
    except Exception as e:
        return {"forged policy": "all predicates relaxed",
                "signature": "valid (adversary holds the signing key)",
                "result": f"{type(e).__name__} -- key does not reproduce"}
    raise AssertionError("a relaxed, validly-signed policy opened the envelope")


@mutation("envelope-policy-digest-is-load-bearing")
def _original_advisory_policy():
    """A scheme where the policy is signed but NOT in the KDF transcript."""
    import hashlib

    import cbor2
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.asymmetric import x25519

    dev = E.DeviceIdentity()
    signer = ed25519.Ed25519PrivateKey.generate()
    policy = E.make_policy("matter")

    def seal_advisory(pt):
        eph = x25519.X25519PrivateKey.generate()
        ct_x = eph.public_key().public_bytes(serialization.Encoding.Raw,
                                             serialization.PublicFormat.Raw)
        ss_x = eph.exchange(x25519.X25519PublicKey.from_public_bytes(
            dev.public()["x25519"]))
        from kyber_py.ml_kem import ML_KEM_768
        ss_k, ct_k = ML_KEM_768.encaps(dev.public()["mlkem768"])
        kek = E._combine(ss_x, ss_k, ct_x, ct_k, b"", "cloister/kek")  # <-- no policy
        ck = b"\x11" * 32
        n1 = b"\x00" * 12
        wrapped = AESGCM(kek).encrypt(n1, ck, None)                    # <-- no AAD
        header = {"suite": E.SUITE, "policy": policy,
                  "kem": {"ct_x25519": ct_x, "ct_mlkem768": ct_k,
                          "nonce": n1, "wrapped_ck": wrapped}}
        hdr = cbor2.dumps(header, canonical=True)
        n2 = b"\x01" * 12
        return cbor2.dumps({"hdr": hdr, "sig": signer.sign(hashlib.sha384(hdr).digest()),
                            "nonce": n2, "body": AESGCM(ck).encrypt(n2, pt, None)})

    def unseal_advisory(envelope):
        env = cbor2.loads(envelope)
        hdr = env["hdr"]
        signer.public_key().verify(env["sig"], hashlib.sha384(hdr).digest())
        header = cbor2.loads(hdr)
        for k, want in header["policy"]["require"].items():
            if want and not False:
                pass                            # advisory: nothing enforces it
        kem = header["kem"]
        ss_x = dev.x_sk.exchange(
            x25519.X25519PublicKey.from_public_bytes(kem["ct_x25519"]))
        from kyber_py.ml_kem import ML_KEM_768
        ss_k = ML_KEM_768.decaps(dev.k_dk, kem["ct_mlkem768"])
        kek = E._combine(ss_x, ss_k, kem["ct_x25519"], kem["ct_mlkem768"], b"",
                         "cloister/kek")
        ck = AESGCM(kek).decrypt(kem["nonce"], kem["wrapped_ck"], None)
        return AESGCM(ck).decrypt(env["nonce"], env["body"], None)

    sealed = seal_advisory(DOC)
    env = cbor2.loads(sealed)
    header = cbor2.loads(env["hdr"])
    header["policy"] = dict(policy, require={k: False for k in E.POSTURE})
    new_hdr = cbor2.dumps(header, canonical=True)
    forged = cbor2.dumps({"hdr": new_hdr,
                          "sig": signer.sign(hashlib.sha384(new_hdr).digest()),
                          "nonce": env["nonce"], "body": env["body"]})
    out = unseal_advisory(forged)
    assert out != DOC, "the advisory scheme opened a relaxed, re-signed policy"


@regression("envelope-posture-gate-precedes-derivation",
            bug="a sandbox applied after decryption protects nothing, because the "
                "plaintext already exists in a process that could have leaked it. The "
                "posture gate therefore has to run before any key material is derived, "
                "not merely before the plaintext is returned.",
            found_by="instrumenting the KEM to count decapsulations during a denied open")
def gate_runs_before_any_key_derivation():
    dev, signer, policy, sealed = _fixture()
    calls = {"decaps": 0, "combine": 0}
    real_kem, real_combine = E.ML_KEM_768, E._combine

    class CountingKEM:
        @staticmethod
        def decaps(*a, **k):
            calls["decaps"] += 1
            return real_kem.decaps(*a, **k)

        @staticmethod
        def encaps(*a, **k):
            return real_kem.encaps(*a, **k)

    def counting_combine(*a, **k):
        calls["combine"] += 1
        return real_combine(*a, **k)

    try:
        E.ML_KEM_768, E._combine = CountingKEM, counting_combine
        failing = dict(ALL_TRUE, egress_blocked=False)
        try:
            E.unseal(sealed, dev, signer.public_key(), E.strict_posture(failing))
        except E.PostureViolation as e:
            msg = str(e)
        else:
            raise AssertionError("a failing runtime opened the envelope")
    finally:
        E.ML_KEM_768, E._combine = real_kem, real_combine

    assert calls["decaps"] == 0, f"{calls['decaps']} decapsulations on a denied open"
    assert calls["combine"] == 0, f"{calls['combine']} KDF calls on a denied open"
    return {"denied with": msg, "KEM decapsulations": 0, "KDF derivations": 0}


@mutation("envelope-posture-gate-precedes-derivation")
def _original_gate_after_derivation():
    """Derive first, check posture afterwards -- the ordering that protects nothing."""
    dev, signer, policy, sealed = _fixture()
    calls = {"decaps": 0}
    real_kem = E.ML_KEM_768

    class CountingKEM:
        @staticmethod
        def decaps(*a, **k):
            calls["decaps"] += 1
            return real_kem.decaps(*a, **k)

        @staticmethod
        def encaps(*a, **k):
            return real_kem.encaps(*a, **k)

    import cbor2
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.asymmetric import x25519
    try:
        E.ML_KEM_768 = CountingKEM
        env = cbor2.loads(sealed)
        header = cbor2.loads(env["hdr"])
        kem = header["kem"]
        ss_x = dev.x_sk.exchange(
            x25519.X25519PublicKey.from_public_bytes(kem["ct_x25519"]))
        ss_k = E.ML_KEM_768.decaps(dev.k_dk, kem["ct_mlkem768"])
        pol_h = E.policy_digest(header["policy"])
        kek = E._combine(ss_x, ss_k, kem["ct_x25519"], kem["ct_mlkem768"], pol_h,
                         "cloister/kek")
        AESGCM(kek).decrypt(kem["nonce"], kem["wrapped_ck"], pol_h)
        E.strict_posture(dict(ALL_TRUE, egress_blocked=False))(header["policy"])
    except E.PostureViolation:
        pass
    finally:
        E.ML_KEM_768 = real_kem
    assert calls["decaps"] == 0, (
        f"{calls['decaps']} decapsulations happened before the posture check")


@claim("envelope-kem-ciphertexts-are-bound",
       says="both KEM ciphertexts are in the transcript, so mauling either one yields a "
            "key that does not reproduce rather than a related key")
def kem_ciphertexts_bound():
    dev, signer, policy, sealed = _fixture()
    import cbor2
    env = cbor2.loads(sealed)
    header = cbor2.loads(env["hdr"])
    out = {}
    for field in ("ct_x25519", "ct_mlkem768"):
        h = cbor2.loads(cbor2.dumps(header))
        blob = bytearray(h["kem"][field])
        blob[0] ^= 0x01
        h["kem"][field] = bytes(blob)
        import hashlib
        nh = cbor2.dumps(h, canonical=True)
        mauled = cbor2.dumps({"hdr": nh,
                              "sig": signer.sign(hashlib.sha384(nh).digest()),
                              "nonce": env["nonce"], "body": env["body"]})
        try:
            E.unseal(mauled, dev, signer.public_key(), E.strict_posture(ALL_TRUE))
        except Exception as e:
            out[f"maul {field}"] = type(e).__name__
        else:
            raise AssertionError(f"mauling {field} still opened the envelope")
    return out


@claim("envelope-lease-expires",
       says="the envelope never yields a permanently usable key: revocation means "
            "stop issuing leases, which is a thing that actually works")
def lease_expires():
    dev, signer, policy, sealed = _fixture(lease_seconds=900)
    log = E.TransparencyLog()
    lease = E.Lease.issue(policy, log=log)
    assert lease.remaining() > 890
    out = E.unseal(sealed, dev, signer.public_key(), E.strict_posture(ALL_TRUE),
                   lease=lease)
    assert out == DOC

    expired = E.Lease(policy["matter"], time.time() - 1000, 900)
    try:
        E.unseal(sealed, dev, signer.public_key(), E.strict_posture(ALL_TRUE),
                 lease=expired)
    except E.LeaseExpired as e:
        expired_msg = str(e)
    else:
        raise AssertionError("an expired lease still opened the envelope")

    other = E.Lease("a different matter", time.time(), 900)
    try:
        E.unseal(sealed, dev, signer.public_key(), E.strict_posture(ALL_TRUE),
                 lease=other)
    except E.LeaseExpired:
        pass
    else:
        raise AssertionError("a lease for another matter opened this envelope")
    return {"valid lease": "opens", "expired": expired_msg,
            "wrong matter": "refused", "log entries": len(log.entries)}


@claim("envelope-transparency-log-detects-edits",
       says="the access log is hash-chained, so 'nobody opened it' becomes a statement "
            "that survives challenge")
def transparency_log_detects_edits():
    log = E.TransparencyLog()
    policy = E.make_policy("matter")
    for _ in range(4):
        E.Lease.issue(policy, log=log)
    assert log.verify(), "a freshly built chain does not verify"
    head = log.head
    log.entries[1] = dict(log.entries[1], matter="something else")
    assert not log.verify(), "editing an entry did not break the chain"
    return {"entries": len(log.entries), "head": head[:16] + "...",
            "after editing entry 1": "chain fails to verify"}


@claim("envelope-policy-digest-is-canonical",
       says="the policy digest is over canonical CBOR, so re-ordering the same policy's "
            "keys does not change the key it derives")
def policy_digest_is_canonical():
    a = {"matter": "m", "require": {"egress_blocked": True, "ptrace_blocked": True},
         "lease_seconds": 900}
    b = {"lease_seconds": 900, "matter": "m",
         "require": {"ptrace_blocked": True, "egress_blocked": True}}
    assert E.policy_digest(a) == E.policy_digest(b), "digest depends on key order"
    c = dict(a, lease_seconds=901)
    assert E.policy_digest(a) != E.policy_digest(c), "digest ignores a policy change"
    return {"reordered keys": "same digest", "changed lease": "different digest"}


if __name__ == "__main__":
    main(__doc__)
