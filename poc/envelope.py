#!/usr/bin/env python3
"""
CLOISTER — Layer P (Prevent), part 1: the Envelope.

A hybrid post-quantum sealed container whose content key is bound to a *runtime
posture policy*, not to a user identity. Concretely:

    ss  = HKDF( ss_X25519 || ss_MLKEM768 || ct_X25519 || ct_MLKEM768 || H(policy) )
    KW  = AES-256-GCM(ss)      wraps the content key, AAD = H(policy)
    CT  = AES-256-GCM(CK)      wraps the document,    AAD = H(header)

Binding both ciphertexts and the policy digest into the KDF transcript follows the
X-Wing / TLS hybrid-design rule: the combiner is secure if *either* KEM survives,
and the policy digest cannot be swapped without destroying the key.

Why post-quantum matters here specifically: privileged legal material, sealed court
filings and embargoed research have confidentiality horizons of 20-70 years. An
adversary who captures an envelope today and decrypts it in 2045 has still breached
privilege. This is the textbook harvest-now-decrypt-later target.
"""
import hashlib, hmac, json, os, secrets, statistics, time
import cbor2
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from kyber_py.ml_kem import ML_KEM_768

SUITE = "CLOISTER-v1-X25519+MLKEM768-AES256GCM-SHA384"


# --------------------------------------------------------------------- identities
class DeviceIdentity:
    """In production both private keys are non-exportable and sealed to the platform
    root of trust (TPM 2.0 policy session / Secure Enclave / StrongBox), so possession
    of the key implies execution on an attested device."""

    def __init__(self):
        self.x_sk = x25519.X25519PrivateKey.generate()
        self.k_ek, self.k_dk = ML_KEM_768.keygen()

    def public(self):
        return {
            "x25519": self.x_sk.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw),
            "mlkem768": self.k_ek,
        }


def policy_digest(policy):
    return hashlib.sha384(cbor2.dumps(policy, canonical=True)).digest()


def combine(ss_x, ss_k, ct_x, ct_k, pol_h, label):
    return HKDF(algorithm=hashes.SHA384(), length=32, salt=None,
                info=label.encode()).derive(
        ss_x + ss_k + ct_x + ct_k + pol_h + SUITE.encode())


# ------------------------------------------------------------------------ sealing
def seal(plaintext, recipient_pub, policy, signer):
    pol_h = policy_digest(policy)
    eph = x25519.X25519PrivateKey.generate()
    ct_x = eph.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ss_x = eph.exchange(x25519.X25519PublicKey.from_public_bytes(recipient_pub["x25519"]))
    ss_k, ct_k = ML_KEM_768.encaps(recipient_pub["mlkem768"])

    kek = combine(ss_x, ss_k, ct_x, ct_k, pol_h, "cloister/kek")
    ck = secrets.token_bytes(32)
    n1 = secrets.token_bytes(12)
    wrapped = AESGCM(kek).encrypt(n1, ck, pol_h)

    header = {
        "suite": SUITE,
        "policy": policy,
        "kem": {"ct_x25519": ct_x, "ct_mlkem768": ct_k, "nonce": n1, "wrapped_ck": wrapped},
    }
    hdr_bytes = cbor2.dumps(header, canonical=True)
    hdr_h = hashlib.sha384(hdr_bytes).digest()
    n2 = secrets.token_bytes(12)
    body = AESGCM(ck).encrypt(n2, plaintext, hdr_h)
    sig = signer.sign(hdr_h)          # production: ML-DSA-65 alongside Ed25519
    return cbor2.dumps({"hdr": hdr_bytes, "sig": sig, "nonce": n2, "body": body})


def unseal(envelope, device, verify_key, posture_prover):
    env = cbor2.loads(envelope)
    hdr_bytes = env["hdr"]
    hdr_h = hashlib.sha384(hdr_bytes).digest()
    verify_key.verify(env["sig"], hdr_h)
    header = cbor2.loads(hdr_bytes)
    policy = header["policy"]

    # ---- posture gate: refuse to even derive the KEK unless the live runtime
    # ---- satisfies the policy. This is the whole point of the design.
    posture_prover(policy)

    pol_h = policy_digest(policy)
    kem = header["kem"]
    ss_x = device.x_sk.exchange(x25519.X25519PublicKey.from_public_bytes(kem["ct_x25519"]))
    ss_k = ML_KEM_768.decaps(device.k_dk, kem["ct_mlkem768"])
    kek = combine(ss_x, ss_k, kem["ct_x25519"], kem["ct_mlkem768"], pol_h, "cloister/kek")
    ck = AESGCM(kek).decrypt(kem["nonce"], kem["wrapped_ck"], pol_h)
    return AESGCM(ck).decrypt(env["nonce"], env["body"], hdr_h)


# --------------------------------------------------------------- posture gate demo
class PostureViolation(Exception):
    pass


def strict_posture(observed):
    def prove(policy):
        req = policy["require"]
        for k, want in req.items():
            got = observed.get(k)
            if got != want:
                raise PostureViolation(f"{k}: required {want!r}, observed {got!r}")
    return prove


# ------------------------------------------------------------------------ measure
def bench():
    dev = DeviceIdentity()
    sk = ed25519.Ed25519PrivateKey.generate()
    pol = {
        "matter": "17-CV-4821",
        "require": {
            "egress_blocked": True,      # no route to any network namespace peer
            "ptrace_blocked": True,
            "capture_excluded": True,    # window excluded from screen capture / Recall
            "clipboard_gated": True,
            "attested_renderer": True,   # measured binary matches the pinned digest
        },
        "lease_seconds": 900,
        "not_after": "2027-01-01T00:00:00Z",
        "fingerprint_seed_id": "R-0001-adi",
        "transparency_log": "https://log.cloister.example/2026",
    }
    good = {k: True for k in pol["require"]}

    out = {"suite": SUITE, "sizes": {}, "timings_ms": {}, "posture": {}}

    t = time.perf_counter(); DeviceIdentity(); out["timings_ms"]["device_keygen"] = round((time.perf_counter()-t)*1e3, 2)

    for label, size in (("1KB", 1024), ("100KB", 100*1024), ("10MB", 10*1024*1024)):
        pt = os.urandom(size)
        ts, tu = [], []
        reps = 20 if size <= 100*1024 else 3
        for _ in range(reps):
            t = time.perf_counter(); env = seal(pt, dev.public(), pol, sk); ts.append(time.perf_counter()-t)
            t = time.perf_counter(); got = unseal(env, dev, sk.public_key(), strict_posture(good)); tu.append(time.perf_counter()-t)
            assert got == pt
        out["sizes"][label] = {"plaintext": size, "envelope": len(env),
                              "overhead_bytes": len(env) - size}
        out["timings_ms"][f"seal_{label}"] = round(statistics.median(ts)*1e3, 2)
        out["timings_ms"][f"unseal_{label}"] = round(statistics.median(tu)*1e3, 2)
        if size == 10*1024*1024:
            out["timings_ms"]["throughput_MBps_unseal"] = round(10/statistics.median(tu), 1)

    # posture gate must FAIL closed on every single violated predicate
    env = seal(b"privileged", dev.public(), pol, sk)
    for k in pol["require"]:
        bad = dict(good); bad[k] = False
        try:
            unseal(env, dev, sk.public_key(), strict_posture(bad))
            out["posture"][k] = "FAIL-OPEN (bug)"
        except PostureViolation as e:
            out["posture"][k] = f"denied: {e}"

    # policy tampering must destroy the key even with a valid device key
    env2 = cbor2.loads(env)
    h = cbor2.loads(env2["hdr"]); h["policy"]["require"]["egress_blocked"] = False
    env2["hdr"] = cbor2.dumps(h, canonical=True)
    try:
        unseal(cbor2.dumps(env2), dev, sk.public_key(), strict_posture(good))
        out["policy_tamper"] = "FAIL-OPEN (bug)"
    except Exception as e:
        out["policy_tamper"] = f"rejected at {type(e).__name__}"

    out["pq_params"] = {"mlkem768_ek": 1184, "mlkem768_dk": 2400, "mlkem768_ct": 1088,
                        "x25519_pk_ct": 32, "shared_secret": 32}
    return out


if __name__ == "__main__":
    print(json.dumps(bench(), indent=2))
