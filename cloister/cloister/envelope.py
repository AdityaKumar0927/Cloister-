"""
Layer P1 — the envelope.

A hybrid post-quantum sealed container whose content key is bound to a *runtime posture
policy* rather than to a user identity:

    ss  = HKDF-SHA384( ss_X25519 ‖ ss_MLKEM768 ‖ ct_X25519 ‖ ct_MLKEM768 ‖ H(policy) )
    KW  = AES-256-GCM(ss)  wraps the content key,  AAD = H(policy)
    CT  = AES-256-GCM(CK)  wraps the document,     AAD = H(header)

Two design points that are easy to get wrong.

The policy digest is *load-bearing*, not advisory. It appears inside the KDF transcript,
so editing the policy does not yield a permissive envelope -- it yields a key that no
longer reproduces. That holds even against an adversary who also controls the signing
key, which is the case a signed-policy scheme fails. There is a test for exactly that.

Both KEM ciphertexts are bound into the transcript, following the same rule as the TLS
hybrid designs: the combiner is secure if *either* primitive survives, and without the
binding an adversary who can maul one ciphertext can produce a related key.

Why post-quantum at all for documents: privileged legal material, sealed filings and
embargoed research have confidentiality horizons measured in decades, and an envelope is
a self-contained ciphertext an adversary can simply keep. That is the textbook
harvest-now-decrypt-later target.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time

import cbor2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from kyber_py.ml_kem import ML_KEM_768

SUITE = "CLOISTER-v1-X25519+MLKEM768-AES256GCM-SHA384"

# The posture predicates a policy may require. Every one must be demonstrated by the
# runtime before any key material is derived.
POSTURE = (
    "egress_blocked",       # no route out of the reader's network namespace
    "ptrace_blocked",       # no debugger, no /proc/pid/mem
    "capture_excluded",     # window withheld from screen capture and OS assistants
    "clipboard_gated",      # clipboard writes denied or watermarked
    "attested_renderer",    # measured binary matches the pinned digest
)


class PostureViolation(Exception):
    """Raised before any key derivation when the runtime fails the policy."""


class LeaseExpired(Exception):
    pass


# --------------------------------------------------------------------- identities
class DeviceIdentity:
    """
    A device keypair pair: X25519 for the classical half, ML-KEM-768 for the
    post-quantum half.

    In deployment both private keys are non-exportable and sealed to the platform root
    of trust -- a TPM 2.0 policy session, the Secure Enclave, StrongBox -- so possession
    of the key implies execution on an attested device. Here they are ordinary keys in
    memory, which is the one thing this module cannot demonstrate on its own.
    """

    def __init__(self):
        self.x_sk = x25519.X25519PrivateKey.generate()
        self.k_ek, self.k_dk = ML_KEM_768.keygen()

    def public(self) -> dict:
        return {
            "x25519": self.x_sk.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw),
            "mlkem768": self.k_ek,
        }

    def export_public(self) -> bytes:
        return cbor2.dumps(self.public(), canonical=True)


def policy_digest(policy: dict) -> bytes:
    return hashlib.sha384(cbor2.dumps(policy, canonical=True)).digest()


def _combine(ss_x: bytes, ss_k: bytes, ct_x: bytes, ct_k: bytes,
             pol_h: bytes, label: str) -> bytes:
    return HKDF(algorithm=hashes.SHA384(), length=32, salt=None,
                info=label.encode()).derive(
        ss_x + ss_k + ct_x + ct_k + pol_h + SUITE.encode())


def make_policy(matter: str, require=POSTURE, lease_seconds=900,
                not_after: str | None = None, fingerprint_seed_id: str | None = None,
                transparency_log: str | None = None) -> dict:
    return {
        "matter": matter,
        "require": {k: True for k in require},
        "lease_seconds": int(lease_seconds),
        "not_after": not_after or "2030-01-01T00:00:00Z",
        "fingerprint_seed_id": fingerprint_seed_id or "unassigned",
        "transparency_log": transparency_log or "",
    }


# ------------------------------------------------------------------------ sealing
def seal(plaintext: bytes, recipient_pub: dict, policy: dict,
         signer: ed25519.Ed25519PrivateKey) -> bytes:
    pol_h = policy_digest(policy)
    eph = x25519.X25519PrivateKey.generate()
    ct_x = eph.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ss_x = eph.exchange(
        x25519.X25519PublicKey.from_public_bytes(recipient_pub["x25519"]))
    ss_k, ct_k = ML_KEM_768.encaps(recipient_pub["mlkem768"])

    kek = _combine(ss_x, ss_k, ct_x, ct_k, pol_h, "cloister/kek")
    ck = secrets.token_bytes(32)
    n1 = secrets.token_bytes(12)
    wrapped = AESGCM(kek).encrypt(n1, ck, pol_h)

    header = {"suite": SUITE, "policy": policy,
              "kem": {"ct_x25519": ct_x, "ct_mlkem768": ct_k,
                      "nonce": n1, "wrapped_ck": wrapped}}
    hdr = cbor2.dumps(header, canonical=True)
    hdr_h = hashlib.sha384(hdr).digest()
    n2 = secrets.token_bytes(12)
    body = AESGCM(ck).encrypt(n2, plaintext, hdr_h)
    return cbor2.dumps({"hdr": hdr, "sig": signer.sign(hdr_h),
                        "nonce": n2, "body": body})


def unseal(envelope: bytes, device: DeviceIdentity,
           verify_key: ed25519.Ed25519PublicKey, prove_posture,
           lease=None) -> bytes:
    """
    prove_posture(policy) must raise PostureViolation unless the live runtime satisfies
    every predicate. It is called BEFORE any key material is derived: a sandbox applied
    after decryption protects nothing, because the plaintext already exists somewhere
    that could have leaked it.
    """
    env = cbor2.loads(envelope)
    hdr = env["hdr"]
    hdr_h = hashlib.sha384(hdr).digest()
    verify_key.verify(env["sig"], hdr_h)
    header = cbor2.loads(hdr)
    policy = header["policy"]

    prove_posture(policy)
    if lease is not None:
        lease.check(policy)

    pol_h = policy_digest(policy)
    kem = header["kem"]
    ss_x = device.x_sk.exchange(
        x25519.X25519PublicKey.from_public_bytes(kem["ct_x25519"]))
    ss_k = ML_KEM_768.decaps(device.k_dk, kem["ct_mlkem768"])
    kek = _combine(ss_x, ss_k, kem["ct_x25519"], kem["ct_mlkem768"],
                   pol_h, "cloister/kek")
    ck = AESGCM(kek).decrypt(kem["nonce"], kem["wrapped_ck"], pol_h)
    return AESGCM(ck).decrypt(env["nonce"], env["body"], hdr_h)


# -------------------------------------------------------------------- posture gates
def strict_posture(observed: dict):
    """Deny unless every predicate the policy names is observed true."""
    def prove(policy):
        for k, want in policy["require"].items():
            got = observed.get(k)
            if got != want:
                raise PostureViolation(
                    f"{k}: policy requires {want!r}, runtime reports {got!r}")
    return prove


def live_posture():
    """
    Observe the posture of the process we are actually running in, rather than trusting
    an assertion. Only the predicates this module can genuinely verify are reported as
    satisfied; everything else is reported False, so a policy demanding it fails closed.
    """
    from . import membrane
    obs = membrane.observe()
    return strict_posture(obs)


# --------------------------------------------------------------------------- leases
class Lease:
    """
    The envelope never yields a permanently usable key. A lease is a short-lived
    authorisation the membrane must hold; revocation then means "stop issuing leases",
    which actually works, unlike revocation in identity-based rights management where
    the recipient already holds a usable key.

    Offline work is supported by lease duration, not by permanent release.
    """

    def __init__(self, matter: str, issued_at: float, seconds: int, log_entry: str = ""):
        self.matter, self.issued_at, self.seconds = matter, issued_at, seconds
        self.log_entry = log_entry

    @classmethod
    def issue(cls, policy: dict, log=None) -> "Lease":
        entry = ""
        if log is not None:
            entry = log.append({"matter": policy["matter"],
                                "policy": policy_digest(policy).hex()})
        return cls(policy["matter"], time.time(), policy["lease_seconds"], entry)

    def remaining(self) -> float:
        return self.issued_at + self.seconds - time.time()

    def check(self, policy: dict):
        if policy["matter"] != self.matter:
            raise LeaseExpired("lease was issued for a different matter")
        if self.remaining() <= 0:
            raise LeaseExpired(
                f"lease expired {abs(self.remaining()):.0f}s ago; request another")


class TransparencyLog:
    """
    Append-only, hash-chained record of every lease issued, in the manner of certificate
    transparency. This is what turns "we think nobody opened it" into a statement that
    survives challenge -- the property compliance buyers actually pay for, and one no
    network gateway can offer, because a gateway never sees access that happens
    off-network.
    """

    def __init__(self, path: str | None = None):
        self.path = path
        self.entries: list[dict] = []
        self.head = hashlib.sha256(b"cloister/log/v1").hexdigest()
        if path and os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        self._absorb(json.loads(line))

    def _absorb(self, rec):
        self.entries.append(rec)
        self.head = hashlib.sha256(
            (self.head + json.dumps(rec, sort_keys=True)).encode()).hexdigest()

    def append(self, rec: dict) -> str:
        rec = dict(rec, seq=len(self.entries), at=time.time())
        self._absorb(rec)
        if self.path:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, sort_keys=True) + "\n")
        return self.head

    def verify(self) -> bool:
        h = hashlib.sha256(b"cloister/log/v1").hexdigest()
        for rec in self.entries:
            h = hashlib.sha256((h + json.dumps(rec, sort_keys=True)).encode()).hexdigest()
        return h == self.head
