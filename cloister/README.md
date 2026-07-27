# cloister

Protect documents against machine ingestion, and trace leaks back to a recipient.

This is the **format-only posture** described in the CLOISTER whitepaper: it needs
nothing installed on the recipient's machine, no server, and no key exchange. You get
a normal PDF that opens in anything. What it does differently:

- **A text extractor reads a different document than a human does.** The glyphs on the
  page are your document. The characters `pdftotext`, `pypdf`, `pdfplumber` and every
  other extraction library report are fluent cover prose about facilities maintenance.
  An automated pipeline terminates confidently on the wrong document, with no signal
  that anything went wrong.
- **Every copy is unique, and the fingerprint survives a photograph.** Inter-word
  spacing carries a collusion-resistant Tardos codeword at a displacement of about a
  quarter of a point. Photograph one page with a phone, and `cloister trace` names the
  recipient.

It does **not** stop a vision model or an OCR pass from reading the rendered page.
Nothing can. See *Limits* below.

## Install

    pip install fonttools pillow numpy python-docx        # format-only posture
    pip install cryptography cbor2 kyber-py               # plus the sealed envelope
    # and poppler-utils, for pdftotext / pdftoppm

    python3 -m cloister --help

The first three commands below need only the first line. `seal` / `open` / `membrane`
need the second.

## Use

Protect one document for a list of recipients:

    python3 -m cloister protect brief.md \
        --roster team.csv --out dist/ --cover minutes

`--roster` takes a CSV (first column) or a plain newline list. `--cover` picks which
innocuous topic the decoy is written about: `facilities`, `minutes`, `inventory`,
`travel`. Input can be `.md`, `.txt`, `.docx` or `.pdf`.

That writes one PDF per recipient, plus `manifest.json` and `_reference.pdf`.
**Both of those are secrets** — they are what makes tracing possible, and the
reference render is what the detector subtracts to cancel per-glyph side bearings.
Distribute the numbered copies; keep the rest.

Check that the copies actually diverge from their text layer:

    python3 -m cloister verify dist/

Trace a leak. The evidence can be a PDF, or a photograph of a single page:

    python3 -m cloister trace leaked.jpg --manifest dist/manifest.json

It works out which page of the master it is looking at, deskews and rescales the
image onto the master's coordinate system, recovers the codeword, and applies the
calibrated accusation test. It either names a recipient or says it cannot — it will
not offer a "most likely" guess dressed up as a result.

Emit a true-text copy for a screen reader:

    python3 -m cloister accessible dist/

## The sealed envelope, and the membrane (the enforcement posture)

The format-only posture above assumes the recipient's machine is not yours to control.
When it is — a firm's own laptops, a court's terminals — the guarantee gets much
stronger, because the key can be made conditional on the runtime rather than on an
identity.

    python3 -m cloister keygen --out keys/
    python3 -m cloister seal brief.md --keys keys/ --matter "Ashgrove v. Merridew" \
        --out brief.cloister
    python3 -m cloister membrane -- python3 -m cloister open brief.cloister \
        --keys keys/ --out brief.md

The last line is the whole idea. `open` outside the membrane is **refused**, and refused
*before any key material is derived*:

    DENIED before any key was derived: egress_blocked: policy requires True,
    runtime reports False

Inside it, the same command succeeds and returns a 900-second lease.

**Ordering is the design.** A sandbox applied after decryption protects nothing, because
the plaintext already exists in a process that could have leaked it. So the reader enters
an irreversible runtime *first* and then presents the resulting posture to obtain a key.
The suite asserts this by counting KEM decapsulations during a denied open: zero.

**The policy is load-bearing, not advisory.** The policy digest sits inside the KDF
transcript, so editing the policy does not produce a permissive envelope — it produces a
key that no longer reproduces. That holds even against an adversary who *also holds the
signing key*, which is where a signed-policy scheme fails, and the suite exercises
exactly that adversary.

What the membrane enforces on Linux, without root: an empty network namespace, a
seccomp-BPF filter denying 16 egress and memory-inspection syscalls, `PR_SET_DUMPABLE 0`,
`no_new_privs`, and Landlock where the running kernel exposes it (probed, not inferred
from a version number). The filter survives `execve`, which is what makes it cover the
real renderer and any agent runtime that attaches itself downstream.

Three honest notes. Capture exclusion, clipboard gating and renderer attestation are
**not** implemented here — they are per-platform windowing and measurement calls, and on
bare X11 the first does not exist at all — so `observe()` reports them False and a policy
requiring them fails closed. The device keys are ordinary keys in memory; in deployment
they would be non-exportable and sealed to a TPM or Secure Enclave, which is the one
property this code cannot demonstrate on its own. And post-quantum matters here
specifically because an envelope is a self-contained ciphertext an adversary can simply
keep: privileged material has a confidentiality horizon measured in decades.

## Authorship provenance (the academic case)

The other half of the academic problem is not distribution — it is a submission you did
not write. Detection is the wrong primitive for that: the signal is weak, the cost of a
false positive is an accused student, and the bias falls on non-native English writers.
So this inverts it. Rather than proving a student *did* cheat, a student can offer
positive evidence that they wrote it, and nobody runs a classifier over their prose.

    python3 -m cloister trail --profile honest --out trail.json     # the editor's job
    python3 -m cloister attest --trail trail.json --submission essay.docx --out auth/
    python3 -m cloister credential auth/
    python3 -m cloister check auth/credential.json --trusted auth/editor.pub

**Two trust problems, two mechanisms — conflating them is the mistake.**

*Protecting the student.* A keystroke log is surveillance and no institution should hold
one. The trail never leaves the author's device. What is disclosed is a set of
zero-knowledge predicates over it — "no single insertion exceeded 400 characters" —
proved with Pedersen commitments and bit-decomposition range proofs in a 2048-bit group
with a 256-bit prime-order subgroup. Audited output: of 861 edit events, **zero**
timestamps and **zero** statistic values appear anywhere in the credential. The
instructor learns the policy bounds, pass/fail against each, the submission hash, the
trail root, and which editor signed it. Nothing else.

*Protecting the institution.* Zero-knowledge proofs supply no integrity by themselves —
an author could commit to whatever statistics suit them. So an attested editor computes
the statistics, commits to them, and signs the commitments alongside the trail root and
the submission hash. The proofs are then bound to commitments the author cannot change.
The proofs are privacy; the signature is integrity.

Measured, on five simulated sessions all producing the same length of text:

| session | verdict |
|---|---|
| honest, deliberate (65 min) | credential complete |
| honest, fluent (3 min) | credential complete |
| one bulk paste | incomplete — all three predicates fail |
| pasted in twelve chunks | incomplete — all three predicates fail |
| **model output retyped by hand** | **credential complete** |

That last row is the fundamental limit and the test suite asserts it. This layer attests
a *process*, not an *origin*. Someone who reads model output off a phone and types it in
at human pace satisfies every predicate. What changes is that the shortcut is no longer
free, and the honest student is no longer at the mercy of a classifier.

**The default policy contains no time or rhythm predicate, on purpose.** A wall-clock
floor looks like an obvious check and is a bad one. In testing, two honest sessions
producing identical output took 65 minutes and 3 minutes; a 30-minute floor passes the
first and fails the second. A floor penalises fluency and rewards leaving the editor
open. Rhythm statistics are worse — they misfire on dictation, on motor impairment, and
on drafting in a second language. `--with-time-floor` exists if an instructor insists,
with the caveat attached.

Proof cost: ~350 ms to prove and ~330 ms to verify per predicate, 16 KB each, 54 KB for
a three-predicate credential. Soundness is exercised rather than asserted — the test
suite attempts seven forgeries (retargeting the bound, tampering with each commitment,
mutating a bit response, reordering and dropping bits, replaying under a different
context) and all seven are rejected, and the prover refuses to attempt a false
statement rather than producing an unverifiable proof.

Read `LIMITS` at the bottom of `cloister/authorship.py` before deploying this. The
short version: it must be optional, absence of a credential is not evidence of
misconduct, and it is worthless without a pinned editor identity.

## How it works

| Module | What it does |
|---|---|
| `ingest.py` | `.md` / `.txt` / `.docx` / `.pdf` into styled blocks |
| `decoy.py` | keyed recombination of a cover corpus into fluent prose |
| `render.py` | the PDF: CID font banks, layout, both watermark channels |
| `code.py` | Tardos code, generation-time screening, calibrated accusation |
| `detect.py` | deskew, normalise, sub-pixel centroid recovery from an image |
| `zk.py` | Pedersen commitments, OR-proofs, range and bound proofs |
| `authorship.py` | edit trail, Merkle commitment, editor attestation, credentials |
| `envelope.py` | hybrid PQ seal, posture policy in the KDF transcript, leases, log |
| `membrane.py` | seccomp-BPF filter, namespaces, Landlock probe, posture observation |
| `cli.py` | the commands above |

Three design points that are not obvious and were each arrived at by measurement:

**A CID may report a *string*, not a character.** This is what lets the decoy be
ordinary human prose. Six drawn glyphs can report a whole sentence, so the decoy does
not have to match the true text word-for-word in length, and no language model is
needed to generate it.

**Gaps are displaced in pairs that sum to zero.** `(base+d, base-d)` for a 1 and the
reverse for a 0. Line length is therefore invariant, displacement cannot accumulate
along a line, and the right margin never moves. Detection is a local comparison of two
gaps, which also cancels global scale error from printing or photographing.

**The detector never segments words out of the image.** It holds the master, so it
computes each word's expected window from the layout map and takes an
intensity-weighted centroid inside it. Two earlier detectors that found words by ink
connectivity both failed *at chance*: a single split or merged glyph shifts every
following gap index and inverts the bits after it.

**Every threshold is measured from the paper, not from zero.** A photograph's paper is
grey and unevenly lit, so a cut expressed as a fraction of the peak lands *below* the
paper on the dark side of the page. The detector therefore subtracts a fitted quadratic
illumination surface first, then thresholds what remains relative to the local paper level
with a noise-floor term. Skipping either step does not produce a warning — it stretches
the text bounding box to the page edge, misregisters every word window, and recovers bits
at chance while the diagnostics still look healthy.

## Tests

    cd tests && python3 run_all.py          # everything, about 5 minutes
    python3 run_all.py --fast               # skip the modules that rasterise pages
    python3 run_all.py kerning              # one area

Every measured claim in the whitepaper has a named test here, and every bug that
measurement turned up has a *regression test that carries the bug with it*. Each
regression registers two callables: one that asserts the property holds, and one that
reconstructs the original broken implementation and asserts it fails. If the broken
version passes, the test is reported **TOOTHLESS** and the suite exits non-zero — because
a regression test that its own bug would have passed protects nothing. That is mutation
testing narrowed to the mutations that actually happened, which is the subset already
proven able to get past review.

## Measured

On an eight-page privileged memorandum distributed to forty recipients
(2,668 words, 1,148 codeword positions per copy = 16.6× coverage of a 69-bit code):

| | |
|---|---|
| Distinctive source terms in any copy's text layer | **0 of 84** |
| Numeric strings leaked | **0 of 3** |
| Traced correctly from one photographed page | **20 of 20** |
| False accusations | **0** |
| Worst score margin over the nearest innocent | 17.2 |

The photographs were simulated with random rotation (±1.6°), Gaussian blur
(0.4–1.0 px), sensor noise (σ 4–12), downscaling to 60–95%, and JPEG quality 55–85.
Fingerprint recovery is unaffected by JPEG down to quality 35, noise to σ 20,
downscaling to 55%, and rotation to 5° once deskewed. It degrades gracefully at a
1.5 px blur (BER 5.8%, still traced) and needs deskewing — uncorrected rotation
beyond about a degree destroys it.

**That ladder held the paper white, which was a gap.** Every degradation model in the
original measurement left the page at full white, and a full-white page hides two
threshold bugs: the uint8 clip removes the negative half of the sensor noise, and there is
no paper pedestal for a cut measured from zero to fall below. Adding grey, unevenly lit
paper broke the detector, which is what motivated the background model above. Re-measured
across eight lighting conditions — flatbed scan, four phone photographs from good light
down to a dim room, a downscaled screenshot, and two with cos⁴ vignetting plus an
off-centre shadow — three recipients each:

| | |
|---|---|
| Traced correctly | **24 of 24** |
| False accusations | **0** |
| Bit error rate | 0.0% in 20 of 24, worst 2.9% |
| Redundancy exploited per position | 2.97× (combined margin 3.10 px from 1.01 px gaps) |

Past that envelope — paper at 170–180 *and* sensor noise of 20–26 grey levels *and* a
downscale to 70–80%, which leaves under 0.8 px per gap — recovery falls to chance. The
suite asserts what happens there: at 48% BER it names **nobody**, and accuses no innocent.
A detector that degrades into confident nonsense is worse than one that refuses, because
the output of this pipeline is an accusation against a named person.

## Limits

- **OCR or a vision model reads the rendered page in full.** The chaff layer removes
  the cheap path and imposes roughly a 10× token cost; it is not a barrier.
- **The analog hole is open.** Someone who may read a document can retype it. Then the
  kerning channel is gone, though the trace survives verbatim retyping of the decoy.
- **One page traces a single leaker, not a coalition.** Resisting five colluders needs
  a code an order of magnitude longer, and correspondingly more recovered material.
  Pass `--collusion 5` and expect to need several pages of evidence.
- **The accusation threshold is calibrated per code, not taken from theory.** At small
  observation counts the Tardos score is not reliably Gaussian, and two codes with
  identical parameters can differ by an order of magnitude in detection power. That is
  why `protect` screens candidates and stores the chosen threshold in the manifest.
- **Accessibility.** The chaff layer breaks screen readers by design. Under this
  posture there is no attestation gate, so the honest answer is to ship the accessible
  variant on request and say so on the document's face. Do not deploy the chaff layer
  where you cannot meet that.
- **The detector has a measured floor, and it is lighting, not resolution.** Contrast
  matters more than pixel count: a dim, unevenly lit capture that is also heavily
  downscaled falls to chance. `trace` reports the redundancy and both gap margins, and
  warns when the margins are far larger than the embedded displacement — the signature of
  a misregistered page, which is the condition under which a detector would otherwise
  accuse someone confidently and wrongly.
- **Every number above is a simulation.** Degradation models are written by the same
  person who wrote the detector, which is a structural weakness no amount of care removes:
  the white-paper gap above sat undetected through a whole measurement campaign for exactly
  that reason. Photograph real printed copies before believing any of it.

Not production software. No warranty. Read the whitepaper's threat model before
relying on any of this.
