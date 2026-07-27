# CLOISTER

**Keep documents out of AI models, and trace the ones that get out.**

[![Deploy site](https://github.com/AdityaKumar0927/Cloister-/actions/workflows/deploy.yml/badge.svg)](https://github.com/AdityaKumar0927/Cloister-/actions/workflows/deploy.yml)
[![Re-measure the claims](https://github.com/AdityaKumar0927/Cloister-/actions/workflows/evidence.yml/badge.svg)](https://github.com/AdityaKumar0927/Cloister-/actions/workflows/evidence.yml)

→ **[adityakumar0927.github.io/Cloister-](https://adityakumar0927.github.io/Cloister-/)**
· [Live attack demo](https://adityakumar0927.github.io/Cloister-/demo)
· [Whitepaper (PDF)](whitepaper/CLOISTER-whitepaper.pdf)
· [What it cannot do](https://adityakumar0927.github.io/Cloister-/limits)

---

You cannot build a file that a determined human with a camera cannot read. So this does
not try. It attacks the four moments where ingestion actually happens.

| | Layer | What it does | Assumes |
|---|---|---|---|
| **D** | Chaff | The glyphs on the page are your document; the characters every extractor reports are fluent cover prose. An automated pipeline terminates confidently on the wrong document. | nothing installed anywhere |
| **P1** | Envelope | A hybrid post-quantum seal whose content key is bound to a *runtime posture*, not an identity. Relaxing the policy yields a key that no longer reproduces — even for someone holding the signing key. | you control the reader's machine |
| **P2** | Membrane | The reader enters an irreversible sandbox (empty netns, 16 syscalls denied, no ptrace) *first*, then presents that posture to get a 900-second lease. | Linux, no root needed |
| **T** | Fingerprint | Inter-word spacing carries a Tardos codeword at ¼ pt. Photograph one page with a phone and the recipient is named out of a 40-person roster. | the leak will happen |
| **A** | Provenance | An author proves their editing process in zero knowledge instead of having a classifier run over their prose. | an attested editor |

## The honest part, before the pitch

**OCR reads the page.** On the reference document, tesseract recovers 10 of 10 sensitive
terms — and you can run that channel yourself in the browser demo, because a demo that
only showed the flattering result would be advertising. Retyping defeats the fingerprint.
Authorship provenance attests a *process*, not an *origin*: model output retyped by hand
earns a complete credential, and the test suite asserts that outcome deliberately.

Every degradation figure here is a simulation, written by the same person who wrote the
detector. That already flattered it once: every photograph model held the paper pure
white, which hides two threshold bugs at once, and the gap survived an entire measurement
campaign. Photograph real printed copies before relying on any tracing number.

## Measured

52 tests: 37 measured claims, 15 regression tests. Re-run weekly by CI, which commits the
results back — so the numbers on the website are whatever the suite last wrote.

| | |
|---|---|
| Sensitive terms recovered by text extraction | **0 of 10** (pdftotext, pypdf, pdfplumber, all agreeing) |
| Sensitive terms recovered by OCR | **10 of 10** |
| Leaks traced from one photographed page | **20 of 20**, 0 false accusations |
| Re-measured across 8 lighting conditions | **24 of 24**, 0 false accusations |
| Fingerprint displacement | 0.2625 pt = 1.09 px at 300 dpi |
| Envelope overhead | 1,622 B, constant; 155 MB/s seal, 308 MB/s open |
| Egress syscalls denied inside the membrane | 16, filter survives `execve` |

## Quick start

```bash
pip install fonttools pillow numpy python-docx cryptography cbor2 kyber-py
sudo apt-get install poppler-utils tesseract-ocr fonts-dejavu-core

cd cloister
printf 'alice@firm.example\nbob@firm.example\n' > roster.csv
python3 -m cloister protect brief.md --roster roster.csv --out dist/ --cover minutes
python3 -m cloister verify dist/
python3 -m cloister trace leaked.jpg --manifest dist/manifest.json
```

`manifest.json` and `_reference.pdf` are **secrets** — they are what makes tracing
possible. Distribute the numbered copies; keep the rest.

The sealed envelope, where you control the machine:

```bash
python3 -m cloister keygen --out keys/
python3 -m cloister seal brief.md --keys keys/ --matter "Ashgrove v. Merridew" \
    --out brief.cloister
python3 -m cloister membrane -- python3 -m cloister open brief.cloister --keys keys/
```

Outside the membrane that last command is refused *before any key is derived*:

```
DENIED before any key was derived: egress_blocked: policy requires True,
runtime reports False
```

## Tests

```bash
cd cloister/tests && python3 run_all.py        # ~7 min
python3 run_all.py --fast                      # skip page rasterisation
```

Regression tests here carry their own bug. Each registers the fix **and** a faithful
reconstruction of the original broken code, and asserts the broken one fails. If it
passes, the test reports `TOOTHLESS` and the run exits non-zero — a regression test its own
bug would have passed protects nothing. The harness also snapshots module state around
every test and reports `LEAKY` if a mutation left a monkeypatch behind, because that failure
otherwise looks like several unrelated tests breaking in a different file.

## For agents

- [`AGENTS.md`](AGENTS.md) — repository conventions, and the traps that will waste your time.
- [`mcp/server.py`](mcp/server.py) — MCP server exposing `protect`, `trace`, `verify`,
  `accessible` and `limits`. Standard library only. There is deliberately **no** tool that
  opens an envelope: layer P1 exists to keep plaintext away from processes that could
  exfiltrate it, and an agent runtime is exactly the process it excludes.

```json
{ "mcpServers": { "cloister": { "command": "python3", "args": ["mcp/server.py"] } } }
```

## The website

Astro 7 · React islands · Tailwind 4 · static · GitHub Pages.

The interesting page is the [live attack](https://adityakumar0927.github.io/Cloister-/demo):
an adversarial agent runs **in your browser tab** — WebGPU via WebLLM, or Chrome's built-in
Gemini Nano, or a deterministic extractor if neither is available — and loops
`plan → extract → verify → critique` against a real protected PDF. No API key, nothing
uploaded, which is the same property the tool argues for.

Its verify step is a deterministic tool, not a prompt: every term the model claims is
checked by string containment against its own input. That is what turns "the model failed"
into "the model hallucinated, and here is the proof" — without it you cannot tell a
protected document from a weak model.

```bash
cd site && npm ci && npm run dev
```

Three CI loops:

- **deploy** — builds and publishes, and *refuses to publish* if `regression.json` shows
  anything other than all tests passing.
- **evidence** — reruns the suite weekly, regenerates the demo artefacts with the real
  tool, commits them back. On failure a model triages which published claim is now false
  and opens an issue.
- **overclaim-audit** — points a hostile reviewer at this project's own marketing copy,
  with only the measured results as evidence, and asks it to argue against us. Advisory
  only; it comments on pull requests and cannot block a merge.

## Layout

```
cloister/     the Python package (12 CLI commands) and its 52-test suite
poc/          the measurement scripts behind the whitepaper figures
evidence/     JSON the suite wrote; the site reads these, never hand-typed numbers
site/         the Astro website
whitepaper/   36 pages: threat model, constructions, measurements, nine bugs found by measuring
mcp/          MCP server
```

## Reading order

If you only read one thing, read the [limits](https://adityakumar0927.github.io/Cloister-/limits).
If you read two, add §5.10 of the whitepaper — the three bugs that writing the test suite
found, including the one that would have named the wrong person.

---

Research prototype by [Aditya Kumar](https://github.com/AdityaKumar0927). Not production
software, no warranty. Read the whitepaper's threat model before relying on any of it.
