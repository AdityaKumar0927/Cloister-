# AGENTS.md

Instructions for coding agents working in this repository. Humans should read
`README.md` first; this file is the operational detail an agent needs and the reasoning
behind the rules, because a rule without its reason gets optimised away.

## What this project is

CLOISTER protects documents from being ingested by AI systems, and traces the copies that
escape. Four layers: a PDF whose text layer reads as a different document, a
posture-gated post-quantum envelope, a per-recipient spacing fingerprint recoverable from
a photograph, and zero-knowledge authorship provenance.

```
cloister/          the Python package and its test suite
  cloister/        library + CLI (12 commands)
  tests/           52 tests: 37 measured claims, 15 regression tests
poc/               measurement scripts behind the whitepaper figures
evidence/          JSON the suite wrote; the website reads these, never hand-typed numbers
site/              Astro 7 website, static, deployed to GitHub Pages
whitepaper/        the paper (HTML source + built PDF)
mcp/               MCP server exposing the tool to agents
```

## The one rule that matters

**Do not weaken a test to make it pass.** Every claim on the public website links to a
named test in `cloister/tests/`. Loosening an assertion silently converts a published
sentence into a false one. If a test fails, either fix the code or change the claim on the
site — both, if the measurement genuinely moved.

This is not hypothetical caution. Nine security properties in this project were silently
false at some point while the code looked correct, and in every case the reason was the
same: nothing exercised the condition that made them false.

## How the test suite is unusual

Regression tests register **two** implementations: the fix, and a faithful reconstruction
of the original broken code. The suite asserts the broken one *fails*.

```python
@regression("kerning-paper-pedestal", bug="...", found_by="...")
def thresholds_are_measured_from_the_paper_level():
    ...                      # assert the property holds now

@mutation("kerning-paper-pedestal")
def _original_peak_relative_threshold():
    ...                      # rebuild the bug; must raise AssertionError
```

Three non-obvious consequences:

- If the mutation *passes*, the test reports `TOOTHLESS` and the run fails. A regression
  test that its own bug would have passed protects nothing. When you see `TOOTHLESS`, the
  mutation is wrong or a later fix has subsumed the bug — do not delete the test to make
  it green.
- Mutations work by monkeypatching, so the harness snapshots module state around every
  test and reports `LEAKY` if anything was left patched. A leaked patch looks like several
  unrelated tests failing in a different file; fix the leak first and re-run before
  believing any other failure.
- When you fix a bug, add its mutation. That is the deliverable, not the fix.

```bash
cd cloister/tests
python3 run_all.py            # everything, ~7 minutes
python3 run_all.py --fast     # skip the modules that rasterise pages
python3 run_all.py kerning    # one area
```

## Local dependencies

```bash
pip install fonttools pillow numpy python-docx cryptography cbor2 kyber-py
pip install pypdf pdfplumber                    # the suite needs two other PDF readers
sudo apt-get install poppler-utils tesseract-ocr fonts-dejavu-core
```

`fonts-dejavu-core` is not optional. The renderer measures glyph advances from DejaVu
Serif and the detector's layout map depends on them, so a different serif silently breaks
recovery rather than erroring.

## The website

```bash
cd site && npm ci && npm run dev
```

Astro 7 with React islands, Tailwind 4, static output, `base: '/Cloister-'` — the repo
name has a trailing hyphen and that is the deploy path. **Never write an internal link as
`/foo`**; use `` `${import.meta.env.BASE_URL}/foo` ``, or it works in dev and 404s in
production.

`npm run build` runs `sync-evidence.mjs`, which copies `evidence/*.json` into
`src/data/`. Pages import those directly, so a missing figure breaks the build instead of
leaving a stale number on the page. **If you want to change a number on the site, change
the measurement.** There is a scheduled workflow that will overwrite hand-edits anyway.

The demo island (`site/src/components/AgentDemo.tsx`) runs an LLM in the visitor's tab via
WebGPU. Keep it that way: a privacy tool that demonstrates itself by uploading the demo
document to an API is incoherent, and the 5.9 MB WebLLM chunk must stay behind a dynamic
`import()` so it is fetched only when the visitor asks for it.

## Style

Python: standard library plus the deps above, no framework. Comments explain *why*,
especially where a simpler-looking approach was tried and failed — several modules
document a wrong version alongside the right one on purpose. Keep it.

TypeScript/Astro: strict mode. Prettier defaults, single quotes, no semicolons in `.astro`
frontmatter.

Commits: imperative subject, lower-case prefix by area (`detect:`, `site:`, `evidence:`).
Explain the reasoning in the body when the change is not obvious.

## Things that will waste your time

- `pdftoppm` output is collected by prefix. `render_pdf` clears stale matches first;
  removing that reintroduces a bug where a one-page document adopted a previous run's
  reference pages and traced against the wrong document.
- The ZK group is a 2048-bit prime with a 256-bit prime-order subgroup, **not** a safe
  prime. Squaring does not land in the subgroup; exponentiate by the cofactor. There is a
  `_selftest()` asserting this at import.
- `PR_SET_DUMPABLE` does not survive `execve` but the seccomp filter does. Anything
  launched into the membrane must call `harden()` before reporting its posture.
- Every degradation model in `tests/test_kerning.py` must include grey, unevenly lit
  paper. Pure white paper hides two threshold bugs at once: the `uint8` clip discards half
  the sensor noise, and there is no paper pedestal for a threshold measured from zero to
  fall below. That gap survived an entire measurement campaign.

## Don't

- Add analytics, trackers, or any third-party script to the site.
- Send document content anywhere in the demo.
- Publish a number that no committed artefact contains.
- Describe this tool as preventing AI from reading a document. It does not; OCR reads the
  page, and `site/src/pages/limits.astro` says so at the same volume as the claims.
