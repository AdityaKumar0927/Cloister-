# Start here

This folder is already a git repository. Seven commits, all authored
`AdityaKumar0927 <adityaagangania@gmail.com>`, remote already pointing at
`https://github.com/AdityaKumar0927/Cloister-.git`.

## Push it from VS Code

1. **File → Open Folder** → this folder.
2. Source Control panel (`Ctrl+Shift+G`). You should see the seven commits and a
   **Publish Branch** button — the remote is set but the branch has no upstream yet, which
   is exactly the state that makes VS Code offer to publish.
3. Click **Publish Branch**. Sign in to GitHub if prompted.

Or from a terminal in this folder:

```bash
git push -u origin main
```

Check the authorship landed as intended:

```bash
git log --format='%an <%ae>  %s'
```

Every line should read `AdityaKumar0927 <adityaagangania@gmail.com>`. There is no Claude or
Co-Authored-By attribution anywhere in the history.

## Then one click, once

**Settings → Pages → Build and deployment → Source: `GitHub Actions`**

That is the only manual configuration. Selecting it triggers the deploy workflow and the
site appears at:

**https://adityakumar0927.github.io/Cloister-/**

No secrets to add. All three workflows use only the `GITHUB_TOKEN` that Actions provides
automatically — no API keys, no third-party accounts.

## Run it locally first, if you like

The website:

```bash
cd site
npm install
npm run dev          # http://localhost:4321/Cloister-
```

The tool and its test suite:

```bash
pip install fonttools pillow numpy python-docx cryptography cbor2 kyber-py pypdf pdfplumber
# and poppler-utils, tesseract-ocr, fonts-dejavu-core from your package manager

cd cloister/tests
python3 run_all.py --fast     # ~40 seconds
python3 run_all.py            # all 52 tests, ~7 minutes
```

`fonts-dejavu-core` is not optional: the renderer measures glyph advances from DejaVu Serif
and the detector's layout map depends on them, so a different serif breaks recovery
silently rather than erroring.

## What is in here

```
cloister/     the Python package (12 CLI commands) and its 52-test suite
poc/          the measurement scripts behind the whitepaper figures
evidence/     JSON the suite wrote; the site imports these, never hand-typed numbers
site/         the Astro 7 website, including the in-browser adversarial agent demo
whitepaper/   36 pages, HTML source and built PDF
mcp/          MCP server exposing the tool to agents
AGENTS.md     conventions for coding agents, and the traps that waste time
```

`node_modules` and build output are not included — `npm install` regenerates them, and
they are gitignored anyway.

## Three things worth knowing before you read the code

**The test suite is unusual on purpose.** Regression tests register two implementations:
the fix, and a faithful reconstruction of the original broken code, asserting the broken
one fails. If it passes, the test reports `TOOTHLESS` and the run exits non-zero — a
regression test its own bug would have passed protects nothing.

**The site cannot print a number that no artefact contains.** Pages import
`evidence/*.json` at build time, so a figure that stops being produced breaks the build
instead of going stale on a page. If you want to change a number, change the measurement.

**The unflattering results have equal billing.** OCR recovers the document, the demo has a
one-click OCR channel that wins 10/10, and `/limits` is in the main navigation. That is
deliberate: a document-protection tool that overstates itself gets someone's confidential
filing read.
