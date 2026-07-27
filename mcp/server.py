"""
CLOISTER as an MCP server.

Exposes the tool over the Model Context Protocol so an agent can protect and trace
documents directly. Uses only the standard library plus the package itself: MCP is a
JSON-RPC 2.0 protocol over stdio, which needs no SDK, and depending on one would make this
harder to audit than the fifty lines it replaces.

    python3 mcp/server.py

Register it with any MCP client, e.g. in `.mcp.json`:

    { "mcpServers": { "cloister": { "command": "python3",
                                    "args": ["mcp/server.py"] } } }

One deliberate omission: there is no tool here that decrypts an envelope. Layer P1 exists
precisely to keep plaintext away from processes that could exfiltrate it, and an agent
runtime is the exact process it is designed to exclude. A `cloister_open` tool would
undo the layer it was advertising.
"""
from __future__ import annotations

import json
import os
import sys
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "cloister"))

PROTOCOL = "2025-06-18"
NAME = "cloister"
VERSION = "0.3.0"

TOOLS = [
    {
        "name": "cloister_protect",
        "description": (
            "Protect a document for a list of recipients. Produces one PDF per recipient "
            "whose text layer reads as innocuous cover prose while the visible page is the "
            "real document, each copy carrying a unique fingerprint in its inter-word "
            "spacing. Returns the manifest, which is a secret: it is what makes tracing "
            "possible. Does NOT prevent OCR or a vision model from reading the page."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "source": {"type": "string",
                           "description": "Path to a .md, .txt, .docx or .pdf file."},
                "recipients": {"type": "array", "items": {"type": "string"},
                               "description": "One identifier per recipient."},
                "out_dir": {"type": "string", "description": "Directory for the copies."},
                "cover": {"type": "string", "enum": ["facilities", "minutes",
                                                     "inventory", "travel"],
                          "default": "minutes",
                          "description": "Topic the decoy prose is written about."},
                "collusion": {"type": "integer", "default": 1, "minimum": 1,
                              "description": "Colluding recipients to resist. Higher "
                                             "needs a longer code and more recovered "
                                             "material to trace."},
            },
            "required": ["source", "recipients", "out_dir"],
        },
    },
    {
        "name": "cloister_trace",
        "description": (
            "Identify which recipient a leaked copy came from. Evidence may be a PDF or a "
            "photograph of a single page. Either names a recipient or reports that it "
            "cannot; it never returns a most-likely guess dressed up as a result, because "
            "the output of this tool is an accusation against a named person."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "evidence": {"type": "string",
                             "description": "Path to the leaked PDF or page image."},
                "manifest": {"type": "string",
                             "description": "Path to manifest.json from cloister_protect."},
                "dpi": {"type": "integer", "default": 300},
            },
            "required": ["evidence", "manifest"],
        },
    },
    {
        "name": "cloister_verify",
        "description": (
            "Check that protected copies actually diverge from their text layer, by "
            "extracting each one and confirming no distinctive source term survives. Run "
            "this before distributing anything."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"dist_dir": {"type": "string"}},
            "required": ["dist_dir"],
        },
    },
    {
        "name": "cloister_accessible",
        "description": (
            "Emit a true-text copy for screen readers. The chaff layer breaks assistive "
            "technology by design, so this is not optional in any deployment that has "
            "accessibility obligations."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"dist_dir": {"type": "string"}},
            "required": ["dist_dir"],
        },
    },
    {
        "name": "cloister_limits",
        "description": (
            "Return what CLOISTER cannot do, with the measured figures. Call this before "
            "advising anyone to rely on the tool: OCR reads the rendered page, retyping "
            "defeats the fingerprint, and every degradation figure is a simulation."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def _cli(args: list[str]) -> dict:
    """Run the packaged CLI in-process and capture what it printed."""
    import contextlib
    import io

    from cloister import cli

    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            rc = cli.main(args)
    except SystemExit as e:
        rc = int(e.code or 0)
    return {"exit_code": rc, "output": buf.getvalue()}


def call_tool(name: str, a: dict) -> dict:
    if name == "cloister_protect":
        import tempfile
        roster = os.path.join(tempfile.mkdtemp(), "roster.txt")
        with open(roster, "w", encoding="utf-8") as fh:
            fh.write("\n".join(a["recipients"]) + "\n")
        r = _cli(["protect", a["source"], "--roster", roster, "--out", a["out_dir"],
                  "--cover", a.get("cover", "minutes"),
                  "--collusion", str(a.get("collusion", 1))])
        r["manifest"] = os.path.join(a["out_dir"], "manifest.json")
        r["warning"] = ("manifest.json and _reference.pdf are secrets. Distribute the "
                        "numbered copies only.")
        return r
    if name == "cloister_trace":
        return _cli(["trace", a["evidence"], "--manifest", a["manifest"],
                     "--dpi", str(a.get("dpi", 300))])
    if name == "cloister_verify":
        return _cli(["verify", a["dist_dir"]])
    if name == "cloister_accessible":
        return _cli(["accessible", a["dist_dir"]])
    if name == "cloister_limits":
        p = os.path.join(ROOT, "evidence", "demo.json")
        demo = json.load(open(p, encoding="utf-8")) if os.path.exists(p) else {}
        h = demo.get("headline", {})
        return {
            "fundamental": [
                f"OCR reads the rendered page: {h.get('ocr_recovered', 'all')} of "
                f"{h.get('terms_total', 'the')} sensitive terms recovered by tesseract on "
                f"the reference document. The format layer removes the cheap path and "
                f"imposes roughly a 10x token cost; it is not a barrier.",
                "Anyone permitted to read a document can retype it, which destroys the "
                "spacing fingerprint.",
                "Authorship provenance attests a process, not an origin: model output "
                "retyped by hand at human pace earns a complete credential.",
            ],
            "methodological": [
                "Every degradation figure is a simulation, written by the same person who "
                "wrote the detector. That already flattered it once -- all photograph "
                "models held the paper pure white, which hid two threshold bugs for an "
                "entire measurement campaign. Photograph real printed copies before "
                "relying on the tracing numbers.",
            ],
            "measured_floors": [
                "The detector's limit is lighting, not resolution. A dim, unevenly lit and "
                "heavily downscaled capture falls to chance; at chance it names nobody "
                "rather than an innocent.",
                "One page traces a single leaker, not a coalition.",
            ],
            "unimplemented": [
                "Capture exclusion, clipboard gating and renderer attestation. Reported "
                "False so a policy requiring them fails closed.",
                "Hardware-sealed device keys (TPM / Secure Enclave).",
            ],
        }
    raise ValueError(f"unknown tool: {name}")


def respond(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        rid, method = req.get("id"), req.get("method")

        if method == "initialize":
            respond({"jsonrpc": "2.0", "id": rid, "result": {
                "protocolVersion": PROTOCOL,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": NAME, "version": VERSION},
            }})
        elif method == "tools/list":
            respond({"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}})
        elif method == "tools/call":
            p = req.get("params", {})
            try:
                out = call_tool(p.get("name", ""), p.get("arguments", {}) or {})
                respond({"jsonrpc": "2.0", "id": rid, "result": {
                    "content": [{"type": "text",
                                 "text": json.dumps(out, indent=1, ensure_ascii=False)}],
                }})
            except Exception as e:
                respond({"jsonrpc": "2.0", "id": rid, "result": {
                    "content": [{"type": "text",
                                 "text": f"{type(e).__name__}: {e}\n"
                                         f"{traceback.format_exc(limit=3)}"}],
                    "isError": True,
                }})
        elif method in ("notifications/initialized", "initialized"):
            pass
        elif rid is not None:
            respond({"jsonrpc": "2.0", "id": rid,
                     "error": {"code": -32601, "message": f"method not found: {method}"}})


if __name__ == "__main__":
    main()
