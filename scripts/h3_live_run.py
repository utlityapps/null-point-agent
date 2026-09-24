#!/usr/bin/env python3
"""H3 live evaluation: Nemotron precondition extraction accuracy via Nebius.

For each advisory in fixtures/h3_advisories.json, asks Nemotron to extract
(port, protocol, auth_required) and scores exact-match against the labels.
All raw responses and failures are preserved in
fixtures/recorded/h3_live_run_<date>.json.

Usage: python3 scripts/h3_live_run.py [--limit N]
"""
from __future__ import annotations

import datetime
import json
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHAT = os.path.expanduser("~/workspace/skills/nebius-token-factory/bin/nebius-chat")
MODEL = "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B"

SYSTEM_PROMPT = """\
You extract structured exploit preconditions from a CVE advisory.
Respond with JSON only, exactly this shape:
{
  "port": <int>,
  "protocol": "TCP" | "UDP",
  "auth_required": <bool>,
  "network_vector": "NETWORK" | "ADJACENT" | "LOCAL",
  "payload_constraints": "<one sentence>",
  "confidence": <0.0-1.0>,
  "narrative_claim": "exposed" | "isolated" | "unknown"
}
"narrative_claim" is your best guess at whether the vulnerable service is
exposed to untrusted networks, based on the advisory text alone. It is a
guess: the deterministic solver verifies it and the narrative guard blocks
it if it disagrees.
"""


def extract(cve_id: str, text: str) -> dict:
    proc = subprocess.run(
        [CHAT, "--model", MODEL, "--system", SYSTEM_PROMPT,
         "--user", f"CVE {cve_id}: {text}",
         "--temperature", "0.0", "--max-tokens", "4096",
         "--response-format", "json_object"],
        capture_output=True, text=True, timeout=600,
    )
    if proc.returncode != 0:
        return {"_error": f"cli failed: {proc.stderr.strip()[:300]}"}
    out = proc.stdout.strip()
    if not out or out == "None":
        return {"_error": "empty model content (reasoning budget exhausted?)"}
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        # try to salvage a JSON object from the text
        start, end = out.find("{"), out.rfind("}")
        if start != -1 and end > start:
            try:
                return json.loads(out[start:end + 1])
            except json.JSONDecodeError:
                pass
        return {"_error": "non-JSON model output", "_raw": out[:500]}


def main() -> int:
    limit = int(sys.argv[sys.argv.index("--limit") + 1]) if "--limit" in sys.argv else None
    with open(os.path.join(REPO, "fixtures", "h3_advisories.json")) as fh:
        advisories = json.load(fh)["advisories"]
    if limit:
        advisories = advisories[:limit]

    results = []
    correct = 0
    for adv in advisories:
        cve_id = adv["id"]
        print(f"[{len(results)+1}/{len(advisories)}] {cve_id} ...", flush=True)
        resp = extract(cve_id, adv["text"])
        got = None
        match = False
        if "_error" not in resp:
            try:
                got = {
                    "port": int(resp["port"]),
                    "protocol": str(resp["protocol"]).upper(),
                    "auth_required": bool(resp["auth_required"]),
                }
                want = {"port": adv["port"], "protocol": adv["protocol"],
                        "auth_required": adv["auth_required"]}
                match = (got == want)
            except (KeyError, TypeError, ValueError):
                resp = {"_error": "missing/unparseable fields", "_raw": resp}
        if match:
            correct += 1
        results.append({
            "cve_id": cve_id,
            "label": {"port": adv["port"], "protocol": adv["protocol"],
                      "auth_required": adv["auth_required"]},
            "extracted": got,
            "exact_match": match,
            "raw": resp,
        })
        print(f"    label={results[-1]['label']} got={got} match={match}", flush=True)

    stamp = datetime.date.today().isoformat()
    summary = {
        "date": stamp,
        "model": MODEL,
        "provider": "Nebius Token Factory",
        "n": len(results),
        "exact_matches": correct,
        "accuracy": round(correct / len(results), 4) if results else 0.0,
        "falsification_bar": ">=0.90 exact-match on (port, protocol, auth_required)",
        "verdict": "SUPPORTED" if results and correct / len(results) >= 0.9 else "NOT SUPPORTED",
        "results": results,
    }
    out_path = os.path.join(REPO, "fixtures", "recorded", f"h3_live_run_{stamp}.json")
    with open(out_path, "w") as fh:
        json.dump(summary, fh, indent=2)
    print(f"\n{correct}/{len(results)} exact = {summary['accuracy']:.1%} -> {summary['verdict']}")
    print(f"recorded: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
