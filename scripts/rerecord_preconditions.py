"""Re-record Nemotron precondition extractions via live Nebius Token Factory.

Reads every unique CVE description from fixtures/cves.json, calls Nemotron
with the same extraction prompt the product uses, and rewrites
fixtures/recorded/nemotron_extractions.json with REAL model output
(replacing the hand-written stubs).

Auth: uses the nebius-chat CLI, which carries the stored credential.
No secrets in this script, no secrets in the output file.
"""
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nullpoint.nemotron import EXTRACTION_SYSTEM_PROMPT

MODEL = "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B"
CHAT = "/home/hatch/workspace/skills/nebius-token-factory/bin/nebius-chat"
REQUIRED = ("port", "protocol", "auth_required", "network_vector",
            "payload_constraints", "confidence", "narrative_claim", "delivery")


def extract(cve_id: str, description: str) -> dict:
    proc = subprocess.run(
        [CHAT, "--model", MODEL,
         "--system", EXTRACTION_SYSTEM_PROMPT,
         "--user", f"CVE {cve_id}: {description}",
         "--max-tokens", "4096",
         "--temperature", "0",
         "--response-format", "json_object"],
        capture_output=True, text=True, timeout=300,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"nebius-chat failed for {cve_id}: {proc.stderr[:500]}")
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        raise RuntimeError(f"non-JSON output for {cve_id}: {proc.stdout[:300]}")
    missing = [k for k in REQUIRED if k not in data]
    if missing:
        raise RuntimeError(f"{cve_id} missing keys {missing}: {data}")
    return {k: data[k] for k in REQUIRED}


def main() -> None:
    cves = json.load(open("fixtures/cves.json"))
    recs = cves if isinstance(cves, list) else cves.get("findings", [])
    seen: dict[str, str] = {}
    for r in recs:
        seen.setdefault(r["cve_id"], r.get("description", ""))
    out: dict[str, dict] = {}
    for cve_id, desc in sorted(seen.items()):
        print(f"extracting {cve_id} ...", flush=True)
        out[cve_id] = extract(cve_id, desc)
        print(f"  -> claim={out[cve_id]['narrative_claim']!r} "
              f"port={out[cve_id]['port']}/{out[cve_id]['protocol']}", flush=True)
    out["_comment"] = ("Live Nemotron extractions via Nebius Token Factory "
                       "(re-recorded; replaces hand-written stubs).")
    with open("fixtures/recorded/nemotron_extractions.json", "w") as fh:
        json.dump(out, fh, indent=1)
    print(f"wrote {len(seen)} extractions")


if __name__ == "__main__":
    sys.exit(main())
