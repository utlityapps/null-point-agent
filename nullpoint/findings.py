"""Finding loaders: native NullPoint findings and AWS Inspector2 conversion.

A NullPoint finding is the unit the scanner reasons about::

    {"id", "cve_id", "title", "description", "host", "port", "protocol", "severity"}

Two input formats are accepted (auto-detected by :func:`load_findings`):

- **Native** — ``{"findings": [...]}`` with the fields above
  (``fixtures/cves.json`` is the bundled example).
- **Inspector2** — the raw output of ``aws inspector2 list-findings``,
  ``{"findings": [{"findingArn": ..., ...}]}``. Converted by
  :func:`inspector2_to_findings`.

Inspector2 notes (honest limitations, not gaps):

- Only ``PACKAGE_VULNERABILITY`` findings with a real CVE ID are converted.
  ``NETWORK_REACHABILITY`` findings ("Port 22 is reachable…") carry no CVE
  and are skipped — converting one's title into a CVE ID would be garbage.
- Package-vulnerability findings name the CVE
  (``packageVulnerabilityDetails.vulnerabilityId``) and the EC2 instance
  (``resources[0].id``) but carry **no port**. On hosts with no internet
  path at all the scanner dismisses them via the any-port proof; on hosts
  with an internet path they fail closed to human review (nothing to test).
- Findings on non-EC2 resources (e.g. ECR images) get ``host="unknown"``,
  which the scanner routes to human review via the unknown-host rule.
- Real CVE IDs have no recorded offline stubs, so real findings need live
  mode (``--live`` with ``NEBIUS_API_KEY`` / ``TAVILY_API_KEY``).
"""
from __future__ import annotations

import json
import pathlib
import re

#: A real CVE ID. Anything else (titles, ARNs, "Port") is not converted.
_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)


def is_inspector2_doc(doc: dict) -> bool:
    """True when ``doc`` looks like ``aws inspector2 list-findings`` output."""
    findings = doc.get("findings") if isinstance(doc, dict) else None
    if not findings:
        return False
    first = findings[0]
    return isinstance(first, dict) and "findingArn" in first


def inspector2_to_findings(doc: dict) -> list[dict]:
    """Convert ``aws inspector2 list-findings`` JSON to NullPoint findings.

    Only ``PACKAGE_VULNERABILITY`` findings with a real CVE ID are kept;
    network-reachability findings and non-CVE entries are skipped, not
    coerced.
    """
    out = []
    n = 0
    for f in doc.get("findings", []):
        if str(f.get("type") or "").upper() != "PACKAGE_VULNERABILITY":
            # e.g. NETWORK_REACHABILITY ("Port 22 is reachable…") — no CVE,
            # nothing for the precondition extractor to work with.
            continue
        pv = f.get("packageVulnerabilityDetails") or {}
        cve_id = str(pv.get("vulnerabilityId") or "").strip()
        if not _CVE_RE.match(cve_id):
            continue
        n += 1
        host = "unknown"
        for r in f.get("resources", []) or []:
            # Only EC2 instances exist in the infra graph; anything else
            # (ECR images, Lambda) stays "unknown" and the scanner fails it
            # closed via the unknown-host rule.
            if r.get("type") == "AWS_EC2_INSTANCE" and r.get("id"):
                host = r["id"]
                break
        out.append({
            "id": f"INSP-{n:03d}",
            "cve_id": cve_id,
            "title": f.get("title", ""),
            "description": f.get("description", ""),
            "host": host,
            # Inspector2 package findings carry no port: on hosts with no
            # internet path the any-port proof dismisses them; otherwise
            # the scanner fails them closed to human review.
            "port": None,
            "protocol": "TCP",
            "severity": str(f.get("severity") or "UNKNOWN").upper(),
            "source": "inspector2",
        })
    return out


def load_findings(path: str | pathlib.Path) -> list[dict]:
    """Load findings from a native file or raw Inspector2 output (auto-detect)."""
    with open(path) as fh:
        doc = json.load(fh)
    if is_inspector2_doc(doc):
        return inspector2_to_findings(doc)
    findings = doc.get("findings", [])
    # Normalize: every finding needs the fields the scanner reads.
    for j, f in enumerate(findings):
        f.setdefault("id", f"EXT-{j + 1:03d}")
        f.setdefault("protocol", "TCP")
        f.setdefault("severity", "UNKNOWN")
    return findings
