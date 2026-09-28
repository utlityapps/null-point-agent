"""NullPoint dual-surface UI — self-contained static HTML report generator.

Renders the two product surfaces as a single offline HTML file (inline CSS +
vanilla JS, zero external assets, zero network):

1. Primary surface — Interactive Investigation Trace: pick any finding and see
   the hop-by-hop reachability trace from the deterministic solver alongside
   the LLM's proposed preconditions and reasoning, ending in the verdict.
2. Secondary surface — Ranked Action Queue vs Dismissed Proof Log: reachable
   findings ranked by exploitability intel; dismissed findings each expandable
   to show the falsification trace and the tamper-evident log entry.

Usage:
    python -m nullpoint.report --offline [--out report.html]

The scan always runs from recorded fixtures (judge mode): no credentials,
no network. A fresh, temporary dismissal chain is built per report so the
rendered log entries always match the verdicts.

Why static HTML instead of Streamlit: the repo's core promise is
credential-free, offline, deterministic judge runs. A single HTML file needs
no server, no extra dependencies (Streamlit would add ~100MB to the install),
opens in any browser, and screen-records cleanly for the demo video. All
interactivity (tabs, finding selector, expandable dismissals) is client-side.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import tempfile

from . import graph as graph_mod
from .dismissal_log import DismissalLog
from .findings import load_findings
from .guard import NarrativeGuard
from .nemotron import NemotronClient
from .scanner import run_scan
from .tavily import TavilyClient

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "fixtures"

HTML_TEMPLATE_PATH = pathlib.Path(__file__).with_name("_report_template.html")


def load_json(path: pathlib.Path):
    with open(path) as fh:
        return json.load(fh)


def run_offline_scan(infra_path=None, findings_path=None) -> tuple[dict, DismissalLog, list[dict], list[dict]]:
    """Run the full pipeline on recorded fixtures; return (report, log, entries, findings)."""
    infra = load_json(pathlib.Path(infra_path) if infra_path else FIXTURES / "infra.json")
    if findings_path:
        findings = load_findings(findings_path)
    else:
        findings = load_json(FIXTURES / "cves.json")["findings"]
    nemotron = NemotronClient.from_fixtures(str(FIXTURES), offline=True)
    tavily = TavilyClient.from_fixtures(str(FIXTURES), offline=True)
    tmp = tempfile.NamedTemporaryFile(prefix="nullpoint-dismissals-", suffix=".jsonl",
                                      delete=False)
    tmp.close()
    dismissal_log = DismissalLog(tmp.name)
    guard = NarrativeGuard()
    report = run_scan(infra, findings, nemotron, tavily, guard, dismissal_log,
                      source=graph_mod.INTERNET)
    return report, dismissal_log, dismissal_log.entries(), findings


def verdict_to_dict(v) -> dict:
    return {
        "finding_id": v.finding_id,
        "cve_id": v.cve_id,
        "host": v.host,
        "port": v.port,
        "protocol": v.protocol,
        "reachable": v.reachable,
        "decision": v.decision,
        "reason": v.reason,
        "guard_passed": v.guard_passed,
        "exploitability": v.exploitability or {},
        "preconditions": v.preconditions or {},
        "trace": v.trace or [],
    }


def assemble_data(report: dict, log: DismissalLog, entries: list[dict],
                  findings: list[dict]) -> dict:
    verdicts = [verdict_to_dict(v) for v in report["verdicts"]]
    titles = {f["id"]: {"title": f.get("title", ""), "description": f.get("description", "")}
              for f in findings}
    for v in verdicts:
        v.update(titles.get(v["finding_id"], {}))
    by_id = {v["finding_id"]: v for v in verdicts}
    dismissals = []
    for e in entries:
        v = by_id.get(e.get("finding_id"), {})
        dismissals.append({
            "finding_id": e.get("finding_id"),
            "cve_id": e.get("cve_id"),
            "host": e.get("host"),
            "port": e.get("port"),
            "protocol": e.get("protocol"),
            "reason": e.get("reason", ""),
            "guard": e.get("guard", ""),
            "kev_listed": e.get("kev_listed"),
            "weaponized": e.get("weaponized"),
            "seq": e.get("seq"),
            "ts": e.get("ts"),
            "hash": e.get("hash"),
            "prev_hash": e.get("prev_hash"),
            "trace": v.get("trace", []),
        })
    ok, msg = log.verify()
    guard_events = report.get("guard_events", [])
    return {
        "mode": "OFFLINE judge mode — recorded fixtures, zero credentials, zero network",
        "raw_alert_count": report["raw_alert_count"],
        "verdicts": verdicts,
        "actionable": [v["finding_id"] for v in verdicts if v["decision"] == "actionable"],
        "dismissed": [v["finding_id"] for v in verdicts if v["decision"] == "dismissed"],
        "needs_review": [v["finding_id"] for v in verdicts if v["decision"] == "needs-review"],
        "dismissals": dismissals,
        "guard": {
            "total": len(guard_events),
            "blocked": sum(1 for e in guard_events if not e.get("allowed")),
            "events": guard_events,
        },
        "chain": {"ok": ok, "msg": msg},
    }


def build_html(data: dict) -> str:
    template = HTML_TEMPLATE_PATH.read_text(encoding="utf-8")
    payload = json.dumps(data, separators=(",", ":"))
    # The template is a plain (non-f) string; inject the JSON payload and a
    # matching HTML-escaped copy for the <noscript>-free static preamble.
    return template.replace("__NULLPOINT_DATA__", payload)


def cmd_report(args: argparse.Namespace) -> int:
    report, log, entries, findings = run_offline_scan(args.infra, args.findings)
    data = assemble_data(report, log, entries, findings)
    out = pathlib.Path(args.out or str(REPO_ROOT / "nullpoint-report.html"))
    out.write_text(build_html(data), encoding="utf-8")
    # Clean up the temp chain file; the report embeds everything it needs.
    try:
        os.remove(log.path)
    except OSError:
        pass
    print(f"Wrote {out}")
    n_act = len(data["actionable"])
    reduction = (f"{data['raw_alert_count'] / n_act:.0f}x reduction"
                 if n_act > 0 else "no actionable findings")
    print(f"{data['raw_alert_count']} raw Critical alerts -> {n_act} actionable "
          f"({reduction}); "
          f"chain: {data['chain']['msg']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="nullpoint-report",
        description="Build the NullPoint dual-surface UI as a self-contained HTML file.",
    )
    parser.add_argument("--offline", action="store_true",
                        help="Run from recorded fixtures (the only supported mode).")
    parser.add_argument("--out", default=None, help="Output HTML path.")
    parser.add_argument("--infra", default=None,
                        help="Path to infra.json (default: fixtures/infra.json).")
    parser.add_argument("--findings", default=None,
                        help="Path to findings JSON: native findings or raw "
                             "`aws inspector2 list-findings` output "
                             "(default: fixtures/cves.json).")
    return cmd_report(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
