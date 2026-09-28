"""NullPoint demo CLI — the one-command offline judge run.

Usage:
    python -m nullpoint.cli scan --offline
    python -m nullpoint.cli scan --live        # requires NEBIUS_API_KEY (+ TAVILY_API_KEY)

Offline (default when no key is present): everything runs from the recorded
fixtures; no network, no credentials, no setup friction.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib

from . import graph as graph_mod
from .dismissal_log import DismissalLog
from .findings import load_findings
from .guard import NarrativeGuard
from .nemotron import NemotronClient
from .scanner import run_scan
from .tavily import TavilyClient

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "fixtures"


def load_json(path: pathlib.Path) -> dict:
    with open(path) as fh:
        return json.load(fh)


def _reduction_str(raw: int, n_act: int) -> str:
    # Never print a fake ratio when nothing is actionable.
    if n_act <= 0:
        return "no actionable findings"
    return f"{raw / n_act:.0f}x reduction"


def cmd_scan(args: argparse.Namespace) -> int:
    infra_path = pathlib.Path(args.infra) if args.infra else FIXTURES / "infra.json"
    infra = load_json(infra_path)
    if args.findings:
        findings = load_findings(args.findings)
        print(f"Loaded {len(findings)} findings from {args.findings}")
    else:
        findings = load_json(FIXTURES / "cves.json")["findings"]

    live_nemotron = bool(args.live and os.environ.get("NEBIUS_API_KEY"))
    live_tavily = bool(args.live and os.environ.get("TAVILY_API_KEY"))
    offline = not (live_nemotron or live_tavily)
    nemotron = NemotronClient.from_fixtures(str(FIXTURES), offline=not live_nemotron)
    tavily = TavilyClient.from_fixtures(str(FIXTURES), offline=not live_tavily)

    log_path = args.log_path or str(REPO_ROOT / "dismissals.jsonl")
    if os.path.exists(log_path) and args.fresh_log:
        os.remove(log_path)
    dismissal_log = DismissalLog(log_path)
    guard = NarrativeGuard()

    mode = "OFFLINE judge mode (recorded fixtures, zero credentials)" if offline else "LIVE mode"
    print(f"NullPoint Agent v0.1.0 — {mode}")
    print(f"Scanning {len(findings)} scanner findings against network telemetry...\n")

    report = run_scan(infra, findings, nemotron, tavily, guard, dismissal_log)

    # The refusal moment: the pre-auth RCE finding on the internal cluster.
    for v in report["verdicts"]:
        if v.finding_id == "F-001":
            print("─" * 64)
            print("THE REFUSAL MOMENT")
            print("─" * 64)
            print(f"Generic scanner says: CRITICAL {v.cve_id} on {v.host} — patch everything, now.")
            print(f"NullPoint solver:    {v.reason}")
            print(f"NullPoint decision:  {v.decision.upper()} — no reachable execution path.")
            print("─" * 64 + "\n")

    print("ACTIONABLE QUEUE (reachable from untrusted networks):")
    if not report["actionable"]:
        print("  (empty)")
    for v in report["actionable"]:
        intel = v.exploitability
        print(f"  ! [{v.finding_id}] {v.cve_id} on {v.host}:{v.port}/{v.protocol}")
        print(f"      {v.reason}")
        print(f"      intel: {intel.get('summary', '')[:110]}")

    print("\nDISMISSED (zero reachable execution path — see tamper-evident log):")
    for v in report["dismissed"]:
        print(f"  - [{v.finding_id}] {v.cve_id} on {v.host}:{v.port} — {v.reason[:100]}")

    if report["needs_review"]:
        print("\nNEEDS HUMAN REVIEW (payload delivery not falsifiable by network proof):")
        for v in report["needs_review"]:
            print(f"  ? [{v.finding_id}] {v.reason}")

    blocked = [e for e in report["guard_events"] if not e["allowed"]]
    print(f"\nNarrative guard: {len(report['guard_events'])} checks, {len(blocked)} blocked")
    ok, msg = dismissal_log.verify()
    print(f"Tamper-evident dismissal log: {log_path} — {msg}")
    print(f"\nAlert volume: {report['raw_alert_count']} raw Critical alerts -> "
          f"{len(report['actionable'])} actionable "
          f"({_reduction_str(report['raw_alert_count'], len(report['actionable']))})")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nullpoint", description="NullPoint Agent — falsify exploitability.")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Run the offline/online scan over fixtures.")
    scan.add_argument("--offline", action="store_true", help="Force offline stub mode (default without keys).")
    scan.add_argument("--live", action="store_true", help="Use live Nebius/Tavily APIs (requires API keys).")
    scan.add_argument("--log-path", default=None, help="Where to write dismissals.jsonl.")
    scan.add_argument("--fresh-log", action="store_true", help="Start a new dismissal log chain.")
    scan.add_argument("--infra", default=None,
                      help="Path to infra.json (default: fixtures/infra.json). "
                           "Use the AWS importer's output to scan real infrastructure.")
    scan.add_argument("--findings", default=None,
                      help="Path to findings JSON (default: fixtures/cves.json). "
                           "Accepts native findings or raw `aws inspector2 list-findings` output.")
    args = parser.parse_args(argv)
    if args.command == "scan":
        return cmd_scan(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
