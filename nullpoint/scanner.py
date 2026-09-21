"""NullPoint scan orchestrator: model proposes, code proves, product decides.

Pipeline per finding:
1. Nemotron extracts exploit preconditions from the CVE advisory (stubbed
   offline from recorded fixtures; live via Nebius Token Factory).
2. Tavily enriches with exploitability/weaponization metadata (stubbed offline).
3. The deterministic graph solver computes boolean reachability from the
   internet to (host, port, protocol).
4. The narrative guard fail-closed checks the LLM's exposure claim against
   the solver. A blocked claim routes the finding to human review — it is
   never silently dismissed or escalated.
5. Reachable  -> "actionable" (ranked queue).
   Unreachable -> "dismissed" (tamper-evident dismissal log entry).
"""
from __future__ import annotations

from . import graph as graph_mod
from .dismissal_log import DismissalLog
from .guard import NarrativeGuard
from .models import Verdict
from .nemotron import NemotronClient
from .tavily import TavilyClient


def run_scan(
    infra: dict,
    findings: list[dict],
    nemotron: NemotronClient,
    tavily: TavilyClient,
    guard: NarrativeGuard | None = None,
    dismissal_log: DismissalLog | None = None,
    source: str = graph_mod.INTERNET,
) -> dict:
    solver = graph_mod.InfraGraph(infra)
    guard = guard or NarrativeGuard()
    verdicts: list[Verdict] = []

    for finding in findings:
        cve_id = finding["cve_id"]
        host = finding["host"]
        pre = nemotron.extract_preconditions(cve_id, finding.get("description", ""))
        intel = tavily.get_exploitability(cve_id)
        reachable, trace = solver.check_reachability(source, host, pre.port, pre.protocol)
        allowed, guard_reason = guard.check(cve_id, host, pre.narrative_claim, reachable)

        verdict = Verdict(
            finding_id=finding["id"],
            cve_id=cve_id,
            host=host,
            port=pre.port,
            protocol=pre.protocol,
            reachable=reachable,
            trace=trace,
            guard_passed=allowed,
            exploitability=intel,
            preconditions={
                "port": pre.port,
                "protocol": pre.protocol,
                "auth_required": pre.auth_required,
                "network_vector": pre.network_vector,
                "payload_constraints": pre.payload_constraints,
                "confidence": pre.confidence,
                "narrative_claim": pre.narrative_claim,
            },
        )
        if not allowed:
            verdict.decision = "needs-review"
            verdict.reason = guard_reason
        elif reachable:
            verdict.decision = "actionable"
            verdict.reason = (
                f"solver proves {host}:{pre.port}/{pre.protocol} reachable from {source}; "
                f"KEV-listed={intel.get('kev_listed')}, weaponized={intel.get('weaponized')}"
            )
        else:
            verdict.decision = "dismissed"
            verdict.reason = solver.summarize_denial(trace)
            if dismissal_log is not None:
                dismissal_log.append({
                    "finding_id": verdict.finding_id,
                    "cve_id": cve_id,
                    "host": host,
                    "port": pre.port,
                    "protocol": pre.protocol,
                    "decision": "dismissed",
                    "reason": verdict.reason,
                    "guard": guard_reason,
                    "kev_listed": intel.get("kev_listed"),
                    "weaponized": intel.get("weaponized"),
                })
        verdicts.append(verdict)

    actionable = [v for v in verdicts if v.decision == "actionable"]
    # Rank reachable findings: weaponized + KEV-listed first, then EPSS.
    actionable.sort(
        key=lambda v: (
            bool(v.exploitability.get("weaponized")),
            bool(v.exploitability.get("kev_listed")),
            float(v.exploitability.get("epss") or 0),
        ),
        reverse=True,
    )
    return {
        "verdicts": verdicts,
        "actionable": actionable,
        "dismissed": [v for v in verdicts if v.decision == "dismissed"],
        "needs_review": [v for v in verdicts if v.decision == "needs-review"],
        "guard_events": guard.events,
        "raw_alert_count": len(findings),
    }
