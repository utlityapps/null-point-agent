"""NullPoint scan orchestrator: model proposes, code proves, product decides.

Pipeline per finding:
1. Nemotron extracts exploit preconditions from the CVE advisory (stubbed
   offline from recorded fixtures; live via Nebius Token Factory).
2. Tavily enriches with exploitability/weaponization metadata (stubbed offline).
3. The deterministic graph solver computes boolean reachability from the
   internet to (host, port, protocol).
4. The narrative guard fail-closed checks the LLM's exposure claim against
   the solver. The solver always wins: a blocked claim is logged as a caught
   model error, but it never overrides the solver's verdict — a blocked
   claim is never silently acted on, and never vetoes a proof.
5. Data-plane payloads (log/header/queue-borne) cannot be falsified by a
   network reachability proof, so they route to human review, never to
   "dismissed".
6. Reachable  -> "actionable" (ranked queue).
   Unreachable -> "dismissed" (tamper-evident dismissal log entry).
"""
from __future__ import annotations

from . import graph as graph_mod
from .dismissal_log import DismissalLog
from .guard import NarrativeGuard
from .models import Verdict
from .nemotron import NemotronClient
from .tavily import TavilyClient


# Payload hints that the exploit travels via the data plane (log pipeline,
# HTTP headers, message queues) rather than a direct network connection.
# The reachability solver only models L3/L4 network paths, so it cannot
# prove non-exposure for these — e.g. Log4Shell reached internal systems
# through logged JNDI strings, not through direct connections. Findings
# with data-plane payloads route to human review, never to "dismissed".
_DATA_PLANE_HINTS = (
    "log message",
    "header value",
    "message queue",
    "log pipeline",
    "syslog",
    "jndi lookup",
)


def payload_via_data_plane(payload_constraints: str | None) -> bool:
    """True when the exploit payload travels via the data plane."""
    pc = (payload_constraints or "").lower()
    return any(h in pc for h in _DATA_PLANE_HINTS)


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
        if payload_via_data_plane(pre.payload_constraints):
            verdict.decision = "needs-review"
            verdict.reason = (
                "payload travels via data plane (log/header/queue); "
                "network reachability proof cannot establish non-exposure"
            )
        elif reachable:
            verdict.decision = "actionable"
            verdict.reason = (
                f"solver proves {host}:{pre.port}/{pre.protocol} reachable from {source}; "
                f"KEV-listed={intel.get('kev_listed')}, weaponized={intel.get('weaponized')}"
            )
        else:
            verdict.decision = "dismissed"
            verdict.reason = solver.summarize_denial(trace)
        if not allowed:
            # The solver always wins: a blocked narrative claim is recorded
            # as a caught model error, but it never overrides the solver's
            # verdict — neither to suppress a real ticket nor to veto a proof.
            verdict.reason += (
                f" | narrative guard blocked LLM claim ({guard_reason}); "
                "solver's verdict stands"
            )
        if verdict.decision == "dismissed" and dismissal_log is not None:
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
