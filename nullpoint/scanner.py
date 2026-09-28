"""NullPoint scan orchestrator: model proposes, code proves, product decides.

Pipeline per finding:
0. Fail-closed input checks (before any proof is attempted):
   - host not in the infra snapshot -> "needs-review". Absence of evidence
     (another region, stale inventory) is not evidence of non-exposure.
   - no observed port on the finding -> "needs-review". Nothing to test.
   - model port/protocol disagrees with the scanner's observed
     port/protocol -> "needs-review". The solver tests the OBSERVED port,
     never the model's guess: a wrong model port that dismisses a real
     ticket is fail-open.
1. Nemotron extracts exploit preconditions from the CVE advisory (stubbed
   offline from recorded fixtures; live via Nebius Token Factory).
2. Tavily enriches with exploitability/weaponization metadata (stubbed offline).
3. The deterministic graph solver computes boolean reachability from the
   internet to (host, observed port, observed protocol).
4. The narrative guard fail-closed checks the LLM's exposure claim against
   the solver. The solver always wins: a blocked claim is logged as a caught
   model error, but it never overrides the solver's verdict — a blocked
   claim is never silently acted on, and never vetoes a proof.
5. Reachable  -> "actionable" (ranked queue). Proven exposure outranks
   payload routing: a reachable finding is queued even for data-plane
   payloads.
   Unreachable + data-plane/unknown delivery -> "needs-review". A network
   proof cannot falsify data-plane delivery, so fail closed to a human,
   never to "dismissed".
   Unreachable + direct delivery -> "dismissed" (tamper-evident dismissal
   log entry).
"""
from __future__ import annotations

from . import graph as graph_mod
from .dismissal_log import DismissalLog
from .guard import NarrativeGuard
from .models import Verdict
from .nemotron import NemotronClient
from .tavily import TavilyClient


# Payload delivery comes from the extraction as a structured field
# ("direct" | "data_plane" | "unknown"), not keyword matching: the model
# makes the judgment call, and anything but an explicit "direct" fails
# closed to human review. A network reachability proof cannot falsify
# data-plane delivery (cf. Log4Shell via log pipelines).


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
        preconditions = {
            "port": pre.port,
            "protocol": pre.protocol,
            "auth_required": pre.auth_required,
            "network_vector": pre.network_vector,
            "delivery": pre.delivery,
            "payload_constraints": pre.payload_constraints,
            "confidence": pre.confidence,
            "narrative_claim": pre.narrative_claim,
        }
        observed_port = finding.get("port")
        observed_proto = str(finding.get("protocol") or "TCP").upper()
        verdict = Verdict(
            finding_id=finding["id"],
            cve_id=cve_id,
            host=host,
            port=int(observed_port or 0),
            protocol=observed_proto,
            reachable=False,
            guard_passed=True,
            exploitability=intel,
            preconditions=preconditions,
        )
        guard_reason = ""

        if host not in solver.G:
            # Fail closed: a host missing from the snapshot (another region,
            # a new instance, stale inventory) is absence of evidence, not
            # evidence of absence — it must never be dismissed as "no exposure".
            verdict.decision = "needs-review"
            verdict.reason = (
                f"host {host} is not in the infrastructure snapshot "
                "(wrong region? stale inventory?) — cannot prove non-exposure; "
                "failing closed to human review"
            )
        elif observed_port is None:
            # Fail closed: no observed port means nothing for the solver to test.
            verdict.decision = "needs-review"
            verdict.reason = (
                "the finding carries no observed port — there is nothing for "
                "the solver to test; failing closed to human review"
            )
        elif int(observed_port) != pre.port or observed_proto != pre.protocol.upper():
            # Fail closed: the solver tests the OBSERVED port, not the model's
            # guess — a wrong model port that dismisses a real ticket is
            # fail-open. On disagreement we cannot tell which side is right.
            verdict.decision = "needs-review"
            verdict.reason = (
                f"the model extracted {pre.port}/{pre.protocol} but the scanner "
                f"observed {observed_port}/{observed_proto} — cannot tell which "
                "is right; failing closed to human review"
            )
        else:
            reachable, trace = solver.check_reachability(
                source, host, int(observed_port), observed_proto)
            allowed, guard_reason = guard.check(cve_id, host, pre.narrative_claim, reachable)
            verdict.reachable = reachable
            verdict.trace = trace
            verdict.guard_passed = allowed
            if reachable:
                verdict.decision = "actionable"
                verdict.reason = (
                    f"solver proves {host}:{int(observed_port)}/{observed_proto} "
                    f"reachable from {source}; "
                    f"KEV-listed={intel.get('kev_listed')}, weaponized={intel.get('weaponized')}"
                )
            elif pre.delivery != "direct":
                # The solver found no network path, but the payload may arrive
                # via the data plane (logs, headers, queues) — a network proof
                # cannot establish non-exposure, so fail closed to human review,
                # never to "dismissed". (Reachable findings are already queued
                # above: proven exposure outranks payload routing.)
                verdict.decision = "needs-review"
                verdict.reason = (
                    f"payload delivery is {pre.delivery!r}, not a direct network "
                    "connection; network reachability proof cannot establish "
                    "non-exposure"
                )
            else:
                verdict.decision = "dismissed"
                verdict.reason = solver.summarize_denial(trace)
            if not allowed:
                # The solver always wins: a blocked narrative claim is recorded
                # as a caught model error, but it never overrides the solver's
                # verdict — neither to suppress a real ticket nor to veto a proof.
                # Own sentence, not buried mid-paragraph.
                if not verdict.reason.endswith("."):
                    verdict.reason += "."
                verdict.reason += (
                    f" Guard: blocked the LLM's {pre.narrative_claim!r} exposure claim "
                    f"({guard_reason}); the solver's verdict stands."
                )
        if verdict.decision == "dismissed" and dismissal_log is not None:
            dismissal_log.append({
                "finding_id": verdict.finding_id,
                "cve_id": cve_id,
                "host": host,
                "port": verdict.port,
                "protocol": verdict.protocol,
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
