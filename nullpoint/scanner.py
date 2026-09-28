"""NullPoint scan orchestrator: model proposes, code proves, product decides.

Pipeline per finding — prove first, then doubt:
0. Unknown host (not in the infra snapshot) -> "needs-review". Absence of
   evidence (another region, stale inventory) is not evidence of non-exposure.
1. Nemotron extracts exploit preconditions from the CVE advisory (stubbed
   offline from recorded fixtures; live via Nebius Token Factory).
2. Tavily enriches with exploitability/weaponization metadata (stubbed offline).
3. PROVE: if the host has no network path from the source on ANY port, the
   proof holds for every port — direct-delivery findings are dismissed even
   with no observed port or a wrong model port. (Data-plane/unknown delivery
   still goes to review: a network proof cannot falsify data-plane delivery.)
4. Otherwise the host has some internet path: test the scanner's OBSERVED
   port AND the model's port if different. Doubt is resolved by proof, not
   by review — if either is reachable the finding is actionable. A wrong
   model port can delay nothing: it can only add a ticket, never dismiss one.
5. The narrative guard fail-closed checks the LLM's exposure claim against
   the solver. The solver always wins: a blocked claim is logged as a caught
   model error, but it never overrides the solver's verdict — a blocked
   claim is never silently acted on, and never vetoes a proof.
6. Reachable  -> "actionable" (ranked queue). Proven exposure outranks
   payload routing: a reachable finding is queued even for data-plane
   payloads.
   Unreachable + data-plane/unknown delivery -> "needs-review".
   Unreachable + direct delivery -> "dismissed" (tamper-evident dismissal
   log entry).

Per-finding isolation: each finding is processed inside its own try/except.
An unrecorded CVE in offline mode, a failed live Nemotron/Tavily call, or
any other per-finding error sends THAT finding to review — it never crashes
the scan.
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


def _note_blocked_claim(verdict: Verdict, narrative_claim: str,
                        guard_reason: str, allowed: bool) -> None:
    # The solver always wins: a blocked narrative claim is recorded as a
    # caught model error, but it never overrides the solver's verdict —
    # neither to suppress a real ticket nor to veto a proof.
    # Own sentence, not buried mid-paragraph.
    if allowed:
        return
    if not verdict.reason.endswith("."):
        verdict.reason += "."
    verdict.reason += (
        f" Guard: blocked the LLM's {narrative_claim!r} exposure claim "
        f"({guard_reason}); the solver's verdict stands."
    )


def _gap_reason(host: str, gaps: list[dict]) -> str:
    codes = ", ".join(sorted({g.get("code", "?") for g in gaps}))
    return (f"the network model has coverage gap(s) affecting {host} ({codes}) — "
            "cannot prove non-exposure; failing closed to human review")


def _scan_one(
    solver: graph_mod.InfraGraph,
    finding: dict,
    nemotron: NemotronClient,
    tavily: TavilyClient,
    guard: NarrativeGuard,
    source: str,
) -> tuple[Verdict, str]:
    cve_id = finding["cve_id"]
    host = finding["host"]
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
    )
    try:
        pre = nemotron.extract_preconditions(cve_id, finding.get("description", ""))
        intel = tavily.get_exploitability(cve_id)
    except Exception as exc:  # noqa: BLE001 — fail closed, never crash the scan
        # Per-finding isolation: one bad finding (unrecorded CVE offline, a
        # failed live API call, malformed input) goes to human review. The
        # scan continues with the rest.
        verdict.decision = "needs-review"
        verdict.reason = (
            f"could not process this finding ({type(exc).__name__}: {exc}) — "
            "failing closed to human review"
        )
        verdict.exploitability = {}
        verdict.preconditions = {}
        return verdict, ""

    verdict.exploitability = intel
    verdict.preconditions = {
        "port": pre.port,
        "protocol": pre.protocol,
        "auth_required": pre.auth_required,
        "network_vector": pre.network_vector,
        "delivery": pre.delivery,
        "payload_constraints": pre.payload_constraints,
        "confidence": pre.confidence,
        "narrative_claim": pre.narrative_claim,
    }
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
        return verdict, guard_reason
    elif not solver.has_any_path(source, host):
        # PROVE FIRST: no network path from the source to this host on ANY
        # port. The proof holds for every port, so a missing observed port
        # or a wrong model port cannot weaken it. Probe one port anyway for
        # the evidence trace (why there is no path), not for the decision.
        probe_port = int(observed_port) if observed_port is not None else pre.port
        _, trace = solver.check_reachability(source, host, probe_port, observed_proto)
        verdict.trace = trace
        allowed, guard_reason = guard.check(cve_id, host, pre.narrative_claim, False)
        verdict.guard_passed = allowed
        gaps = solver.coverage_gaps_for(host)
        if gaps:
            # The "no path on any port" proof is unsound when the model
            # cannot see part of the network (auth actions, weighted
            # forwards, IP targets, unevaluated rules, IPv6 routes).
            verdict.decision = "needs-review"
            verdict.reason = _gap_reason(host, gaps)
        elif pre.delivery == "direct":
            verdict.decision = "dismissed"
            verdict.reason = (
                f"no network path from {source} to {host} on any port — the "
                f"proof holds regardless of port ({solver.summarize_denial(trace)})"
            )
        else:
            verdict.decision = "needs-review"
            verdict.reason = (
                f"no network path from {source} to {host}, but payload delivery "
                f"is {pre.delivery!r} — a network proof cannot falsify "
                "data-plane delivery; failing closed to human review"
            )
        _note_blocked_claim(verdict, pre.narrative_claim, guard_reason, allowed)
    else:
        # The host has some internet path: resolve doubt by proof. Test the
        # scanner's OBSERVED port and the model's port if different — if
        # either is reachable, the finding is actionable. A wrong model port
        # can only add a ticket here, never dismiss one.
        candidates: list[tuple[int, str]] = []
        if observed_port is not None:
            candidates.append((int(observed_port), observed_proto))
        model_pp = (pre.port, pre.protocol.upper())
        if model_pp not in candidates:
            candidates.append(model_pp)
        if not candidates:
            verdict.decision = "needs-review"
            verdict.reason = (
                "no observed port and no model port — there is nothing for "
                "the solver to test; failing closed to human review"
            )
        else:
            traces: list[dict] = []
            reachable_any = False
            for cport, cproto in candidates:
                r, t = solver.check_reachability(source, host, cport, cproto)
                traces.extend(t)
                if r:
                    reachable_any = True
                    verdict.port, verdict.protocol = cport, cproto
                    break
            verdict.reachable = reachable_any
            verdict.trace = traces
            allowed, guard_reason = guard.check(
                cve_id, host, pre.narrative_claim, reachable_any)
            verdict.guard_passed = allowed
            if reachable_any:
                verdict.decision = "actionable"
                verdict.reason = (
                    f"solver proves {host}:{verdict.port}/{verdict.protocol} "
                    f"reachable from {source}; "
                    f"KEV-listed={intel.get('kev_listed')}, weaponized={intel.get('weaponized')}"
                )
            elif solver.coverage_gaps_for(host):
                verdict.decision = "needs-review"
                verdict.reason = _gap_reason(host, solver.coverage_gaps_for(host))
            elif observed_port is None:
                # No observed port and the model's guessed port is
                # unreachable: trusting the guess would dismiss the finding
                # on the model's word alone — the failure this product
                # exists to prevent. There is nothing proven either way.
                verdict.decision = "needs-review"
                verdict.reason = (
                    f"no observed port; only the model's guessed port "
                    f"{pre.port}/{pre.protocol} was tested and it is unreachable — "
                    "failing closed to human review"
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
                verdict.reason = solver.summarize_denial(traces)
            _note_blocked_claim(verdict, pre.narrative_claim, guard_reason, allowed)
    return verdict, guard_reason


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
        try:
            verdict, guard_reason = _scan_one(solver, finding, nemotron, tavily, guard, source)
        except Exception as exc:  # noqa: BLE001 — malformed findings never crash the scan
            # The inner try in _scan_one only wraps the API calls; anything
            # else (missing host, a port like "8443/tcp") lands here and
            # fails closed to human review instead of aborting the scan.
            fid = finding.get("id", "?") if isinstance(finding, dict) else "?"
            cve = finding.get("cve_id", "?") if isinstance(finding, dict) else "?"
            host = finding.get("host", "?") if isinstance(finding, dict) else "?"
            verdict = Verdict(
                finding_id=str(fid), cve_id=str(cve), host=str(host),
                port=0, protocol="TCP", reachable=False, guard_passed=True,
                decision="needs-review",
                reason=(f"malformed finding ({type(exc).__name__}: {exc}) — "
                        "failing closed to human review"),
            )
            guard_reason = ""
        if verdict.decision == "dismissed" and dismissal_log is not None:
            dismissal_log.append({
                "finding_id": verdict.finding_id,
                "cve_id": verdict.cve_id,
                "host": verdict.host,
                "port": verdict.port,
                "protocol": verdict.protocol,
                "decision": "dismissed",
                "reason": verdict.reason,
                "guard": guard_reason,
                "kev_listed": verdict.exploitability.get("kev_listed"),
                "weaponized": verdict.exploitability.get("weaponized"),
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
