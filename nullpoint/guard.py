"""Narrative guard — fail-closed check on LLM exposure claims.

The LLM proposes a narrative claim about a host ("exposed" / "isolated" /
"unknown"). The deterministic solver has already computed ground truth.
If the claim disagrees with the solver — or is ambiguous — the claim is
BLOCKED and the event is logged. The solver always wins; the guard is what
lets us put an LLM in the loop without letting it hallucinate reachability.

This is the mechanism behind "numbers never pass through the LLM": the
model narrates, the code decides.
"""
from __future__ import annotations

import datetime as dt


class NarrativeGuard:
    def __init__(self):
        self.events: list[dict] = []

    def check(self, cve_id: str, host: str, claim: str, solver_reachable: bool) -> tuple[bool, str]:
        """Return (allowed, reason). Fail closed on mismatch or ambiguity."""
        normalized = (claim or "").strip().lower()
        if normalized == "exposed" and solver_reachable:
            allowed, reason = True, "claim 'exposed' agrees with solver (reachable)"
        elif normalized == "isolated" and not solver_reachable:
            allowed, reason = True, "claim 'isolated' agrees with solver (unreachable)"
        elif normalized == "exposed":
            allowed, reason = False, "BLOCKED: LLM claims 'exposed' but solver proves unreachable"
        elif normalized == "isolated":
            allowed, reason = False, "BLOCKED: LLM claims 'isolated' but solver proves reachable"
        else:
            allowed, reason = False, f"BLOCKED: ambiguous claim {claim!r} — fail closed"
        self.events.append({
            "ts": dt.datetime.now(dt.timezone.utc).isoformat(),
            "cve_id": cve_id,
            "host": host,
            "claim": normalized,
            "solver_reachable": solver_reachable,
            "allowed": allowed,
            "reason": reason,
        })
        return allowed, reason

    def blocked_events(self) -> list[dict]:
        return [e for e in self.events if not e["allowed"]]
