"""Narrative guard — proves fail-closed behavior on LLM/solver disagreement."""
from nullpoint.guard import NarrativeGuard


def test_guard_blocks_false_exposed_claim():
    guard = NarrativeGuard()
    allowed, reason = guard.check("CVE-2026-42424", "i-analytics-1", "exposed", solver_reachable=False)
    assert allowed is False
    assert "BLOCKED" in reason
    assert len(guard.blocked_events()) == 1


def test_guard_blocks_false_isolated_claim():
    guard = NarrativeGuard()
    allowed, reason = guard.check("CVE-2026-31007", "i-gateway-1", "isolated", solver_reachable=True)
    assert allowed is False
    assert "BLOCKED" in reason


def test_guard_allows_agreement():
    guard = NarrativeGuard()
    allowed, _ = guard.check("CVE-2026-31007", "i-gateway-1", "exposed", solver_reachable=True)
    assert allowed is True
    allowed, _ = guard.check("CVE-2026-42424", "i-analytics-1", "isolated", solver_reachable=False)
    assert allowed is True
    assert guard.blocked_events() == []


def test_guard_fails_closed_on_ambiguous_claim():
    guard = NarrativeGuard()
    for claim in ("unknown", "", "maybe", "EXPOSED "):  # trailing space is fine -> exposed
        allowed, _ = guard.check("CVE-X", "h", claim, solver_reachable=True)
        if claim.strip().lower() in ("exposed", "isolated"):
            assert allowed is True
        else:
            assert allowed is False, f"ambiguous claim {claim!r} must fail closed"


def test_guard_logs_every_check():
    guard = NarrativeGuard()
    guard.check("CVE-A", "h1", "exposed", True)
    guard.check("CVE-B", "h2", "isolated", False)
    assert len(guard.events) == 2
    assert all("ts" in e and "reason" in e for e in guard.events)
