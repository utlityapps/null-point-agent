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


"""Scanner-level: the solver always wins when the guard blocks a claim."""

import json

from nullpoint.dismissal_log import DismissalLog
from nullpoint.nemotron import NemotronClient, _clean_delivery
from nullpoint.scanner import run_scan
from nullpoint.tavily import TavilyClient


def _clients(fixtures_dir):
    return (NemotronClient.from_fixtures(fixtures_dir),
            TavilyClient.from_fixtures(fixtures_dir))


def _with_claim(nemotron, cve_id, claim):
    nemotron.stub_responses[cve_id] = dict(
        nemotron.stub_responses[cve_id], narrative_claim=claim)


def _with_delivery(nemotron, cve_id, delivery):
    nemotron.stub_responses[cve_id] = dict(
        nemotron.stub_responses[cve_id], delivery=delivery)


def test_blocked_exposed_claim_keeps_solver_dismissal(
        infra, findings, fixtures_dir, tmp_path):
    # F-001 is unreachable; the model wrongly claims "exposed".
    findings = json.loads(json.dumps(findings))
    nemotron, tavily = _clients(fixtures_dir)
    _with_claim(nemotron, "CVE-2026-42424", "exposed")
    log = DismissalLog(str(tmp_path / "d.jsonl"))
    report = run_scan(infra, findings, nemotron, tavily, NarrativeGuard(), log)
    v = next(x for x in report["verdicts"] if x.finding_id == "F-001")
    assert v.decision == "dismissed"  # solver wins; NOT needs-review
    assert v.guard_passed is False
    assert "solver's verdict stands" in v.reason
    assert len(report["dismissed"]) == 10
    assert report["needs_review"] == []
    ok, msg = log.verify()
    assert ok, msg


def test_blocked_isolated_claim_keeps_solver_actionable(
        infra, findings, fixtures_dir, tmp_path):
    # F-011 IS reachable; the model hallucinating "isolated" must not
    # suppress the ticket — the dangerous direction.
    findings = json.loads(json.dumps(findings))
    nemotron, tavily = _clients(fixtures_dir)
    _with_claim(nemotron, "CVE-2026-31007", "isolated")
    log = DismissalLog(str(tmp_path / "d.jsonl"))
    report = run_scan(infra, findings, nemotron, tavily, NarrativeGuard(), log)
    v = next(x for x in report["verdicts"] if x.finding_id == "F-011")
    assert v.decision == "actionable"
    assert v.guard_passed is False
    assert "solver's verdict stands" in v.reason


def test_data_plane_payload_routes_to_review(
        infra, findings, fixtures_dir):
    # A data-plane payload cannot be falsified by a network proof,
    # even when the solver finds no path — cf. Log4Shell via log pipelines.
    findings = json.loads(json.dumps(findings))
    nemotron, tavily = _clients(fixtures_dir)
    _with_delivery(nemotron, "CVE-2026-42424", "data_plane")
    report = run_scan(infra, findings, nemotron, tavily, NarrativeGuard(), None)
    v = next(x for x in report["verdicts"] if x.finding_id == "F-001")
    assert v.decision == "needs-review"
    assert "data_plane" in v.reason


def test_unknown_delivery_fails_closed_to_review(
        infra, findings, fixtures_dir):
    # The advisory doesn't say how the payload arrives -> review, never dismissed.
    findings = json.loads(json.dumps(findings))
    nemotron, tavily = _clients(fixtures_dir)
    _with_delivery(nemotron, "CVE-2026-42424", "unknown")
    report = run_scan(infra, findings, nemotron, tavily, NarrativeGuard(), None)
    v = next(x for x in report["verdicts"] if x.finding_id == "F-001")
    assert v.decision == "needs-review"


def test_reachable_outranks_data_plane_routing(
        infra, findings, fixtures_dir):
    # Regression: the reachable branch runs BEFORE the data-plane check.
    # Proven exposure goes to the action queue even for data-plane payloads;
    # delaying a reachable ticket to "needs review" is a fail-open.
    findings = json.loads(json.dumps(findings))
    nemotron, tavily = _clients(fixtures_dir)
    _with_delivery(nemotron, "CVE-2026-31007", "data_plane")
    report = run_scan(infra, findings, nemotron, tavily, NarrativeGuard(), None)
    v = next(x for x in report["verdicts"] if x.finding_id == "F-011")
    assert v.decision == "actionable"


def test_delivery_cleaning_fails_closed():
    assert _clean_delivery("direct") == "direct"
    assert _clean_delivery("data_plane") == "data_plane"
    assert _clean_delivery("unknown") == "unknown"
    assert _clean_delivery("") == "unknown"
    assert _clean_delivery(None) == "unknown"
    assert _clean_delivery("DIRECT ") == "direct"
    assert _clean_delivery("side-channel") == "unknown"  # not a known value
