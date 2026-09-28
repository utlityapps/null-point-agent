"""Fail-closed regression tests: never dismiss what the product cannot prove.

Three holes closed 2026-09-27 (external review round 3):
1. A finding whose host is not in the infra snapshot was DISMISSED as
   "unknown host" — absence of evidence treated as evidence of absence.
   Now: needs-review.
2. The solver tested the port the MODEL guessed and ignored the port the
   scanner observed. A wrong model port could dismiss a real ticket
   (verified: changing the model's port on the gateway finding from 8443
   to 443 dismissed the only real ticket). Now: the solver tests the
   OBSERVED port; model/observation disagreement goes to needs-review.
3. A finding with no observed port at all has nothing for the solver to
   test. Now: needs-review.
"""
import copy

import pytest

from nullpoint.dismissal_log import DismissalLog
from nullpoint.guard import NarrativeGuard
from nullpoint.models import Preconditions
from nullpoint.scanner import run_scan
from nullpoint.tavily import TavilyClient


class _StubNemotron:
    """Fixed extraction regardless of CVE (offline, no network)."""

    def __init__(self, port, protocol="TCP", delivery="direct",
                 narrative_claim="exposed"):
        self.pre = Preconditions(
            port=port, protocol=protocol, delivery=delivery,
            narrative_claim=narrative_claim, confidence=0.9,
        )

    def extract_preconditions(self, cve_id, description=""):
        return self.pre


@pytest.fixture()
def tavily(fixtures_dir):
    return TavilyClient.from_fixtures(fixtures_dir)


def _finding(findings, fid):
    return copy.deepcopy(next(f for f in findings if f["id"] == fid))


def test_unknown_host_goes_to_review_not_dismissed(infra, findings, tavily, tmp_path):
    f = _finding(findings, "F-001")
    f["host"] = "i-does-not-exist"  # e.g. another region describe-* never saw
    log = DismissalLog(str(tmp_path / "d.jsonl"))
    report = run_scan(infra, [f], _StubNemotron(8080), tavily, NarrativeGuard(), log)
    assert report["dismissed"] == []
    assert report["actionable"] == []
    assert len(report["needs_review"]) == 1
    assert "not in the infrastructure snapshot" in report["needs_review"][0].reason
    ok, msg = log.verify()
    assert ok, msg


def test_finding_without_observed_port_goes_to_review(infra, findings, tavily):
    f = _finding(findings, "F-011")
    del f["port"]
    report = run_scan(infra, [f], _StubNemotron(8443), tavily, NarrativeGuard(), None)
    assert report["dismissed"] == []
    assert report["actionable"] == []
    assert len(report["needs_review"]) == 1
    assert "no observed port" in report["needs_review"][0].reason


def test_wrong_model_port_cannot_dismiss_real_ticket(infra, findings, tavily):
    # F-011 is the reachable gateway finding (scanner observed 8443/TCP).
    # A model that guesses 443 must not get the real ticket dismissed —
    # previously it did.
    f = _finding(findings, "F-011")
    report = run_scan(infra, [f], _StubNemotron(443), tavily, NarrativeGuard(), None)
    assert report["dismissed"] == []
    assert report["actionable"] == []
    assert len(report["needs_review"]) == 1
    assert "model extracted" in report["needs_review"][0].reason


def test_correct_model_port_keeps_real_ticket(infra, findings, tavily):
    # Sanity: when the model agrees with the observation, the reachable
    # finding is still queued as actionable.
    f = _finding(findings, "F-011")
    report = run_scan(infra, [f], _StubNemotron(8443), tavily, NarrativeGuard(), None)
    assert len(report["actionable"]) == 1
    assert report["actionable"][0].finding_id == "F-011"
    assert report["actionable"][0].port == 8443  # the observed port, not a guess


def test_protocol_mismatch_goes_to_review(infra, findings, tavily):
    f = _finding(findings, "F-011")
    report = run_scan(infra, [f], _StubNemotron(8443, protocol="UDP"),
                      tavily, NarrativeGuard(), None)
    assert report["dismissed"] == []
    assert len(report["needs_review"]) == 1


def test_reduction_str_never_fakes_a_ratio_with_zero_actionable():
    from nullpoint.cli import _reduction_str
    assert _reduction_str(11, 0) == "no actionable findings"
    assert _reduction_str(11, 1) == "11x reduction"
