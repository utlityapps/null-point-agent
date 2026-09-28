"""Fail-closed regression tests: never dismiss what the product cannot prove.

Prove first, then doubt (2026-09-27, external review round 4): the round-3
doubt checks ran BEFORE the reachability proof, which delayed real tickets
(a wrong model port moved the only actionable finding to review) and sent
every port-less Inspector finding to review even on hosts with no internet
path at all. Now the any-port proof runs first:

- host with no internet path + direct delivery -> dismissed, even with no
  observed port or a wrong model port (the proof holds for every port).
- host with no internet path + data_plane/unknown delivery -> needs-review
  (a network proof cannot falsify data-plane delivery).
- host WITH an internet path -> test the observed port AND the model's port
  if different; doubt is resolved by proof. A wrong model port can only add
  a ticket, never dismiss one.
- unknown host -> needs-review (unchanged).
- per-finding errors (unrecorded CVE offline, failed live call) ->
  needs-review for that finding; the scan continues.

Kept from round 3: the solver tests the scanner's observed port — never the
model's guess alone — and missing ports fail closed when there is something
left to prove.
"""
import copy

import pytest

from nullpoint.dismissal_log import DismissalLog
from nullpoint.guard import NarrativeGuard
from nullpoint.models import Preconditions
from nullpoint.nemotron import NemotronClient
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


class _FailingNemotron:
    """Simulates a failed live API call."""

    def extract_preconditions(self, cve_id, description=""):
        raise RuntimeError("Nemotron returned empty content (simulated)")


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


def test_no_internet_path_dismisses_without_any_port(infra, findings, tavily):
    # F-001's host (i-analytics-1) has no internet path at all: the proof
    # holds for every port, so a missing observed port cannot weaken it.
    f = _finding(findings, "F-001")
    del f["port"]
    report = run_scan(infra, [f], _StubNemotron(8080), tavily, NarrativeGuard(), None)
    assert len(report["dismissed"]) == 1
    assert "any port" in report["dismissed"][0].reason


def test_no_internet_path_wrong_model_port_still_dismisses(infra, findings, tavily):
    # Same host, but the model guesses a wildly wrong port: the any-port
    # proof does not care.
    f = _finding(findings, "F-001")
    report = run_scan(infra, [f], _StubNemotron(443), tavily, NarrativeGuard(), None)
    assert len(report["dismissed"]) == 1
    assert report["needs_review"] == []


def test_no_internet_path_data_plane_goes_to_review(infra, findings, tavily):
    # No network path, but the payload may arrive via the data plane — a
    # network proof cannot falsify that.
    f = _finding(findings, "F-001")
    del f["port"]
    report = run_scan(infra, [f], _StubNemotron(8080, delivery="data_plane"),
                      tavily, NarrativeGuard(), None)
    assert report["dismissed"] == []
    assert len(report["needs_review"]) == 1
    assert "data-plane" in report["needs_review"][0].reason


def test_wrong_model_port_cannot_delay_real_ticket(infra, findings, tavily):
    # F-011 is the reachable gateway finding (scanner observed 8443/TCP).
    # A model that guesses 443 must not move the real ticket to review:
    # the observed port is tested and proves reachable.
    f = _finding(findings, "F-011")
    report = run_scan(infra, [f], _StubNemotron(443), tavily, NarrativeGuard(), None)
    assert report["dismissed"] == []
    assert report["needs_review"] == []
    assert len(report["actionable"]) == 1
    assert report["actionable"][0].port == 8443  # the observed port, not the guess


def test_correct_model_port_keeps_real_ticket(infra, findings, tavily):
    # Sanity: when the model agrees with the observation, the reachable
    # finding is still queued as actionable.
    f = _finding(findings, "F-011")
    report = run_scan(infra, [f], _StubNemotron(8443), tavily, NarrativeGuard(), None)
    assert len(report["actionable"]) == 1
    assert report["actionable"][0].finding_id == "F-011"
    assert report["actionable"][0].port == 8443  # the observed port, not a guess


def test_protocol_mismatch_resolved_by_proof(infra, findings, tavily):
    # Model says UDP, scanner observed TCP: both are tested, the reachable
    # observed TCP wins — doubt resolved by proof, not review.
    f = _finding(findings, "F-011")
    report = run_scan(infra, [f], _StubNemotron(8443, protocol="UDP"),
                      tavily, NarrativeGuard(), None)
    assert len(report["actionable"]) == 1
    assert report["actionable"][0].protocol == "TCP"


def test_missing_observed_port_tests_model_port(infra, findings, tavily):
    # i-gateway-1 HAS an internet path: with no observed port the model's
    # port is the only candidate — reachable, so actionable.
    f = _finding(findings, "F-011")
    del f["port"]
    report = run_scan(infra, [f], _StubNemotron(8443), tavily, NarrativeGuard(), None)
    assert len(report["actionable"]) == 1


def test_unrecorded_cve_goes_to_review_without_crashing_scan(
        infra, findings, fixtures_dir, tavily):
    # Claude's round-4 repro: a real CVE in offline mode raised OfflineError
    # and killed the whole scan with a traceback. Now that finding goes to
    # review and the scan completes.
    nemotron = NemotronClient.from_fixtures(fixtures_dir)  # offline stubs
    fs = [_finding(findings, "F-011")]
    bad = _finding(findings, "F-001")
    bad["id"] = "F-BAD"
    bad["cve_id"] = "CVE-2021-44228"  # no recorded stub
    fs.append(bad)
    fs.append(_finding(findings, "F-002"))
    report = run_scan(infra, fs, nemotron, tavily, NarrativeGuard(), None)
    assert len(report["actionable"]) == 1  # F-011 still queued
    assert report["actionable"][0].finding_id == "F-011"
    assert len(report["dismissed"]) == 1  # F-002 still dismissed
    assert len(report["needs_review"]) == 1
    v = report["needs_review"][0]
    assert v.finding_id == "F-BAD"
    assert "OfflineError" in v.reason


def test_failed_live_call_goes_to_review(infra, findings, tavily):
    f = _finding(findings, "F-011")
    report = run_scan(infra, [f], _FailingNemotron(), tavily, NarrativeGuard(), None)
    assert report["actionable"] == []
    assert report["dismissed"] == []
    assert len(report["needs_review"]) == 1
    assert "RuntimeError" in report["needs_review"][0].reason


def test_reduction_str_never_fakes_a_ratio_with_zero_actionable():
    from nullpoint.cli import _reduction_str
    assert _reduction_str(11, 0) == "no actionable findings"
    assert _reduction_str(11, 1) == "11x reduction"
