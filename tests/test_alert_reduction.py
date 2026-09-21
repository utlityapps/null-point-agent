"""Alert-volume reduction: raw scanner output vs NullPoint actionable queue.

The thesis in numbers: a naive scanner emits one Critical alert per
vulnerable service (11 here). NullPoint falsifies exploitability and keeps
only findings with a reachable execution path from untrusted networks.
"""
from nullpoint.dismissal_log import DismissalLog
from nullpoint.guard import NarrativeGuard
from nullpoint.nemotron import NemotronClient
from nullpoint.scanner import run_scan
from nullpoint.tavily import TavilyClient


def _offline_report(infra, findings, fixtures_dir, tmp_path):
    nemotron = NemotronClient.from_fixtures(fixtures_dir, offline=True)
    tavily = TavilyClient.from_fixtures(fixtures_dir, offline=True)
    log = DismissalLog(str(tmp_path / "dismissals.jsonl"))
    return run_scan(infra, findings, nemotron, tavily, NarrativeGuard(), log), log


def test_order_of_magnitude_reduction(infra, findings, fixtures_dir, tmp_path):
    report, _ = _offline_report(infra, findings, fixtures_dir, tmp_path)
    raw = report["raw_alert_count"]
    actionable = len(report["actionable"])
    assert raw == 11
    assert actionable == 1
    assert raw / actionable >= 10  # order-of-magnitude reduction


def test_only_reachable_finding_is_actionable(infra, findings, fixtures_dir, tmp_path):
    report, _ = _offline_report(infra, findings, fixtures_dir, tmp_path)
    assert [v.finding_id for v in report["actionable"]] == ["F-011"]
    assert report["actionable"][0].host == "i-gateway-1"


def test_every_dismissal_has_a_logged_reason(infra, findings, fixtures_dir, tmp_path):
    report, log = _offline_report(infra, findings, fixtures_dir, tmp_path)
    entries = log.entries()
    assert len(entries) == len(report["dismissed"]) == 10
    for entry in entries:
        assert entry["decision"] == "dismissed"
        assert entry["reason"], "dismissal without a reason is not allowed"
    ok, msg = log.verify()
    assert ok, msg


def test_dismissed_log4j_finding_names_the_blockers(infra, findings, fixtures_dir, tmp_path):
    report, _ = _offline_report(infra, findings, fixtures_dir, tmp_path)
    f001 = next(v for v in report["dismissed"] if v.finding_id == "F-001")
    assert "internal" in f001.reason
