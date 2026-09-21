"""Offline judge mode: the full pipeline runs with zero credentials and no network."""
import json

import pytest
import requests

from nullpoint.dismissal_log import DismissalLog
from nullpoint.guard import NarrativeGuard
from nullpoint.nemotron import NemotronClient
from nullpoint.scanner import run_scan
from nullpoint.tavily import TavilyClient


@pytest.fixture(autouse=True)
def scrub_credentials(monkeypatch):
    for var in ("NEBIUS_API_KEY", "NEBIUS_BASE_URL", "NEBIUS_MODEL", "TAVILY_API_KEY"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def _boom(*a, **k):
        raise AssertionError("network access attempted in offline mode")
    monkeypatch.setattr(requests, "post", _boom)
    monkeypatch.setattr(requests, "get", _boom)


def test_full_scan_runs_offline(infra, findings, fixtures_dir, tmp_path):
    nemotron = NemotronClient.from_fixtures(fixtures_dir)  # no key -> offline
    tavily = TavilyClient.from_fixtures(fixtures_dir)
    assert nemotron.offline is True
    assert tavily.offline is True
    log = DismissalLog(str(tmp_path / "dismissals.jsonl"))
    report = run_scan(infra, findings, nemotron, tavily, NarrativeGuard(), log)
    assert report["raw_alert_count"] == len(findings) == 11
    assert len(report["actionable"]) == 1
    assert report["actionable"][0].finding_id == "F-011"
    assert len(report["dismissed"]) == 10
    assert report["needs_review"] == []
    ok, msg = log.verify()
    assert ok, msg


def test_offline_clients_never_require_keys(fixtures_dir):
    # Explicitly offline even if someone passes offline=True with no stubs dir issues.
    client = NemotronClient.from_fixtures(fixtures_dir, offline=True)
    pre = client.extract_preconditions("CVE-2026-42424", "ignored in stub mode")
    assert pre.port == 8080 and pre.protocol == "TCP"
    t = TavilyClient.from_fixtures(fixtures_dir, offline=True)
    intel = t.get_exploitability("CVE-2026-31007")
    assert intel["weaponized"] is True


def test_missing_stub_raises_clear_error(fixtures_dir):
    client = NemotronClient.from_fixtures(fixtures_dir, offline=True)
    with pytest.raises(Exception, match="no recorded Nemotron response"):
        client.extract_preconditions("CVE-2099-00000", "unknown advisory")


def test_no_credentials_in_fixtures():
    # Repo hygiene: fixtures must never contain anything key-like.
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[1]
    for name in ("fixtures/infra.json", "fixtures/cves.json",
                 "fixtures/recorded/nemotron_extractions.json",
                 "fixtures/recorded/tavily_responses.json"):
        text = (root / name).read_text().lower()
        assert "api_key" not in text, name
        assert "bearer" not in text, name
        assert "BEGIN PRIVATE KEY" not in text, name
