"""--findings: native findings and AWS Inspector2 conversion."""
import json

import pytest

from nullpoint.findings import (
    inspector2_to_findings,
    is_inspector2_doc,
    load_findings,
)
from nullpoint.guard import NarrativeGuard
from nullpoint.nemotron import NemotronClient
from nullpoint.scanner import run_scan
from nullpoint.tavily import TavilyClient


def _inspector2_doc():
    return {
        "findings": [
            {
                "findingArn": "arn:aws:inspector2:us-east-1:123:finding/abc",
                "awsAccountId": "123456789012",
                "type": "PACKAGE_VULNERABILITY",
                "title": "CVE-2026-31007 - admin-api",
                "description": "Pre-auth RCE in admin API.",
                "severity": "CRITICAL",
                "status": "ACTIVE",
                "resources": [
                    {"type": "AWS_EC2_INSTANCE", "id": "i-gateway-1"}
                ],
                "packageVulnerabilityDetails": {
                    "vulnerabilityId": "CVE-2026-31007",
                    "vulnerablePackages": [{"name": "admin-api", "version": "1.2.3"}],
                },
            },
            {
                # ECR image finding: no instance to map to.
                "findingArn": "arn:aws:inspector2:us-east-1:123:finding/def",
                "type": "PACKAGE_VULNERABILITY",
                "title": "CVE-2026-42424 - base-image",
                "description": "RCE in base image.",
                "severity": "HIGH",
                "status": "ACTIVE",
                "resources": [
                    {"type": "AWS_ECR_CONTAINER_IMAGE",
                     "id": "sha256:deadbeef"}
                ],
                "packageVulnerabilityDetails": {
                    "vulnerabilityId": "CVE-2026-42424",
                },
            },
        ],
        "nextToken": "tok",
    }


def test_detects_inspector2_output():
    assert is_inspector2_doc(_inspector2_doc()) is True
    assert is_inspector2_doc({"findings": [{"id": "F-001", "cve_id": "CVE-1"}]}) is False
    assert is_inspector2_doc({"findings": []}) is False


def test_inspector2_conversion_maps_fields():
    out = inspector2_to_findings(_inspector2_doc())
    assert len(out) == 2
    f1 = out[0]
    assert f1["id"] == "INSP-001"
    assert f1["cve_id"] == "CVE-2026-31007"
    assert f1["host"] == "i-gateway-1"
    assert f1["severity"] == "CRITICAL"
    assert f1["port"] is None  # Inspector2 carries no port
    # Image finding: host falls back to "unknown" (scanner fails it closed).
    assert out[1]["host"] == "unknown"


def test_load_findings_auto_detects(tmp_path):
    p = tmp_path / "insp.json"
    p.write_text(json.dumps(_inspector2_doc()))
    out = load_findings(p)
    assert [f["id"] for f in out] == ["INSP-001", "INSP-002"]

    n = tmp_path / "native.json"
    n.write_text(json.dumps({"findings": [{"id": "F-9", "cve_id": "CVE-X",
                                           "host": "h", "port": 80}]}))
    native = load_findings(n)
    assert native[0]["protocol"] == "TCP"  # defaults filled


def test_converted_finding_scans_offline_end_to_end(infra, fixtures_dir):
    # CVE-2026-31007 has recorded offline stubs; i-gateway-1 is in the
    # fixture infra. No observed port -> fail closed to human review.
    findings = inspector2_to_findings(_inspector2_doc())
    nemotron = NemotronClient.from_fixtures(fixtures_dir)
    tavily = TavilyClient.from_fixtures(fixtures_dir)
    report = run_scan(infra, findings[:1], nemotron, tavily, NarrativeGuard(), None)
    assert report["dismissed"] == []
    assert len(report["needs_review"]) == 1
    v = report["needs_review"][0]
    assert v.finding_id == "INSP-001"
    assert "no observed port" in v.reason
