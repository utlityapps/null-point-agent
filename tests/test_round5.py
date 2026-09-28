"""External review round 5 (2026-09-27): the real-account path.

The README invites judges to run the importer against their own AWS
account and feed it to the solver. Claude tested exactly that — an
internet-facing ALB in front of a private app instance — and the app
was dismissed several different ways. This is the failure the product
exists to prevent.

1. Real ALB listeners are HTTP/HTTPS (never "TCP"): map them to TCP in
   _proto_num, and let the app SG allow the ALB's subnet CIDRs (not just
   its SG reference) on the ALB->instance hop.
2. Fail closed on anything the network model cannot see: auth actions,
   weighted forwards, IP-type targets, unevaluated listener rules, IPv6
   routes. Parse what can be parsed; the rest goes to review.
3. A finding with no observed port (every Inspector finding) on an
   exposed host: if the model's guessed port is unreachable, the finding
   goes to review — never dismissed on the model's word alone.
4. Small stuff: malformed findings must not crash the scan; GHSA-only
   Inspector findings are kept and routed to review; the review-queue
   header no longer claims every review is about payload delivery.
"""
import copy

import pytest

from nullpoint import aws_import as ai
from nullpoint import graph as graph_mod
from nullpoint.dismissal_log import DismissalLog
from nullpoint.findings import inspector2_to_findings
from nullpoint.guard import NarrativeGuard
from nullpoint.models import Preconditions
from nullpoint.scanner import run_scan
from nullpoint.tavily import TavilyClient


class _StubNemotron:
    """Fixed extraction regardless of CVE (offline, no network)."""

    def __init__(self, port, protocol="TCP", delivery="direct"):
        self.pre = Preconditions(
            port=port, protocol=protocol, delivery=delivery,
            narrative_claim="exposed", confidence=0.9,
        )

    def extract_preconditions(self, cve_id, description=""):
        return self.pre


@pytest.fixture()
def tavily(fixtures_dir):
    return TavilyClient.from_fixtures(fixtures_dir)


# ---------------------------------------------------------------------------
# Fix 1: the real-ALB path. Internet-facing ALB (HTTPS listener) in front of
# a private app instance — the setup Claude tested on a real account.
# ---------------------------------------------------------------------------

def _alb_infra(app_sg_ingress):
    """Minimal VPC: internet-facing ALB (HTTPS 443) -> private app (8443)."""
    allow_all = {"protocol": "-1", "from_port": None, "to_port": None,
                 "cidr": "0.0.0.0/0"}
    return {
        "instances": [{
            "id": "i-app", "private_ip": "10.0.2.5", "public_ip": None,
            "subnet": "priv-1", "security_groups": ["sg-app"], "services": [],
        }],
        "internet_gateways": [{"id": "igw-1", "vpc": "vpc-1"}],
        "load_balancers": [{
            "id": "alb-1", "scheme": "internet-facing",
            "security_groups": ["sg-alb"], "subnets": ["pub-1"],
            "listeners": [{"port": 443, "protocol": "HTTPS",
                           "target_port": 8443, "targets": ["i-app"]}],
        }],
        "network_acls": [
            {"id": "acl-pub", "ingress": [dict(allow_all, rule_number=100,
                                               action="allow")],
             "egress": [dict(allow_all, rule_number=100, action="allow")],
             "subnet_ids": ["pub-1"]},
            {"id": "acl-priv", "ingress": [dict(allow_all, rule_number=100,
                                                action="allow")],
             "egress": [dict(allow_all, rule_number=100, action="allow")],
             "subnet_ids": ["priv-1"]},
        ],
        "route53": [],
        "route_tables": [
            {"id": "rtb-pub",
             "routes": [{"cidr": "10.0.0.0/16", "target": "local"},
                        {"cidr": "0.0.0.0/0", "target": "igw-1"}],
             "subnet_ids": ["pub-1"]},
            {"id": "rtb-priv",
             "routes": [{"cidr": "10.0.0.0/16", "target": "local"}],
             "subnet_ids": ["priv-1"]},
        ],
        "security_groups": [
            {"id": "sg-alb",
             "ingress": [{"protocol": "tcp", "from_port": 443, "to_port": 443,
                          "cidr": "0.0.0.0/0"}],
             "egress": [allow_all]},
            {"id": "sg-app", "ingress": [app_sg_ingress], "egress": [allow_all]},
        ],
        "subnets": [
            {"id": "pub-1", "cidr": "10.0.1.0/24", "vpc": "vpc-1",
             "az": "us-east-1a", "map_public_ip": True},
            {"id": "priv-1", "cidr": "10.0.2.0/24", "vpc": "vpc-1",
             "az": "us-east-1a", "map_public_ip": False},
        ],
        "transit_gateways": [],
        "vpcs": [{"id": "vpc-1", "cidr": "10.0.0.0/16"}],
        "coverage_gaps": [],
    }


def test_https_listener_matches_tcp_query():
    """Real ALB listeners are HTTPS, not TCP: the app behind one must not
    read as unreachable."""
    infra = _alb_infra({"protocol": "tcp", "from_port": 8443, "to_port": 8443,
                        "source_sg": "sg-alb"})
    solver = graph_mod.InfraGraph(infra)
    reachable, _ = solver.check_reachability(graph_mod.INTERNET, "i-app", 8443, "TCP")
    assert reachable is True


def test_app_sg_allowing_vpc_cidr_reachable_via_alb():
    """The app SG may allow the VPC CIDR instead of the ALB's SG: the ALB
    reaches the instance from an IP in its own subnets."""
    infra = _alb_infra({"protocol": "tcp", "from_port": 8443, "to_port": 8443,
                        "cidr": "10.0.0.0/16"})
    solver = graph_mod.InfraGraph(infra)
    reachable, _ = solver.check_reachability(graph_mod.INTERNET, "i-app", 8443, "TCP")
    assert reachable is True


def test_real_alb_path_end_to_end_not_dismissed(tavily):
    """Scanner view of Claude's real-account test: the app behind the ALB
    is reachable, so a finding on it is actionable, not dismissed."""
    infra = _alb_infra({"protocol": "tcp", "from_port": 8443, "to_port": 8443,
                        "cidr": "10.0.0.0/16"})
    nemotron = _StubNemotron(port=8443)
    findings = [{"id": "F-REAL", "cve_id": "CVE-2026-31007", "host": "i-app",
                 "port": 8443, "protocol": "TCP", "description": ""}]
    report = run_scan(infra, findings, nemotron, tavily, NarrativeGuard(), None)
    assert [v.decision for v in report["verdicts"]] == ["actionable"]


# ---------------------------------------------------------------------------
# Fix 2: fail closed on what the model cannot see (importer gaps).
# ---------------------------------------------------------------------------

def _elbv2_bundle(**over):
    bundle = {
        "load_balancers": [{
            "LoadBalancerArn": "arn:lb", "LoadBalancerName": "alb-1",
            "Scheme": "internet-facing", "SecurityGroups": ["sg-alb"],
            "AvailabilityZones": [{"SubnetId": "pub-1"}],
        }],
        "listeners": [{
            "ListenerArn": "arn:lst", "LoadBalancerArn": "arn:lb",
            "Port": 443, "Protocol": "HTTPS",
            "DefaultActions": [{"Type": "forward",
                                "TargetGroupArn": "arn:tg1"}],
        }],
        "target_groups": [
            {"TargetGroupArn": "arn:tg1", "Port": 8443, "TargetType": "instance"},
        ],
        "targets": {"arn:tg1": [{"Id": "i-app"}]},
    }
    bundle.update(over)
    return bundle


def test_auth_action_before_forward_is_parsed_and_gapped():
    """DefaultActions[0] may be authenticate-oidc; the forward after it must
    still be parsed (the old code dropped it -> false dismissal)."""
    bundle = _elbv2_bundle()
    bundle["listeners"][0]["DefaultActions"] = [
        {"Type": "authenticate-oidc",
         "AuthenticateOidcConfig": {"Issuer": "https://x"}},
        {"Type": "forward", "TargetGroupArn": "arn:tg1"},
    ]
    lbs, gaps = ai.import_elbv2(bundle)
    assert lbs[0]["listeners"][0]["targets"] == ["i-app"]
    assert any(g["code"] == "alb-auth-action" for g in gaps)


def test_weighted_forward_parsed_and_gapped():
    bundle = _elbv2_bundle()
    bundle["target_groups"].append(
        {"TargetGroupArn": "arn:tg2", "Port": 8443, "TargetType": "instance"})
    bundle["targets"]["arn:tg2"] = [{"Id": "i-app2"}]
    bundle["listeners"][0]["DefaultActions"] = [{
        "Type": "forward",
        "ForwardConfig": {"TargetGroups": [
            {"TargetGroupArn": "arn:tg1", "Weight": 90},
            {"TargetGroupArn": "arn:tg2", "Weight": 10},
        ]},
    }]
    lbs, gaps = ai.import_elbv2(bundle)
    assert sorted(lbs[0]["listeners"][0]["targets"]) == ["i-app", "i-app2"]
    assert any(g["code"] == "alb-weighted-forward" for g in gaps)


def test_ip_target_resolved_via_private_ip():
    bundle = _elbv2_bundle()
    bundle["target_groups"] = [
        {"TargetGroupArn": "arn:tg1", "Port": 8443, "TargetType": "ip"}]
    bundle["targets"] = {"arn:tg1": [{"Id": "10.0.2.5"}]}
    lbs, gaps = ai.import_elbv2(bundle, {"10.0.2.5": "i-app"})
    assert lbs[0]["listeners"][0]["targets"] == ["i-app"]
    assert gaps == []


def test_ip_target_unresolved_is_gapped():
    bundle = _elbv2_bundle()
    bundle["target_groups"] = [
        {"TargetGroupArn": "arn:tg1", "Port": 8443, "TargetType": "ip"}]
    bundle["targets"] = {"arn:tg1": [{"Id": "10.9.9.9"}]}
    lbs, gaps = ai.import_elbv2(bundle, {"10.0.2.5": "i-app"})
    assert lbs[0]["listeners"][0]["targets"] == []
    assert any(g["code"] == "alb-target-ip-unresolved" for g in gaps)


def test_non_default_listener_rules_gapped_and_parsed():
    bundle = _elbv2_bundle()
    bundle["target_groups"].append(
        {"TargetGroupArn": "arn:tg2", "Port": 9000, "TargetType": "instance"})
    bundle["targets"]["arn:tg2"] = [{"Id": "i-api"}]
    bundle["rules"] = [{
        "ListenerArn": "arn:lst", "IsDefault": False,
        "Actions": [{"Type": "forward", "TargetGroupArn": "arn:tg2"}],
    }]
    lbs, gaps = ai.import_elbv2(bundle)
    assert sorted(lbs[0]["listeners"][0]["targets"]) == ["i-api", "i-app"]
    assert any(g["code"] == "alb-listener-rules" for g in gaps)


def test_ipv6_route_is_gapped():
    infra = {
        "instances": [{"id": "i-a", "subnet": "s-1"}, {"id": "i-b", "subnet": "s-2"}],
        "route_tables": [
            {"id": "rtb-1",
             "routes": [{"cidr": "0.0.0.0/0", "target": "igw-1"},
                        {"cidr": "::/0", "target": "igw-1"}],
             "subnet_ids": ["s-1"]},
            {"id": "rtb-2",
             "routes": [{"cidr": "0.0.0.0/0", "target": "igw-1"}],
             "subnet_ids": ["s-2"]},
        ],
    }
    gaps = ai._ipv6_route_gaps(infra)
    assert len(gaps) == 1
    assert gaps[0]["code"] == "ipv6-route"
    assert gaps[0]["affects"] == ["i-a"]


def test_gap_turns_any_port_dismissal_into_review(infra, findings, tavily):
    """A host with no internet path and a coverage gap: the any-port proof
    is unsound, so the finding goes to review instead of dismissed."""
    gapped = copy.deepcopy(infra)
    gapped["coverage_gaps"] = [{
        "code": "ipv6-route", "node": "rtb-x", "affects": ["i-analytics-1"],
        "detail": "test gap",
    }]
    nemotron = _StubNemotron(port=8080)
    f = next(f for f in findings if f["id"] == "F-001")  # i-analytics-1, 8080
    report = run_scan(gapped, [f], nemotron, tavily, NarrativeGuard(), None)
    assert [v.decision for v in report["verdicts"]] == ["needs-review"]
    assert "coverage gap" in report["verdicts"][0].reason


def test_gap_turns_port_branch_dismissal_into_review(infra, tavily):
    """Host WITH an internet path, ports unreachable, but a coverage gap:
    review, not dismissed."""
    gapped = copy.deepcopy(infra)
    gapped["coverage_gaps"] = [{
        "code": "alb-weighted-forward", "node": "alb-edge",
        "affects": ["i-gateway-1"], "detail": "test gap",
    }]
    nemotron = _StubNemotron(port=8080)  # unreachable on i-gateway-1
    f = {"id": "F-G", "cve_id": "CVE-2026-42424", "host": "i-gateway-1",
         "port": 8080, "protocol": "TCP", "description": ""}
    report = run_scan(gapped, [f], nemotron, tavily, NarrativeGuard(), None)
    assert [v.decision for v in report["verdicts"]] == ["needs-review"]
    assert "coverage gap" in report["verdicts"][0].reason


def test_gap_does_not_weaken_actionable(infra, findings, tavily):
    """Gaps only weaken dismissals: a proven-reachable finding on a
    gap-affected host is still actionable."""
    gapped = copy.deepcopy(infra)
    gapped["coverage_gaps"] = [{
        "code": "alb-auth-action", "node": "alb-edge",
        "affects": ["i-gateway-1"], "detail": "test gap",
    }]
    nemotron = _StubNemotron(port=8443)
    f = next(f for f in findings if f["id"] == "F-011")  # gateway, 8443
    report = run_scan(gapped, [f], nemotron, tavily, NarrativeGuard(), None)
    assert [v.decision for v in report["verdicts"]] == ["actionable"]


# ---------------------------------------------------------------------------
# Fix 3: the model's port guess must not dismiss a port-less finding.
# ---------------------------------------------------------------------------

def test_no_observed_port_unreachable_model_port_goes_to_review(infra, tavily):
    """No observed port (every Inspector finding) on an exposed host; the
    model's guessed port is unreachable -> review, not dismissed. Trusting
    the guess would dismiss on the model's word alone."""
    nemotron = _StubNemotron(port=8080)  # guess; not open on i-gateway-1
    f = {"id": "F-NOPORT", "cve_id": "CVE-2026-42424", "host": "i-gateway-1",
         "port": None, "protocol": "TCP", "description": ""}
    report = run_scan(infra, [f], nemotron, tavily, NarrativeGuard(), None)
    assert [v.decision for v in report["verdicts"]] == ["needs-review"]
    assert "model's guessed port" in report["verdicts"][0].reason


def test_no_observed_port_no_path_still_dismissed(infra, tavily, tmp_path):
    """The any-port proof is unaffected: no internet path at all still
    dismisses even with no observed port (the proof holds for every port)."""
    nemotron = _StubNemotron(port=8080)
    f = {"id": "F-NOPORT2", "cve_id": "CVE-2026-42424", "host": "i-analytics-1",
         "port": None, "protocol": "TCP", "description": ""}
    report = run_scan(infra, [f], nemotron, tavily, NarrativeGuard(),
                      DismissalLog(str(tmp_path / "d.jsonl")))
    assert [v.decision for v in report["verdicts"]] == ["dismissed"]


# ---------------------------------------------------------------------------
# Fix 4a: malformed findings must not crash the scan.
# ---------------------------------------------------------------------------

def test_malformed_finding_missing_host_goes_to_review(infra, findings, tavily):
    nemotron = _StubNemotron(port=8443)
    bad = {"id": "F-BAD", "cve_id": "CVE-2026-31007",  # no "host"
           "port": 8443, "protocol": "TCP", "description": ""}
    good = next(f for f in findings if f["id"] == "F-011")
    report = run_scan(infra, [bad, good], nemotron, tavily,
                      NarrativeGuard(), None)
    by_id = {v.finding_id: v for v in report["verdicts"]}
    assert by_id["F-BAD"].decision == "needs-review"
    assert "malformed finding" in by_id["F-BAD"].reason
    assert by_id["F-011"].decision == "actionable"  # scan continued


def test_malformed_port_goes_to_review(infra, findings, tavily):
    nemotron = _StubNemotron(port=8443)
    bad = {"id": "F-BADPORT", "cve_id": "CVE-2026-31007", "host": "i-gateway-1",
           "port": "8443/tcp", "protocol": "TCP", "description": ""}
    good = next(f for f in findings if f["id"] == "F-011")
    report = run_scan(infra, [bad, good], nemotron, tavily,
                      NarrativeGuard(), None)
    by_id = {v.finding_id: v for v in report["verdicts"]}
    assert by_id["F-BADPORT"].decision == "needs-review"
    assert "malformed finding" in by_id["F-BADPORT"].reason
    assert by_id["F-011"].decision == "actionable"  # scan continued