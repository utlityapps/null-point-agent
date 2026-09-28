"""External review round 6 (2026-09-27): close the inventory class.

1. Missing load-balancer inventory is a coverage gap, not an assumption of
   "no load balancers": without --elbv2/--elb inputs, every instance fails
   closed to review on dismissal paths. scripts/collect_aws.sh always
   produces those inputs, so the gap only fires on hand-rolled imports.
2. scripts/collect_aws.sh runs every describe call and assembles the ELBv2
   bundle, so following the README produces complete inputs.
3. Modeling bugs: NLBs have no security groups (skip the LB SG check), and
   each target is validated on its own registered port.
"""
import json

import pytest

from nullpoint import aws_import as ai
from nullpoint import graph as graph_mod
from nullpoint.guard import NarrativeGuard
from nullpoint.scanner import run_scan
from nullpoint.tavily import TavilyClient

import sys
sys.path.insert(0, "tests")
from test_round5 import _StubNemotron, _alb_infra  # noqa: E402


@pytest.fixture()
def tavily(fixtures_dir):
    return TavilyClient.from_fixtures(fixtures_dir)


# ---------------------------------------------------------------------------
# Fix 3a: NLBs have no security groups — skip the LB SG check.
# ---------------------------------------------------------------------------

def test_nlb_without_security_groups_still_reachable():
    infra = _alb_infra({"protocol": "tcp", "from_port": 8443, "to_port": 8443,
                        "cidr": "10.0.0.0/16"})
    infra["load_balancers"][0]["security_groups"] = []  # NLB: no SGs
    solver = graph_mod.InfraGraph(infra)
    reachable, _ = solver.check_reachability(graph_mod.INTERNET, "i-app", 8443, "TCP")
    assert reachable is True


def test_alb_with_denying_sg_still_denied():
    infra = _alb_infra({"protocol": "tcp", "from_port": 8443, "to_port": 8443,
                        "cidr": "10.0.0.0/16"})
    infra["security_groups"][0]["ingress"] = []  # ALB SG allows nothing
    solver = graph_mod.InfraGraph(infra)
    reachable, _ = solver.check_reachability(graph_mod.INTERNET, "i-app", 8443, "TCP")
    assert reachable is False


# ---------------------------------------------------------------------------
# Fix 3b: each target is validated on its own registered port.
# ---------------------------------------------------------------------------

def test_importer_records_registered_target_ports():
    bundle = {
        "load_balancers": [{
            "LoadBalancerArn": "arn:lb", "LoadBalancerName": "alb-1",
            "Scheme": "internet-facing", "SecurityGroups": [],
            "AvailabilityZones": [{"SubnetId": "pub-1"}],
        }],
        "listeners": [{
            "ListenerArn": "arn:lst", "LoadBalancerArn": "arn:lb",
            "Port": 80, "Protocol": "HTTP",
            "DefaultActions": [{"Type": "forward", "TargetGroupArn": "arn:tg"}],
        }],
        "target_groups": [
            {"TargetGroupArn": "arn:tg", "Port": 80, "TargetType": "instance"}],
        "targets": {"arn:tg": [{"Id": "i-a", "Port": 8080},
                               {"Id": "i-b", "Port": 8081}]},
    }
    lbs, gaps = ai.import_elbv2(bundle)
    targets = {t["id"]: t["port"] for t in lbs[0]["listeners"][0]["targets"]}
    assert targets == {"i-a": 8080, "i-b": 8081}
    assert gaps == []


def test_solver_validates_each_target_on_registered_port():
    infra = _alb_infra({"protocol": "tcp", "from_port": 8080, "to_port": 8081,
                        "cidr": "10.0.0.0/16"})
    infra["load_balancers"][0]["security_groups"] = []
    infra["load_balancers"][0]["listeners"][0]["targets"] = [
        {"id": "i-app", "port": 8080}]
    solver = graph_mod.InfraGraph(infra)
    ok, _ = solver.check_reachability(graph_mod.INTERNET, "i-app", 8080, "TCP")
    assert ok is True
    # The TG/listener default port is not the target's port: no match.
    no, _ = solver.check_reachability(graph_mod.INTERNET, "i-app", 443, "TCP")
    assert no is False


def test_string_targets_keep_listener_target_port():
    """Backwards compatibility: plain-ID targets (fixtures, hand-written
    infra) still use the listener's target port."""
    infra = _alb_infra({"protocol": "tcp", "from_port": 8443, "to_port": 8443,
                        "cidr": "10.0.0.0/16"})
    infra["load_balancers"][0]["security_groups"] = []
    solver = graph_mod.InfraGraph(infra)
    ok, _ = solver.check_reachability(graph_mod.INTERNET, "i-app", 8443, "TCP")
    assert ok is True


# ---------------------------------------------------------------------------
# Fix 1: missing inventory is a coverage gap.
# ---------------------------------------------------------------------------

def _write_docs(tmp_path):
    docs = {
        "sgs": {"SecurityGroups": []},
        "nacls": {"NetworkAcls": []},
        "rtbs": {"RouteTables": []},
        "instances": {"Reservations": [{"Instances": [{
            "InstanceId": "i-1", "PrivateIpAddress": "10.0.2.5",
            "SubnetId": "subnet-1", "SecurityGroups": [], "Tags": []}]}]},
        "subnets": {"Subnets": [{"SubnetId": "subnet-1",
                                 "CidrBlock": "10.0.2.0/24", "VpcId": "vpc-1"}]},
        "vpcs": {"Vpcs": [{"VpcId": "vpc-1", "CidrBlock": "10.0.0.0/16"}]},
        "igws": {"InternetGateways": []},
    }
    files = {}
    for k, doc in docs.items():
        p = tmp_path / f"{k}.json"
        p.write_text(json.dumps(doc))
        files[k] = str(p)
    return files


def test_missing_lb_inventory_is_a_gap(tmp_path):
    files = _write_docs(tmp_path)
    infra = ai.build_infra(files)
    codes = {g["code"] for g in infra["coverage_gaps"]}
    assert "load-balancer-inventory-missing" in codes
    assert "classic-elb-inventory-missing" in codes
    gap = next(g for g in infra["coverage_gaps"]
               if g["code"] == "load-balancer-inventory-missing")
    assert gap["affects"] == ["i-1"]


def test_complete_empty_inventory_clears_the_gap(tmp_path):
    """scripts/collect_aws.sh always writes the bundle files, even when the
    account has no load balancers: empty inventory is complete inventory."""
    files = _write_docs(tmp_path)
    for name, doc in (("elbv2", {"load_balancers": [], "listeners": [],
                                 "target_groups": [], "targets": {}}),
                      ("elb", {"LoadBalancerDescriptions": []})):
        p = tmp_path / f"{name}.json"
        p.write_text(json.dumps(doc))
        files[name] = str(p)
    infra = ai.build_infra(files)
    codes = {g["code"] for g in infra["coverage_gaps"]}
    assert "load-balancer-inventory-missing" not in codes
    assert "classic-elb-inventory-missing" not in codes
    assert "classic-elb-unmodeled" not in codes


def test_existing_classic_elb_is_a_gap(tmp_path):
    files = _write_docs(tmp_path)
    p = tmp_path / "elb.json"
    p.write_text(json.dumps({"LoadBalancerDescriptions": [
        {"LoadBalancerName": "old-clb"}]}))
    files["elb"] = str(p)
    infra = ai.build_infra(files)
    codes = {g["code"] for g in infra["coverage_gaps"]}
    assert "classic-elb-unmodeled" in codes
    assert "classic-elb-inventory-missing" not in codes


def test_missing_inventory_sends_private_host_to_review(tmp_path, tavily):
    """The whole class, closed: without LB inventory a private host can
    never be dismissed — an unseen ALB could expose it."""
    files = _write_docs(tmp_path)
    infra = ai.build_infra(files)
    nemotron = _StubNemotron(port=8080)
    findings = [{"id": "F-1", "cve_id": "CVE-2026-42424", "host": "i-1",
                 "port": 8080, "protocol": "TCP", "description": ""}]
    report = run_scan(infra, findings, nemotron, tavily, NarrativeGuard(), None)
    assert [v.decision for v in report["verdicts"]] == ["needs-review"]
    assert "load-balancer-inventory-missing" in report["verdicts"][0].reason
