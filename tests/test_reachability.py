"""Reachability correctness — hand-verified expectations on the fixture infra.

Manual review used to derive each expectation (mirrors what a security
engineer would check by hand in the AWS console):

- i-gateway-1:8443 from internet: internet -> alb-edge:443
  (alb-edge is internet-facing; sg-alb-edge allows 0.0.0.0/0:443; nacl-pub
  rule 100 allows 443) -> i-gateway-1:8443 (sg-gateway allows from
  sg-alb-edge; nacl-priv rule 145 allows 8443 from 10.0.0.0/16 which covers
  the ALB subnet 10.0.1.0/24). => REACHABLE.
- i-analytics-1:8080 from internet: the only ALB targeting it (alb-internal)
  has scheme 'internal', so no internet ingress edge exists; the instance has
  no public IP. => UNREACHABLE.
- i-analytics-1:8080 from inside the VPC: vpc-internal -> alb-internal:8080
  (sg-alb-internal allows 10.0.0.0/16; nacl-priv rule 90 allows 8080 from
  10.0.0.0/16 *before* rule 95 denies 0.0.0.0/0) -> instance (sg-analytics
  allows from sg-alb-internal; NACL rule 90 covers ALB subnet). => REACHABLE.
  This is the falsification story: the CVE is real, the service is up, but
  there is no path from untrusted networks.
- i-bastion-1:22 from internet: public IP + IGW route give a direct edge,
  but sg-bastion allows 22 only from 203.0.113.0/24 and nacl-pub has no
  0.0.0.0/0:22 allow. => UNREACHABLE.
- i-db-1:5432, i-cache-1:6379, i-queue-1:5672 from internet: private
  subnets, no public IP, no internet-facing ALB. => UNREACHABLE.
- i-gateway-1:80 from internet: alb-edge has no listener forwarding to
  port 80. => UNREACHABLE.
- NACL first-match: nacl-priv rule 90 (allow 8080 from 10.0.0.0/16) beats
  rule 95 (deny 8080 from 0.0.0.0/0) for internal sources; the deny wins
  for 0.0.0.0/0.
"""
from nullpoint import graph as graph_mod


def test_gateway_reachable_via_edge_alb(solver):
    reachable, trace = solver.check_reachability(graph_mod.INTERNET, "i-gateway-1", 8443, "TCP")
    assert reachable is True
    ok_paths = [t for t in trace if t["reachable"]]
    assert len(ok_paths) == 1
    assert ok_paths[0]["path"] == ["internet", "alb-edge", "i-gateway-1"]
    assert all(h["decision"] == "allow" for h in ok_paths[0]["hops"])


def test_analytics_unreachable_from_internet(solver):
    for host in ("i-analytics-1", "i-analytics-2", "i-analytics-3"):
        reachable, trace = solver.check_reachability(graph_mod.INTERNET, host, 8080, "TCP")
        assert reachable is False, f"{host} should be unreachable from the internet"
    reason = solver.summarize_denial(trace)
    assert "internal" in reason


def test_analytics_metrics_port_unreachable_from_internet(solver):
    reachable, _ = solver.check_reachability(graph_mod.INTERNET, "i-analytics-1", 9100, "TCP")
    assert reachable is False


def test_analytics_reachable_inside_vpc(solver):
    # The vulnerability is REAL — the service answers inside the VPC.
    # Falsification is about the *internet* attack path, not the bug.
    reachable, trace = solver.check_reachability(graph_mod.VPC_INTERNAL, "i-analytics-1", 8080, "TCP")
    assert reachable is True
    ok_paths = [t for t in trace if t["reachable"]]
    assert ok_paths[0]["path"] == ["vpc-internal", "alb-internal", "i-analytics-1"]


def test_bastion_ssh_not_open_to_internet(solver):
    reachable, _ = solver.check_reachability(graph_mod.INTERNET, "i-bastion-1", 22, "TCP")
    assert reachable is False


def test_private_services_unreachable(solver):
    for host, port in (("i-db-1", 5432), ("i-cache-1", 6379), ("i-queue-1", 5672)):
        reachable, _ = solver.check_reachability(graph_mod.INTERNET, host, port, "TCP")
        assert reachable is False, f"{host}:{port} should be unreachable"


def test_no_listener_port_unreachable(solver):
    reachable, _ = solver.check_reachability(graph_mod.INTERNET, "i-gateway-1", 80, "TCP")
    assert reachable is False


def test_nacl_explicit_deny_beats_allow_for_internet(solver):
    # Rule 95: deny tcp 8080 from 0.0.0.0/0 must win for internet sources,
    # even though rule 100/110-style allows exist for the VPC CIDR.
    assert solver.nacl_allows("nacl-priv", "ingress", ["0.0.0.0/0"], 8080, "TCP") is False


def test_nacl_allow_wins_for_vpc_cidr_on_lower_rule_number(solver):
    # Rule 90 (allow 8080 from 10.0.0.0/16) is evaluated before rule 95.
    assert solver.nacl_allows("nacl-priv", "ingress", ["10.0.2.5"], 8080, "TCP") is True
    assert solver.nacl_allows("nacl-priv", "ingress", ["10.0.0.0/16"], 8080, "TCP") is True


def test_nacl_default_deny(solver):
    assert solver.nacl_allows("nacl-pub", "ingress", ["0.0.0.0/0"], 22, "TCP") is False


def test_unknown_host_is_unreachable(solver):
    reachable, trace = solver.check_reachability(graph_mod.INTERNET, "i-nope-1", 443, "TCP")
    assert reachable is False
    assert "unknown host" in solver.summarize_denial(trace)


def test_cidr_covers_mixed_ip_versions_returns_false():
    # IPv6 ::/0 tested against an IPv4 source must not crash (TypeError)
    # and must not claim coverage.
    from nullpoint.graph import cidr_covers
    assert cidr_covers("::/0", "0.0.0.0/0") is False
    assert cidr_covers("0.0.0.0/0", "::1") is False
    assert cidr_covers("::/0", "::1") is True
