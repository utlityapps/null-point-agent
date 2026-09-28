"""Deterministic network reachability engine — the load-bearing core of NullPoint.

Given cloud infrastructure (security groups, NACLs, route tables, load
balancers, transit gateways, instances), this module computes *boolean*
reachability for (source, host, port, protocol) by:

1. Building a directed topology graph with NetworkX (nodes: internet /
   load balancers / instances / DNS names; edges: ingress, listener
   forwarding, direct public attachment, TGW pass-through).
2. Enumerating candidate paths from the source to the target host.
3. Validating every hop against real AWS semantics:
   - NACLs: stateless, first-match-wins by rule number, default deny.
   - Security groups: stateful, allow-only; match on protocol, port range,
     and source CIDR or source security group.
   - Route tables: a host without a public IP and without an
     internet-gateway route has no direct internet edge.
   - Load balancers: only ``internet-facing`` schemes accept internet
     ingress; listeners must forward to the queried target port.

The LLM never decides reachability. It only proposes exploit preconditions;
this solver proves or falsifies them. A disagreement between an LLM
narrative claim and this solver is always resolved in the solver's favor
(see :mod:`nullpoint.guard`).
"""
from __future__ import annotations

import ipaddress

import networkx as nx

INTERNET = "internet"
VPC_INTERNAL = "vpc-internal"

#: Source node -> representative source CIDR used for SG/NACL evaluation.
SOURCE_CIDRS = {
    INTERNET: "0.0.0.0/0",
    VPC_INTERNAL: "10.0.0.0/16",
}

_DEFAULT_DENY_RULE = 32767  # conventional NACL "catch-all deny" rule number


def _as_net(cidr: str) -> ipaddress._BaseNetwork:
    return ipaddress.ip_network(str(cidr), strict=False)


def cidr_covers(rule_cidr: str, src: str) -> bool:
    """True when ``rule_cidr`` covers ``src`` (``src`` may be a CIDR or IP)."""
    try:
        return _as_net(rule_cidr).supernet_of(_as_net(src))
    except (ValueError, TypeError):
        # ValueError: unparseable CIDR. TypeError: mixed IP versions, e.g.
        # an IPv6 ::/0 rule tested against an IPv4 source — not a crash,
        # just "does not cover".
        return False


def any_cidr_covers(rule_cidr: str, srcs: list[str]) -> bool:
    return any(cidr_covers(rule_cidr, s) for s in srcs)


def _proto_num(p) -> str:
    # ALB listener protocols are L7 names for L4 transports: HTTP/HTTPS/TLS
    # all ride TCP. Without this mapping every app behind a real ALB (whose
    # listeners are HTTP/HTTPS, never "TCP") reads as unreachable.
    return {"tcp": "6", "udp": "17", "icmp": "1", "http": "6", "https": "6",
            "tls": "6"}.get(str(p).lower(), str(p).lower())


def proto_match(rule_proto, protocol: str) -> bool:
    """Match a rule protocol ('-1'/number/name) against a query protocol."""
    rp = str(rule_proto).lower()
    if rp in ("-1", "all"):
        return True
    return _proto_num(rp) == _proto_num(protocol)


class InfraGraph:
    """Topology graph + deterministic reachability solver."""

    def __init__(self, infra: dict):
        self.infra = infra
        self.subnets = {s["id"]: s for s in infra.get("subnets", [])}
        self.sgs = {s["id"]: s for s in infra.get("security_groups", [])}
        self.nacls = {n["id"]: n for n in infra.get("network_acls", [])}
        self.rtbs = {r["id"]: r for r in infra.get("route_tables", [])}
        self.instances = {i["id"]: i for i in infra.get("instances", [])}
        self.albs = {a["id"]: a for a in infra.get("load_balancers", [])}
        self.route53 = {z["name"]: z for z in infra.get("route53", [])}

        self.subnet_nacl: dict[str, str] = {}
        for n in infra.get("network_acls", []):
            for sid in n.get("subnet_ids", []):
                self.subnet_nacl[sid] = n["id"]
        self.subnet_rtb: dict[str, str] = {}
        for r in infra.get("route_tables", []):
            for sid in r.get("subnet_ids", []):
                self.subnet_rtb[sid] = r["id"]

        self.G = nx.DiGraph()
        self._build_topology()
        # Coverage gaps: network constructs the importer saw but the solver
        # cannot model (auth actions, weighted forwards, IP targets,
        # unevaluated listener rules, IPv6 routes). Each gap names the hosts
        # it affects; a dismissal proof covering those hosts is unsound, so
        # the scanner fails them closed to human review instead.
        self.coverage_gaps: list[dict] = list(infra.get("coverage_gaps", []))

    def coverage_gaps_for(self, host: str) -> list[dict]:
        """Coverage gaps affecting ``host`` (empty when the model is complete)."""
        return [g for g in self.coverage_gaps if host in g.get("affects", [])]

    @staticmethod
    def _target_entries(lst: dict):
        """Yield (target_id, registered_port) for a listener's targets.

        Two shapes are accepted: plain instance-ID strings (fixtures,
        hand-written infra) and {"id", "port"} dicts (importer output,
        where "port" is the target's registered port from
        describe-target-health).
        """
        for t in lst.get("targets", []):
            if isinstance(t, dict):
                yield t.get("id"), t.get("port")
            else:
                yield t, None

    @staticmethod
    def _listener_target_port(lst: dict, target_id: str):
        """The port a listener forwards to ``target_id``: the target's
        registered port when known, else the listener's target port."""
        fallback = lst.get("target_port", lst["port"])
        for tid, tport in InfraGraph._target_entries(lst):
            if tid == target_id:
                return tport if tport is not None else fallback
        return fallback

    # ------------------------------------------------------------------
    # topology construction
    # ------------------------------------------------------------------
    def _build_topology(self) -> None:
        self.G.add_node(INTERNET, kind="internet")
        self.G.add_node(VPC_INTERNAL, kind="vpc-internal")

        for alb_id, alb in self.albs.items():
            self.G.add_node(alb_id, kind="alb", scheme=alb.get("scheme"))
            if alb.get("scheme") == "internet-facing":
                self.G.add_edge(INTERNET, alb_id, kind="ingress")
            else:
                # Internal ALBs are reachable from inside the VPC only.
                self.G.add_edge(VPC_INTERNAL, alb_id, kind="ingress")

        for name, zone in self.route53.items():
            self.G.add_node(name, kind="dns")
            self.G.add_edge(name, zone["target"], kind="alias")

        for alb_id, alb in self.albs.items():
            for lst in alb.get("listeners", []):
                for tgt_id, tgt_port in self._target_entries(lst):
                    self.G.add_edge(
                        alb_id,
                        tgt_id,
                        kind="forward",
                        listener_port=lst["port"],
                        target_port=(tgt_port if tgt_port is not None
                                     else lst.get("target_port", lst["port"])),
                        protocol=lst.get("protocol", "TCP"),
                    )

        for inst_id, inst in self.instances.items():
            self.G.add_node(inst_id, kind="instance")
            if inst.get("public_ip") and self.subnet_has_igw_route(inst["subnet"]):
                self.G.add_edge(INTERNET, inst_id, kind="direct")

        # Transit gateways: modelled as pass-through nodes so the topology
        # is complete; no internet edge touches them in this fixture.
        for tgw in self.infra.get("transit_gateways", []):
            tgw_id = tgw["id"]
            self.G.add_node(tgw_id, kind="tgw")
            for subnet_id in tgw.get("attachments", []):
                for inst_id, inst in self.instances.items():
                    if inst.get("subnet") == subnet_id:
                        self.G.add_edge(inst_id, tgw_id, kind="tgw-attach")
                        self.G.add_edge(tgw_id, inst_id, kind="tgw-attach")

    # ------------------------------------------------------------------
    # primitive evaluators
    # ------------------------------------------------------------------
    def subnet_has_igw_route(self, subnet_id: str) -> bool:
        rtb = self.rtbs.get(self.subnet_rtb.get(subnet_id, ""), {})
        for route in rtb.get("routes", []):
            if route.get("cidr") == "0.0.0.0/0" and "igw" in str(route.get("target", "")):
                return True
        return False

    def sg_allows(
        self,
        sg_ids: list[str],
        src_cidrs: list[str] | None,
        src_sgs: list[str] | None,
        port: int,
        protocol: str,
    ) -> bool:
        """Security groups are allow-only: any matching rule permits."""
        for sg_id in sg_ids or []:
            for rule in self.sgs.get(sg_id, {}).get("ingress", []):
                if not proto_match(rule.get("protocol", "-1"), protocol):
                    continue
                fp, tp = rule.get("from_port"), rule.get("to_port")
                if fp is not None and not (fp <= port <= tp):
                    continue
                if src_cidrs and rule.get("cidr") and any_cidr_covers(rule["cidr"], src_cidrs):
                    return True
                if src_sgs and rule.get("source_sg") in (src_sgs or []):
                    return True
        return False

    def nacl_allows(
        self,
        nacl_id: str,
        direction: str,
        src_cidrs: list[str],
        port: int,
        protocol: str,
    ) -> bool:
        """NACLs are stateless with first-match-wins semantics; default deny."""
        nacl = self.nacls.get(nacl_id, {})
        rules = sorted(nacl.get(direction, []), key=lambda r: r.get("rule_number", _DEFAULT_DENY_RULE))
        for rule in rules:
            if not proto_match(str(rule.get("protocol", "-1")), protocol):
                continue
            pf, pt = rule.get("port_from"), rule.get("port_to")
            if pf is not None and not (pf <= port <= pt):
                continue
            if not any_cidr_covers(rule.get("cidr", ""), src_cidrs):
                continue
            return rule.get("action") == "allow"
        return False

    def nacl_allows_subnets(
        self,
        subnet_ids: list[str],
        direction: str,
        src_cidrs: list[str],
        port: int,
        protocol: str,
    ) -> bool:
        for sid in subnet_ids:
            nacl_id = self.subnet_nacl.get(sid)
            if nacl_id and not self.nacl_allows(nacl_id, direction, src_cidrs, port, protocol):
                return False
        return True

    # ------------------------------------------------------------------
    # path validation
    # ------------------------------------------------------------------
    def _find_listener(self, alb: dict, next_node: str, port: int, protocol: str):
        for lst in alb.get("listeners", []):
            if (
                self._listener_target_port(lst, next_node) == port
                and any(tid == next_node for tid, _ in self._target_entries(lst))
                and proto_match(lst.get("protocol", "TCP"), protocol)
            ):
                return lst
        return None

    def _validate_path(self, path: list[str], src_cidr: str, port: int, protocol: str):
        """Validate every hop of one candidate path. Returns (ok, hops)."""
        hops = []
        for i in range(len(path) - 1):
            a, b = path[i], path[i + 1]
            edge = self.G.edges[a, b]
            kind = edge.get("kind")

            if kind in ("alias", "tgw-attach"):
                hops.append({"hop": f"{a} -> {b}", "decision": "allow", "reason": f"{kind} (transparent)"})
                continue

            if kind == "ingress":
                # a is a source node, b is an ALB.
                alb = self.albs[b]
                nxt = path[i + 2] if i + 2 < len(path) else None
                listener = self._find_listener(alb, nxt, port, protocol) if nxt else None
                if listener is None:
                    hops.append({
                        "hop": f"{a} -> {b}", "decision": "deny",
                        "reason": f"no listener on {b} forwards to {nxt}:{port}/{protocol}",
                    })
                    return False, hops
                lport = listener["port"]
                # NLBs have no security groups: nothing to check at the LB.
                # (ALB/CLB SGs are evaluated when present.)
                alb_sgs = alb.get("security_groups") or []
                if alb_sgs and not self.sg_allows(alb_sgs, [src_cidr], None, lport, protocol):
                    hops.append({"hop": f"{a} -> {b}", "decision": "deny",
                                 "reason": f"{b} security groups deny {src_cidr} on listener port {lport}"})
                    return False, hops
                if not self.nacl_allows_subnets(alb.get("subnets"), "ingress", [src_cidr], lport, protocol):
                    hops.append({"hop": f"{a} -> {b}", "decision": "deny",
                                 "reason": f"{b} subnet NACLs deny {src_cidr} on port {lport}"})
                    return False, hops
                hops.append({"hop": f"{a} -> {b}", "decision": "allow",
                             "reason": f"listener {lport}->{port}/{protocol}; SG+NACL permit {src_cidr}"})
                continue

            if kind == "forward":
                # a is an ALB, b is an instance.
                if edge.get("target_port") != port:
                    hops.append({"hop": f"{a} -> {b}", "decision": "deny",
                                 "reason": "forward target port mismatch"})
                    return False, hops
                alb, inst = self.albs[a], self.instances[b]
                alb_cidrs = [self.subnets[s]["cidr"] for s in alb.get("subnets", [])
                             if s in self.subnets and self.subnets[s].get("cidr")]
                # The ALB reaches the instance from an IP in its own subnets:
                # the app SG may allow the ALB's SG *or* the VPC/subnet CIDR
                # the ALB lives in. Checking only SG references dismissed
                # every app whose SG allows the VPC CIDR instead.
                if not self.sg_allows(inst.get("security_groups"), alb_cidrs,
                                      alb.get("security_groups"), port, protocol):
                    hops.append({"hop": f"{a} -> {b}", "decision": "deny",
                                 "reason": f"{b} security groups do not allow {a} on {port}/{protocol}"})
                    return False, hops
                if not self.nacl_allows_subnets([inst["subnet"]], "ingress", alb_cidrs, port, protocol):
                    hops.append({"hop": f"{a} -> {b}", "decision": "deny",
                                 "reason": f"{b} subnet NACLs deny ALB subnets on {port}/{protocol}"})
                    return False, hops
                hops.append({"hop": f"{a} -> {b}", "decision": "allow",
                             "reason": f"SG allows {a}; NACL permits on {port}/{protocol}"})
                continue

            if kind == "direct":
                inst = self.instances[b]
                if not inst.get("public_ip") or not self.subnet_has_igw_route(inst["subnet"]):
                    hops.append({"hop": f"{a} -> {b}", "decision": "deny",
                                 "reason": f"{b} has no public internet route"})
                    return False, hops
                if not self.sg_allows(inst.get("security_groups"), [src_cidr], None, port, protocol):
                    hops.append({"hop": f"{a} -> {b}", "decision": "deny",
                                 "reason": f"{b} security groups deny {src_cidr} on {port}/{protocol}"})
                    return False, hops
                if not self.nacl_allows_subnets([inst["subnet"]], "ingress", [src_cidr], port, protocol):
                    hops.append({"hop": f"{a} -> {b}", "decision": "deny",
                                 "reason": f"{b} subnet NACLs deny {src_cidr} on {port}/{protocol}"})
                    return False, hops
                hops.append({"hop": f"{a} -> {b}", "decision": "allow",
                             "reason": f"public IP + IGW route; SG+NACL permit {src_cidr}"})
                continue

            hops.append({"hop": f"{a} -> {b}", "decision": "deny", "reason": f"unknown edge kind {kind}"})
            return False, hops
        return True, hops

    def _explain_no_path(self, host: str, port: int, protocol: str) -> list[str]:
        """Human-readable reasons why no candidate path exists from the internet."""
        reasons: list[str] = []
        inst = self.instances.get(host)
        if inst is None:
            return [f"unknown host {host}"]
        for alb_id, alb in self.albs.items():
            listener = None
            for lst in alb.get("listeners", []):
                if (self._listener_target_port(lst, host) == port
                        and any(tid == host for tid, _ in self._target_entries(lst))):
                    listener = lst
                    break
            if listener is None:
                continue
            if alb.get("scheme") != "internet-facing":
                reasons.append(
                    f"{alb_id} targets {host}:{port} but its scheme is "
                    f"'{alb.get('scheme')}' — no internet ingress edge exists"
                )
        if inst.get("public_ip") and self.subnet_has_igw_route(inst["subnet"]):
            reasons.append(f"{host} has a public IP but SG/NACL evaluation denies internet on {port}/{protocol}")
        elif not reasons:
            reasons.append(f"{host} has no public IP and no internet-facing load balancer forwards to it")
        return reasons

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------
    def has_any_path(self, source: str, host: str) -> bool:
        """True when ANY topology path exists from ``source`` to ``host``.

        Port-agnostic: if this is False, no (port, protocol) probe can ever
        succeed, so a non-exposure proof holds for every port.
        """
        try:
            return nx.has_path(self.G, source, host)
        except nx.NetworkXException:
            return False

    def check_reachability(self, source: str, host: str, port: int, protocol: str = "TCP"):
        """Boolean reachability from ``source`` to ``host:port/protocol``.

        Returns ``(reachable, trace)`` where trace is a list of evaluated
        candidate paths with per-hop allow/deny decisions.
        """
        if source not in SOURCE_CIDRS:
            raise ValueError(f"unknown source {source!r}; expected one of {sorted(SOURCE_CIDRS)}")
        if host not in self.G:
            return False, [{"path": [], "reachable": False,
                            "hops": [{"hop": None, "decision": "deny", "reason": f"unknown host {host}"}]}]
        src_cidr = SOURCE_CIDRS[source]
        trace = []
        try:
            paths = list(nx.all_simple_paths(self.G, source, host, cutoff=6))
        except nx.NetworkXNoPath:
            paths = []
        for path in paths:
            ok, hops = self._validate_path(path, src_cidr, port, protocol)
            trace.append({"path": path, "reachable": ok, "hops": hops})
            if ok:
                return True, trace
        if not trace:
            trace.append({"path": [], "reachable": False,
                          "hops": [{"hop": None, "decision": "deny",
                                    "reason": r} for r in self._explain_no_path(host, port, protocol)]})
        return False, trace

    def summarize_denial(self, trace: list[dict]) -> str:
        """One-line human reason for a negative reachability verdict."""
        for entry in trace:
            for hop in entry.get("hops", []):
                if hop.get("decision") == "deny" and hop.get("reason"):
                    return hop["reason"]
        return "no reachable execution path from the source"
