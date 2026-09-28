"""Read-only AWS importer: ``aws ec2 describe-*`` JSON -> NullPoint infra.json.

Collect the inputs (nothing is modified in your account; these are all
read-only describe calls)::

    aws ec2 describe-security-groups    > sgs.json
    aws ec2 describe-network-acls      > nacls.json
    aws ec2 describe-route-tables      > rtbs.json
    aws ec2 describe-instances         > instances.json
    aws ec2 describe-subnets           > subnets.json
    aws ec2 describe-vpcs              > vpcs.json
    aws ec2 describe-internet-gateways > igws.json

Then::

    python3 -m nullpoint.aws_import --sgs sgs.json --nacls nacls.json \\
        --rtbs rtbs.json --instances instances.json --subnets subnets.json \\
        --vpcs vpcs.json --igws igws.json -o infra.json

Instance services (which ports to test) come from an optional tag
``nullpoint:services`` with value like ``8080/TCP:analytics-app,9100/TCP``.
Instances without the tag get an empty service list. ELBv2 load balancers
are optional via ``--elbv2`` (see --help).
"""
from __future__ import annotations

import argparse
import json


def _load(path: str) -> dict:
    with open(path) as fh:
        return json.load(fh)


def import_security_groups(doc: dict) -> list[dict]:
    out = []
    for sg in doc.get("SecurityGroups", []):
        item: dict = {"id": sg["GroupId"], "ingress": [], "egress": []}
        for direction, perms in (("ingress", sg.get("IpPermissions", [])),
                                 ("egress", sg.get("IpPermissionsEgress", []))):
            for perm in perms:
                proto = str(perm.get("IpProtocol", "-1")).lower()
                fp = perm.get("FromPort")
                tp = perm.get("ToPort")
                if proto == "-1":
                    # "All traffic": no port restriction. The solver treats
                    # None as unrestricted; 0/0 would wrongly match nothing.
                    fp, tp = None, None
                base = {"protocol": proto, "from_port": fp, "to_port": tp}
                cidrs = [r["CidrIp"] for r in perm.get("IpRanges", []) if r.get("CidrIp")]
                cidrs += [r["CidrIpv6"] for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6")]
                for cidr in cidrs:
                    item[direction].append({**base, "cidr": cidr})
                for pair in perm.get("UserIdGroupPairs", []):
                    if pair.get("GroupId"):
                        item[direction].append({**base, "source_sg": pair["GroupId"]})
        out.append(item)
    return out


def import_network_acls(doc: dict) -> list[dict]:
    out = []
    for acl in doc.get("NetworkAcls", []):
        item: dict = {"id": acl["NetworkAclId"], "ingress": [], "egress": [],
                      "subnet_ids": []}
        for entry in acl.get("Entries", []):
            rule = {
                "rule_number": entry["RuleNumber"],
                "protocol": str(entry.get("Protocol", "-1")),
                "action": entry.get("RuleAction", "allow"),
                "cidr": entry.get("CidrBlock") or entry.get("Ipv6CidrBlock"),
                "port_from": (entry.get("PortRange") or {}).get("From"),
                "port_to": (entry.get("PortRange") or {}).get("To"),
            }
            item["egress" if entry.get("Egress") else "ingress"].append(rule)
        for assoc in acl.get("Associations", []):
            if assoc.get("SubnetId"):
                item["subnet_ids"].append(assoc["SubnetId"])
        out.append(item)
    return out


def import_route_tables(doc: dict) -> list[dict]:
    out = []
    for rtb in doc.get("RouteTables", []):
        item: dict = {"id": rtb["RouteTableId"], "routes": [], "subnet_ids": []}
        for route in rtb.get("Routes", []):
            target = (route.get("GatewayId") or route.get("NatGatewayId")
                      or route.get("TransitGatewayId")
                      or route.get("VpcPeeringConnectionId")
                      or route.get("NetworkInterfaceId"))
            item["routes"].append({
                "cidr": route.get("DestinationCidrBlock")
                or route.get("DestinationIpv6CidrBlock"),
                "target": target,
            })
        is_main = False
        for assoc in rtb.get("Associations", []):
            if assoc.get("SubnetId"):
                item["subnet_ids"].append(assoc["SubnetId"])
            elif assoc.get("Main"):
                # The VPC's main route table: every subnet without an
                # explicit association uses it (the default-VPC case).
                is_main = True
        if is_main:
            item["main"] = True
            item["vpc"] = rtb.get("VpcId")
        out.append(item)
    return out


def _parse_services_tag(tags: list[dict]) -> list[dict]:
    for tag in tags or []:
        if tag.get("Key") == "nullpoint:services":
            services = []
            for chunk in str(tag.get("Value", "")).split(","):
                chunk = chunk.strip()
                if not chunk:
                    continue
                portproto, _, name = chunk.partition(":")
                port, _, proto = portproto.partition("/")
                services.append({
                    "name": name.strip() or f"port-{port.strip()}",
                    "port": int(port.strip()),
                    "protocol": (proto.strip() or "TCP").upper(),
                })
            return services
    return []


def import_instances(doc: dict) -> list[dict]:
    out = []
    for res in doc.get("Reservations", []):
        for inst in res.get("Instances", []):
            out.append({
                "id": inst["InstanceId"],
                "private_ip": inst.get("PrivateIpAddress"),
                "public_ip": inst.get("PublicIpAddress"),
                "subnet": inst.get("SubnetId"),
                "security_groups": [sg["GroupId"] for sg in inst.get("SecurityGroups", [])],
                "services": _parse_services_tag(inst.get("Tags", [])),
            })
    return out


def import_subnets(doc: dict) -> list[dict]:
    return [{
        "id": s["SubnetId"],
        "cidr": s.get("CidrBlock"),
        "vpc": s.get("VpcId"),
        "az": s.get("AvailabilityZone"),
        "map_public_ip": bool(s.get("MapPublicIpOnLaunch", False)),
    } for s in doc.get("Subnets", [])]


def import_vpcs(doc: dict) -> list[dict]:
    return [{"id": v["VpcId"], "cidr": v.get("CidrBlock")}
            for v in doc.get("Vpcs", [])]


def import_internet_gateways(doc: dict) -> list[dict]:
    out = []
    for igw in doc.get("InternetGateways", []):
        atts = igw.get("Attachments", [])
        out.append({
            "id": igw["InternetGatewayId"],
            "vpc": atts[0].get("VpcId") if atts else None,
        })
    return out


def _target_entry(t: dict) -> tuple[str | None, int | None]:
    """(id, registered port) from a describe-target-health entry.

    Accepts the bundle shorthand {"Id", "Port"} and the raw API shape
    {"Target": {"Id", "Port"}}.
    """
    target = t.get("Target", t) if isinstance(t.get("Target"), dict) else t
    port = target.get("Port")
    return target.get("Id"), (int(port) if port is not None else None)


def _forward_targets(tg_arns: list[str], tg_by_arn: dict, targets_by_tg: dict,
                     ip_to_instance: dict, gaps: list, lb_id: str) -> list[dict]:
    """Resolve target-group ARNs to [{"id", "port"}] entries, recording a
    coverage gap for anything the solver cannot model. "port" is each
    target's registered port (describe-target-health), falling back to the
    target group's port when unregistered."""
    resolved: list[dict] = []
    for tg_arn in tg_arns:
        if not tg_arn:
            continue
        tg = tg_by_arn.get(tg_arn, {})
        ttype = str(tg.get("TargetType", "instance")).lower()
        tg_port = tg.get("Port")
        for t in targets_by_tg.get(tg_arn, []):
            tid, tport = _target_entry(t)
            if not tid:
                continue
            port = tport if tport is not None else tg_port
            if ttype == "instance":
                resolved.append({"id": tid, "port": port})
            elif ttype == "ip":
                iid = ip_to_instance.get(tid)
                if iid:
                    resolved.append({"id": iid, "port": port})  # parse what we can
                else:
                    gaps.append({
                        "code": "alb-target-ip-unresolved", "node": lb_id,
                        "detail": f"IP-type target {tid} matches no known instance",
                    })
            else:
                gaps.append({
                    "code": f"alb-target-type-{ttype}", "node": lb_id,
                    "detail": f"target group {tg_arn} has unmodeled target type {ttype!r}",
                })
    return resolved


def _parse_actions(actions: list[dict], tg_by_arn: dict, targets_by_tg: dict,
                   ip_to_instance: dict, gaps: list, lb_id: str,
                   where: str) -> tuple[list[dict], str | None]:
    """Parse ELBv2 actions into ([{"id", "port"}], first target-group ARN).

    Iterates ALL actions (the old code read only DefaultActions[0], so an
    auth action first silently dropped the forward). Auth actions are
    recorded as gaps; weighted forwards are parsed AND gapped.
    """
    tg_arns: list[str] = []
    for action in actions or []:
        atype = str(action.get("Type", "")).lower()
        if atype == "forward":
            if action.get("TargetGroupArn"):
                tg_arns.append(action["TargetGroupArn"])
            fc = action.get("ForwardConfig") or {}
            ftgs = fc.get("TargetGroups", [])
            if len(ftgs) > 1:
                gaps.append({
                    "code": "alb-weighted-forward", "node": lb_id,
                    "detail": f"{where}: weighted ForwardConfig across "
                              f"{len(ftgs)} target groups; all parsed, weights unevaluated",
                })
            for fwd in ftgs:
                if fwd.get("TargetGroupArn"):
                    tg_arns.append(fwd["TargetGroupArn"])
        elif atype in ("authenticate-oidc", "authenticate-cognito"):
            gaps.append({
                "code": "alb-auth-action", "node": lb_id,
                "detail": f"{where}: {atype} action gates traffic (parsed, auth not modeled)",
            })
        # redirect / fixed-response: terminal, nothing forwarded — no gap.
    targets = _forward_targets(tg_arns, tg_by_arn, targets_by_tg,
                               ip_to_instance, gaps, lb_id)
    return targets, (tg_arns[0] if tg_arns else None)


def _parse_listener(actions: list[dict], tg_by_arn: dict, targets_by_tg: dict,
                    ip_to_instance: dict, gaps: list, lb_id: str,
                    where: str) -> tuple[list[dict], str | None]:
    """Parse one listener's (or rule's) actions; see _parse_actions."""
    return _parse_actions(actions, tg_by_arn, targets_by_tg,
                          ip_to_instance, gaps, lb_id, where)


def import_elbv2(bundle: dict, ip_to_instance: dict | None = None
                 ) -> tuple[list[dict], list[dict]]:
    """Optional ELBv2 bundle -> (load_balancers, coverage_gaps).

    Bundle shape: {"load_balancers": [...], "listeners": [...],
    "target_groups": [...], "targets": {tg_arn: [{"Id": ...}]},
    "rules": [{"ListenerArn": ..., "IsDefault": ..., "Actions": [...]}]}
    (rules optional; from describe-rules).

    Anything the solver cannot model is recorded as a coverage gap instead
    of being silently dropped: auth actions, weighted forwards, non-instance
    target types, unevaluated listener rules. Gaps only ever weaken
    dismissals (findings go to review), never actionability.
    """
    ip_to_instance = ip_to_instance or {}
    tg_by_arn = {tg["TargetGroupArn"]: tg for tg in bundle.get("target_groups", [])}
    targets_by_tg = bundle.get("targets", {})
    listeners_by_lb: dict[str, list[dict]] = {}
    for lst in bundle.get("listeners", []):
        listeners_by_lb.setdefault(lst["LoadBalancerArn"], []).append(lst)
    rules_by_listener: dict[str, list[dict]] = {}
    for rule in bundle.get("rules", []):
        if not rule.get("IsDefault"):
            rules_by_listener.setdefault(rule.get("ListenerArn"), []).append(rule)

    gaps: list[dict] = []
    out = []
    for lb in bundle.get("load_balancers", []):
        lb_id = lb.get("LoadBalancerName", lb["LoadBalancerArn"])
        lb_arn = lb["LoadBalancerArn"]
        listeners = []
        lb_targets: set[str] = set()
        lb_gap_idx = len(gaps)
        for lst in listeners_by_lb.get(lb_arn, []):
            where = f"listener {lst.get('Port')}/{lst.get('Protocol')}"
            targets, first_tg = _parse_listener(lst.get("DefaultActions", []),
                                                tg_by_arn, targets_by_tg,
                                                ip_to_instance, gaps,
                                                lb_id, where)
            for rule in rules_by_listener.get(lst.get("ListenerArn"), []):
                # Rule conditions (host/path) can't be evaluated by the
                # solver, but the rule's forward targets are still parsed so
                # the gap scope is precise.
                rt, _ = _parse_listener(rule.get("Actions", []), tg_by_arn,
                                        targets_by_tg, ip_to_instance,
                                        gaps, lb_id, where + " rule")
                targets.extend(rt)
                gaps.append({
                    "code": "alb-listener-rules", "node": lb_id,
                    "detail": f"{where}: non-default listener rules exist; "
                              "routing conditions unevaluated",
                })
            tport = tg_by_arn.get(first_tg, {}).get("Port") if first_tg else None
            # Dedupe by instance ID, keeping each target's registered port.
            seen: dict[str, dict] = {}
            for entry in targets:
                seen.setdefault(entry["id"], entry)
            listeners.append({
                "port": lst["Port"],
                "protocol": str(lst.get("Protocol", "TCP")).upper(),
                "target_port": tport or lst["Port"],
                "targets": list(seen.values()),
            })
            lb_targets.update(seen)
        # Scope this LB's gaps to every instance it forwards to. If forwarding
        # is entirely unresolvable (e.g. all IP targets unmatched), fall back
        # to VPC-wide scoping via the caller (see build_infra).
        for g in gaps[lb_gap_idx:]:
            g.setdefault("affects", sorted(lb_targets))
        out.append({
            "id": lb_id,
            "scheme": lb.get("Scheme", "internal"),
            "security_groups": lb.get("SecurityGroups", []),
            "subnets": [az["SubnetId"] for az in lb.get("AvailabilityZones", [])
                        if az.get("SubnetId")],
            "listeners": listeners,
        })
    return out, gaps


COLLECTOR = """\
# Preferred: scripts/collect_aws.sh gathers everything below plus the ELBv2
# bundle and Classic ELB inventory into one directory.
aws ec2 describe-security-groups    > sgs.json
aws ec2 describe-network-acls      > nacls.json
aws ec2 describe-route-tables      > rtbs.json
aws ec2 describe-instances         > instances.json
aws ec2 describe-subnets           > subnets.json
aws ec2 describe-vpcs              > vpcs.json
aws ec2 describe-internet-gateways > igws.json
# ELBv2 (optional): assemble {"load_balancers","listeners","target_groups",
# "targets","rules"} from describe-load-balancers / describe-listeners /
# describe-target-groups / describe-target-health / describe-rules, then pass
# it with --elbv2. Without it, a VPC-wide coverage gap is recorded: the
# importer will not assume an account has no load balancers.
# Classic ELB (optional): aws elb describe-load-balancers > elb.json, passed
# with --elb. Classic LBs are not modeled; any found become a coverage gap.
"""


def _all_instance_ids(infra: dict) -> list[str]:
    return sorted({i["id"] for i in infra["instances"]})


def _missing_inventory_gaps(infra: dict, files: dict) -> list[dict]:
    """Missing load-balancer inventory is a coverage gap, not an assumption
    of 'no load balancers'. Any LB in the account that the model cannot see
    could expose a private host, so every instance in the snapshot fails
    closed to review on dismissal paths. Providing the inputs (even empty)
    proves the inventory is complete and clears the gap — which is exactly
    what scripts/collect_aws.sh does."""
    gaps = []
    if not files.get("elbv2"):
        gaps.append({
            "code": "load-balancer-inventory-missing", "node": "account",
            "affects": _all_instance_ids(infra),
            "detail": "no ELBv2 data provided (--elbv2); load balancers in "
                      "the account are not modeled",
        })
    if files.get("elb"):
        classic = _load(files["elb"]).get("LoadBalancerDescriptions", [])
        if classic:
            gaps.append({
                "code": "classic-elb-unmodeled", "node": "account",
                "affects": _all_instance_ids(infra),
                "detail": f"{len(classic)} Classic load balancer(s) exist "
                          "and are not modeled",
            })
    else:
        gaps.append({
            "code": "classic-elb-inventory-missing", "node": "account",
            "affects": _all_instance_ids(infra),
            "detail": "no Classic ELB data provided (--elb); Classic load "
                      "balancers in the account are not modeled",
        })
    return gaps


def _ipv6_route_gaps(infra: dict) -> list[dict]:
    """Route tables with IPv6 routes (e.g. ::/0) are a coverage gap: the
    solver only models IPv4, so hosts in those subnets might be reachable
    over IPv6 in ways the proof cannot see. Fails closed to review."""
    insts_by_subnet: dict[str, list[str]] = {}
    for inst in infra["instances"]:
        insts_by_subnet.setdefault(inst.get("subnet"), []).append(inst["id"])
    gaps = []
    for rtb in infra["route_tables"]:
        v6 = [r["cidr"] for r in rtb["routes"]
              if r.get("cidr") and ":" in str(r["cidr"])]
        if not v6:
            continue
        affects = sorted({iid for sid in rtb["subnet_ids"]
                          for iid in insts_by_subnet.get(sid, [])})
        gaps.append({
            "code": "ipv6-route", "node": rtb["id"], "affects": affects,
            "detail": f"route table {rtb['id']} has IPv6 route(s) "
                      f"{', '.join(v6)}; IPv6 is not modeled",
        })
    return gaps


def build_infra(files: dict) -> dict:
    infra = {
        "_comment": "Generated by nullpoint.aws_import from read-only describe-* output.",
        "instances": import_instances(_load(files["instances"])),
        "internet_gateways": import_internet_gateways(_load(files["igws"])),
        "load_balancers": [],
        "network_acls": import_network_acls(_load(files["nacls"])),
        "route53": [],
        "route_tables": import_route_tables(_load(files["rtbs"])),
        "security_groups": import_security_groups(_load(files["sgs"])),
        "subnets": import_subnets(_load(files["subnets"])),
        "transit_gateways": [],
        "vpcs": import_vpcs(_load(files["vpcs"])),
        "coverage_gaps": [],
    }
    if files.get("elbv2"):
        # Map IP-type target IPs back to known instances ("parse what we
        # can"); anything left unresolved becomes a coverage gap.
        ip_to_instance = {i["private_ip"]: i["id"] for i in infra["instances"]
                          if i.get("private_ip")}
        lbs, gaps = import_elbv2(_load(files["elbv2"]), ip_to_instance)
        infra["load_balancers"] = lbs
        infra["coverage_gaps"].extend(gaps)
        # Gaps whose forwarding is entirely unresolvable (no known instance
        # targets) are scoped VPC-wide: any host in the ALB's VPC might be
        # the unseen target, so no dismissal proof there is sound.
        vpc_by_subnet = {s["id"]: s.get("vpc") for s in infra["subnets"]}
        insts_by_vpc: dict[str, list[str]] = {}
        for inst in infra["instances"]:
            insts_by_vpc.setdefault(vpc_by_subnet.get(inst.get("subnet")), []).append(inst["id"])
        for lb, raw in zip(lbs, _load(files["elbv2"]).get("load_balancers", [])):
            vpcs = {vpc_by_subnet.get(az.get("SubnetId"))
                    for az in raw.get("AvailabilityZones", [])}
            for g in gaps:
                if g.get("node") == lb["id"] and not g.get("affects"):
                    for vpc in vpcs:
                        g["affects"] = sorted(
                            set(g.get("affects", [])) | set(insts_by_vpc.get(vpc, [])))
    _apply_main_route_tables(infra)
    infra["coverage_gaps"].extend(_ipv6_route_gaps(infra))
    # Missing load-balancer inventory is a gap, not an assumption of none.
    infra["coverage_gaps"].extend(_missing_inventory_gaps(infra, files))
    return infra


def _apply_main_route_tables(infra: dict) -> None:
    """Subnets without an explicit route-table association use their VPC's
    main route table (AWS default). Without this, every default-VPC subnet
    reads as having no IGW route."""
    main_by_vpc = {r["vpc"]: r["id"] for r in infra["route_tables"]
                   if r.get("main") and r.get("vpc")}
    claimed = {sid for r in infra["route_tables"] for sid in r["subnet_ids"]}
    vpc_by_subnet = {s["id"]: s.get("vpc") for s in infra["subnets"]}
    for rtb in infra["route_tables"]:
        if not rtb.get("main"):
            continue
        for sid, vpc in vpc_by_subnet.items():
            if sid not in claimed and vpc == rtb.get("vpc"):
                rtb["subnet_ids"].append(sid)
                claimed.add(sid)
    # 'main'/'vpc' are importer bookkeeping; the solver doesn't need them.
    for rtb in infra["route_tables"]:
        rtb.pop("main", None)
        rtb.pop("vpc", None)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sgs", required=True)
    ap.add_argument("--nacls", required=True)
    ap.add_argument("--rtbs", required=True)
    ap.add_argument("--instances", required=True)
    ap.add_argument("--subnets", required=True)
    ap.add_argument("--vpcs", required=True)
    ap.add_argument("--igws", required=True)
    ap.add_argument("--elbv2", default=None,
                    help="optional ELBv2 bundle JSON (see module docstring)")
    ap.add_argument("--elb", default=None,
                    help="optional Classic ELB describe-load-balancers JSON; "
                         "Classic LBs are not modeled, so any found become a "
                         "coverage gap (use scripts/collect_aws.sh)")
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("--print-collector", action="store_true")
    args = ap.parse_args()
    if args.print_collector:
        print(COLLECTOR)
        return
    files = {k: getattr(args, k) for k in
             ("sgs", "nacls", "rtbs", "instances", "subnets", "vpcs", "igws",
              "elbv2", "elb")}
    infra = build_infra(files)
    with open(args.output, "w") as fh:
        json.dump(infra, fh, indent=1)
    print(f"wrote {args.output}: {len(infra['instances'])} instances, "
          f"{len(infra['security_groups'])} security groups, "
          f"{len(infra['network_acls'])} NACLs, "
          f"{len(infra['route_tables'])} route tables")


if __name__ == "__main__":
    main()
