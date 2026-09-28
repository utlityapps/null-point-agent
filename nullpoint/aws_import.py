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


def import_elbv2(bundle: dict) -> list[dict]:
    """Optional ELBv2 bundle: {"load_balancers": [...], "listeners": [...],
    "target_groups": [...], "targets": {tg_arn: [{"Id": ...}]}}."""
    tg_port = {tg["TargetGroupArn"]: tg.get("Port")
               for tg in bundle.get("target_groups", [])}
    listeners_by_lb: dict[str, list[dict]] = {}
    for lst in bundle.get("listeners", []):
        listeners_by_lb.setdefault(lst["LoadBalancerArn"], []).append(lst)
    out = []
    for lb in bundle.get("load_balancers", []):
        listeners = []
        for lst in listeners_by_lb.get(lb["LoadBalancerArn"], []):
            actions = lst.get("DefaultActions", [])
            tg_arn = actions[0].get("TargetGroupArn") if actions else None
            targets = [t["Id"] for t in bundle.get("targets", {}).get(tg_arn, [])]
            listeners.append({
                "port": lst["Port"],
                "protocol": str(lst.get("Protocol", "TCP")).upper(),
                "target_port": tg_port.get(tg_arn, lst["Port"]),
                "targets": targets,
            })
        out.append({
            "id": lb.get("LoadBalancerName", lb["LoadBalancerArn"]),
            "scheme": lb.get("Scheme", "internal"),
            "security_groups": lb.get("SecurityGroups", []),
            "subnets": [az["SubnetId"] for az in lb.get("AvailabilityZones", [])
                        if az.get("SubnetId")],
            "listeners": listeners,
        })
    return out


COLLECTOR = """\
aws ec2 describe-security-groups    > sgs.json
aws ec2 describe-network-acls      > nacls.json
aws ec2 describe-route-tables      > rtbs.json
aws ec2 describe-instances         > instances.json
aws ec2 describe-subnets           > subnets.json
aws ec2 describe-vpcs              > vpcs.json
aws ec2 describe-internet-gateways > igws.json
# ELBv2 (optional): assemble {"load_balancers","listeners","target_groups","targets"}
# from describe-load-balancers / describe-listeners / describe-target-groups /
# describe-target-health, then pass it with --elbv2.
"""


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
    }
    if files.get("elbv2"):
        infra["load_balancers"] = import_elbv2(_load(files["elbv2"]))
    _apply_main_route_tables(infra)
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
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("--print-collector", action="store_true")
    args = ap.parse_args()
    if args.print_collector:
        print(COLLECTOR)
        return
    files = {k: getattr(args, k) for k in
             ("sgs", "nacls", "rtbs", "instances", "subnets", "vpcs", "igws", "elbv2")}
    infra = build_infra(files)
    with open(args.output, "w") as fh:
        json.dump(infra, fh, indent=1)
    print(f"wrote {args.output}: {len(infra['instances'])} instances, "
          f"{len(infra['security_groups'])} security groups, "
          f"{len(infra['network_acls'])} NACLs, "
          f"{len(infra['route_tables'])} route tables")


if __name__ == "__main__":
    main()
