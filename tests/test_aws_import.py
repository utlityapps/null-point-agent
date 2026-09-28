"""AWS importer: read-only describe-* JSON converts to solver-ready infra."""
from nullpoint import aws_import as ai
from nullpoint import graph as graph_mod


def _doc():
    return {
        "sgs": {"SecurityGroups": [{
            "GroupId": "sg-web",
            "IpPermissions": [{
                "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": [],
                "UserIdGroupPairs": [{"GroupId": "sg-app"}],
            }],
            "IpPermissionsEgress": [{
                "IpProtocol": "-1", "FromPort": -1, "ToPort": -1,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": [], "UserIdGroupPairs": [],
            }],
        }]},
        "nacls": {"NetworkAcls": [{
            "NetworkAclId": "acl-1",
            "Entries": [
                {"RuleNumber": 100, "Protocol": "6", "RuleAction": "allow",
                 "Egress": False, "CidrBlock": "0.0.0.0/0",
                 "PortRange": {"From": 443, "To": 443}},
                {"RuleNumber": 32767, "Protocol": "-1", "RuleAction": "deny",
                 "Egress": False, "CidrBlock": "0.0.0.0/0"},
            ],
            "Associations": [{"SubnetId": "subnet-1"}],
        }]},
        "rtbs": {"RouteTables": [{
            "RouteTableId": "rtb-1",
            "Routes": [
                {"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local"},
                {"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1"},
            ],
            "Associations": [{"SubnetId": "subnet-1"}],
        }]},
        "instances": {"Reservations": [{"Instances": [{
            "InstanceId": "i-abc", "PrivateIpAddress": "10.0.1.5",
            "PublicIpAddress": "54.1.2.3",
            "SubnetId": "subnet-1",
            "SecurityGroups": [{"GroupId": "sg-web"}],
            "Tags": [{"Key": "nullpoint:services",
                      "Value": "443/TCP:web,8080/TCP"}],
        }]}]},
        "subnets": {"Subnets": [{
            "SubnetId": "subnet-1", "CidrBlock": "10.0.1.0/24",
            "VpcId": "vpc-1", "AvailabilityZone": "us-east-1a",
            "MapPublicIpOnLaunch": True,
        }]},
        "vpcs": {"Vpcs": [{"VpcId": "vpc-1", "CidrBlock": "10.0.0.0/16"}]},
        "igws": {"InternetGateways": [{
            "InternetGatewayId": "igw-1",
            "Attachments": [{"VpcId": "vpc-1"}],
        }]},
    }


def test_importer_converts_describe_output():
    d = _doc()
    sgs = ai.import_security_groups(d["sgs"])
    assert sgs[0]["id"] == "sg-web"
    assert {"protocol": "tcp", "from_port": 443, "to_port": 443,
            "cidr": "0.0.0.0/0"} in sgs[0]["ingress"]
    assert {"protocol": "tcp", "from_port": 443, "to_port": 443,
            "source_sg": "sg-app"} in sgs[0]["ingress"]
    assert sgs[0]["egress"][0]["protocol"] == "-1"

    nacls = ai.import_network_acls(d["nacls"])
    assert nacls[0]["subnet_ids"] == ["subnet-1"]
    assert nacls[0]["ingress"][0]["rule_number"] == 100

    rtbs = ai.import_route_tables(d["rtbs"])
    assert {"cidr": "0.0.0.0/0", "target": "igw-1"} in rtbs[0]["routes"]

    insts = ai.import_instances(d["instances"])
    assert insts[0]["id"] == "i-abc"
    assert insts[0]["public_ip"] == "54.1.2.3"
    assert {"name": "web", "port": 443, "protocol": "TCP"} in insts[0]["services"]
    assert {"name": "port-8080", "port": 8080, "protocol": "TCP"} in insts[0]["services"]


def test_imported_infra_feeds_solver():
    d = _doc()
    infra = {
        "instances": ai.import_instances(d["instances"]),
        "internet_gateways": ai.import_internet_gateways(d["igws"]),
        "load_balancers": [],
        "network_acls": ai.import_network_acls(d["nacls"]),
        "route53": [], "route_tables": ai.import_route_tables(d["rtbs"]),
        "security_groups": ai.import_security_groups(d["sgs"]),
        "subnets": ai.import_subnets(d["subnets"]),
        "transit_gateways": [], "vpcs": ai.import_vpcs(d["vpcs"]),
    }
    solver = graph_mod.InfraGraph(infra)
    reachable, _ = solver.check_reachability(graph_mod.INTERNET, "i-abc", 443, "TCP")
    assert reachable is True


def test_all_traffic_ingress_rule_has_no_port_restriction():
    # Regression: an "All traffic from 0.0.0.0/0" rule (IpProtocol -1) must
    # not read as unreachable. The solver treats None ports as unrestricted;
    # mapping them to 0/0 matched nothing.
    sgs = ai.import_security_groups({"SecurityGroups": [{
        "GroupId": "sg-open",
        "IpPermissions": [{
            "IpProtocol": "-1", "FromPort": -1, "ToPort": -1,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            "Ipv6Ranges": [], "UserIdGroupPairs": [],
        }],
        "IpPermissionsEgress": [],
    }]})
    rule = sgs[0]["ingress"][0]
    assert rule["protocol"] == "-1"
    assert rule["from_port"] is None and rule["to_port"] is None
    solver = graph_mod.InfraGraph({"instances": [], "internet_gateways": [],
                                   "load_balancers": [], "network_acls": [],
                                   "route53": [], "route_tables": [],
                                   "security_groups": sgs, "subnets": [],
                                   "transit_gateways": [], "vpcs": []})
    assert solver.sg_allows(["sg-open"], ["0.0.0.0/0"], None, 5432, "TCP") is True


def test_main_route_table_fallback():
    # Regression: subnets with no explicit RTB association (every default-VPC
    # subnet) use the VPC's main table. Without the fallback they read as
    # having no IGW route, so public instances look unreachable.
    rtbs = ai.import_route_tables({"RouteTables": [{
        "RouteTableId": "rtb-main", "VpcId": "vpc-1",
        "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1"}],
        "Associations": [{"RouteTableAssociationId": "a1", "Main": True}],
    }]})
    infra = {"instances": [], "internet_gateways": [],
             "load_balancers": [], "network_acls": [], "route53": [],
             "route_tables": rtbs, "security_groups": [],
             "subnets": ai.import_subnets({"Subnets": [{
                 "SubnetId": "subnet-9", "CidrBlock": "10.0.9.0/24",
                 "VpcId": "vpc-1", "AvailabilityZone": "us-east-1a",
                 "MapPublicIpOnLaunch": True}]}),
             "transit_gateways": [],
             "vpcs": ai.import_vpcs({"Vpcs": [{"VpcId": "vpc-1",
                                              "CidrBlock": "10.0.0.0/16"}]})}
    ai._apply_main_route_tables(infra)
    assert "subnet-9" in infra["route_tables"][0]["subnet_ids"]
    assert "main" not in infra["route_tables"][0]  # bookkeeping stripped
    solver = graph_mod.InfraGraph(infra)
    assert solver.subnet_has_igw_route("subnet-9") is True
