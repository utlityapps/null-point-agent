#!/usr/bin/env bash
# Collect read-only AWS inventory for the NullPoint importer.
#
# Runs every describe call nullpoint/aws_import.py needs and assembles the
# ELBv2 bundle (load balancers, listeners, target groups, target health,
# listener rules) plus the Classic ELB inventory, so following the README
# produces complete inputs — no hand-assembled bundles, no missing
# inventory gaps.
#
# Usage: scripts/collect_aws.sh [output-dir]   (default: aws-inventory)
#
# Honors AWS_PROFILE, AWS_REGION / AWS_DEFAULT_REGION like the AWS CLI does.
# All calls are read-only describe-*; nothing in the account is modified.
set -euo pipefail

OUT="${1:-aws-inventory}"
mkdir -p "$OUT"

AWS=(aws --output json --no-cli-pager)

echo "-> EC2 describe calls"
"${AWS[@]}" ec2 describe-security-groups    > "$OUT/sgs.json"
"${AWS[@]}" ec2 describe-network-acls       > "$OUT/nacls.json"
"${AWS[@]}" ec2 describe-route-tables       > "$OUT/rtbs.json"
"${AWS[@]}" ec2 describe-instances          > "$OUT/instances.json"
"${AWS[@]}" ec2 describe-subnets            > "$OUT/subnets.json"
"${AWS[@]}" ec2 describe-vpcs               > "$OUT/vpcs.json"
"${AWS[@]}" ec2 describe-internet-gateways  > "$OUT/igws.json"

echo "-> Classic ELB inventory"
"${AWS[@]}" elb describe-load-balancers > "$OUT/elb-classic.json" 2>/dev/null \
  || echo '{"LoadBalancerDescriptions": []}' > "$OUT/elb-classic.json"

echo "-> ELBv2 inventory"
mkdir -p "$OUT/elbv2"
"${AWS[@]}" elbv2 describe-load-balancers > "$OUT/elbv2/load-balancers.json" 2>/dev/null \
  || echo '{"LoadBalancers": []}' > "$OUT/elbv2/load-balancers.json"

python3 - "$OUT" "${AWS[@]}" <<'EOF'
import json, subprocess, sys

out, aws = sys.argv[1], sys.argv[2:]

def run(*args):
    return json.loads(subprocess.run(aws + list(args), capture_output=True,
                                     text=True, check=True).stdout)

lbs = run("elbv2", "describe-load-balancers").get("LoadBalancers", [])
listeners, target_groups, targets, rules = [], [], {}, []
for lb in lbs:
    arn = lb["LoadBalancerArn"]
    for lst in run("elbv2", "describe-listeners",
                   "--load-balancer-arn", arn).get("Listeners", []):
        listeners.append(lst)
        rules.extend(run("elbv2", "describe-rules",
                         "--listener-arn", lst["ListenerArn"]).get("Rules", []))
    for tg in run("elbv2", "describe-target-groups",
                  "--load-balancer-arn", arn).get("TargetGroups", []):
        target_groups.append(tg)
        th = run("elbv2", "describe-target-health",
                 "--target-group-arn", tg["TargetGroupArn"])
        targets[tg["TargetGroupArn"]] = [
            {"Id": d["Target"]["Id"], "Port": d["Target"].get("Port")}
            for d in th.get("TargetHealthDescriptions", [])
        ]

bundle = {"load_balancers": lbs, "listeners": listeners,
          "target_groups": target_groups, "targets": targets, "rules": rules}
with open(f"{out}/elbv2.json", "w") as fh:
    json.dump(bundle, fh, indent=1)
print(f"   {len(lbs)} load balancer(s), {len(listeners)} listener(s), "
      f"{len(target_groups)} target group(s), {len(rules)} rule(s)")
EOF

echo
echo "Collected into $OUT/. Build the infra snapshot with:"
echo
echo "  python3 -m nullpoint.aws_import --sgs $OUT/sgs.json --nacls $OUT/nacls.json \\"
echo "      --rtbs $OUT/rtbs.json --instances $OUT/instances.json --subnets $OUT/subnets.json \\"
echo "      --vpcs $OUT/vpcs.json --igws $OUT/igws.json \\"
echo "      --elbv2 $OUT/elbv2.json --elb $OUT/elb-classic.json -o infra.json"
