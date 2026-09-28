# NullPoint Agent

**Thesis:** more security alerts do not lower risk — they obscure it. NullPoint
falsifies CVE exploitability against network telemetry and refuses to flag
CVEs with zero reachable execution path.

NullPoint is a cloud-posture agent for the **Nebius x NVIDIA Global AI
Hackathon** (Best Apps & Agents track). Instead of dumping hundreds of
"Critical" alerts on DevOps teams, it:

1. **Model proposes** — NVIDIA Nemotron (via Nebius Token Factory) extracts
   structured exploit preconditions (port, protocol, auth, payload, and
   *payload delivery*: direct vs data-plane vs unknown) from CVE advisories.
2. **Code proves** — a deterministic NetworkX graph engine evaluates AWS
   security groups, NACLs, route tables, load balancers, and transit
   gateways to compute *boolean* reachability from untrusted networks.
3. **Product decides** — reachable findings go to a ranked action queue
   (proven exposure outranks payload routing); unreachable findings with a
   direct payload are dismissed into a tamper-evident, hash-chained log;
   unreachable findings with data-plane/unknown delivery go to human
   review — a network proof cannot falsify them.

A fail-closed **narrative guard** blocks any LLM exposure claim the solver
disagrees with. The solver always wins: a blocked claim is logged as a
caught model error, but it never overrides the solver's verdict — neither
to suppress a real ticket nor to veto a proof. Numbers never pass through
the LLM.

```
[ NVIDIA Nemotron ] ──> exploit preconditions (port, protocol, auth, payload)
         │
         ▼
[ Python Graph Engine ] ──> boolean reachability over SG / NACL / ALB / Route53
         │
         ▼
[ NullPoint Control ] ──> action queue  vs  tamper-evident dismissal log
```

## Quickstart (offline judge mode — zero credentials, zero network)

```bash
pip install -r requirements.txt
pytest -q
python -m nullpoint.cli scan --offline
```

The scan runs entirely on recorded fixtures: 11 synthetic Critical findings
collapse to **1 actionable ticket** (the edge gateway) with 10 dismissals,
each logged with its falsification reason.

## Dual-surface UI (offline judge mode — zero credentials, zero network)

```bash
python -m nullpoint.report --offline        # writes nullpoint-report.html
# then open nullpoint-report.html in any browser (or: python3 -m http.server)
```

A single self-contained HTML file (inline CSS + vanilla JS, no external
assets, no server, no extra dependencies) with the two product surfaces:

1. **Investigation trace** — pick any finding: the model's proposed exploit
   preconditions, the solver's hop-by-hop reachability trace, and the final
   verdict (ACTIONABLE / DISMISSED / NEEDS REVIEW).
2. **Action queue vs dismissal log** — reachable findings ranked by
   weaponization intel, next to every dismissed alert expandable to its
   falsification trace and tamper-evident log entry.

The report opens on the refusal moment: the pre-auth RCE Critical on the
internal analytics cluster is refused (Zero Exposure) while the single
genuinely exposed edge gateway becomes the one ticket.

## Live mode (requires keys)

```bash
export NEBIUS_API_KEY=...            # Nebius Token Factory
export NEBIUS_BASE_URL=...           # override if needed
export NEBIUS_MODEL=...              # verify against the Nebius model catalog
export TAVILY_API_KEY=...            # optional: exploitability enrichment
python -m nullpoint.cli scan --live
```

Keys are read from the environment only. They are never written to disk,
never logged, and never committed — see `.gitignore` and
`tests/test_offline.py`.

## Real AWS infrastructure (read-only importer)

`nullpoint/aws_import.py` converts read-only `aws ec2 describe-*` JSON into
the `infra.json` format the solver reads. Nothing is modified in your
account:

```bash
aws ec2 describe-security-groups    > sgs.json
aws ec2 describe-network-acls      > nacls.json
aws ec2 describe-route-tables      > rtbs.json
aws ec2 describe-instances         > instances.json
aws ec2 describe-subnets           > subnets.json
aws ec2 describe-vpcs              > vpcs.json
aws ec2 describe-internet-gateways > igws.json
python -m nullpoint.aws_import --sgs sgs.json --nacls nacls.json \
  --rtbs rtbs.json --instances instances.json --subnets subnets.json \
  --vpcs vpcs.json --igws igws.json -o infra.json
```

The recommended path is `scripts/collect_aws.sh` — it runs every describe
call, assembles the ELBv2 bundle, and captures Classic ELB inventory, so a
single command produces complete inputs:

```bash
scripts/collect_aws.sh aws-inventory
# then run the printed aws_import command with --elbv2 and --elb included
```

The importer treats **missing load-balancer inventory as a coverage gap,
not as "no load balancers"**: if `--elbv2` is omitted, every instance in the
snapshot fails closed to human review on dismissal paths (an unseen ALB
could expose it). Passing the bundle — even with zero load balancers, which
the script always writes — proves the inventory is complete and clears the
gap. Classic ELBs are inventoried but not modeled: any found become a
VPC-wide coverage gap.

Instance services are parsed from an optional `nullpoint:services` tag,
e.g. `8080/TCP:analytics-app,9100/TCP`, and kept in the infra snapshot for
inventory context. The port the solver *tests* always starts from the
scanner finding's observed port — never from the model, never from the tag.
(Prove first, then doubt: when the observed and model ports disagree, both
are tested; if either proves reachable the finding is actionable. A wrong
model port can only add a ticket, never dismiss one.)
ELBv2 load balancers are imported with each target's **registered port**
(from describe-target-health), so the solver validates per-target ports
rather than assuming the target-group port. NLBs have no security groups,
so the LB security-group check is skipped for them. HTTPS/HTTP listeners
are matched as TCP, and an app security group that allows the VPC CIDR
(rather than the ALB's security group) is honored on the ALB→instance hop,
so apps behind real ALBs are not misread as unreachable.

Fail-closed coverage: anything the network model cannot see is recorded in
`infra.json` as a `coverage_gaps` entry instead of being silently dropped —
auth actions (Cognito/OIDC) before a forward, weighted forwards, IP-type or
other non-instance targets, unevaluated listener rules, and IPv6 routes.
Findings on gap-affected hosts are never dismissed; they go to human
review. Gaps only ever weaken dismissals — a proven-reachable finding is
still actionable.

Scan the imported infrastructure directly:

```bash
python -m nullpoint.cli scan --offline --infra infra.json
python -m nullpoint.report --offline --infra infra.json
```

## Real scanner findings (`--findings`)

Findings are not hard-coded: `scan` and `report` accept `--findings` with
either native findings JSON (`{"findings": [...]}`) or raw
`aws inspector2 list-findings` output (auto-detected):

```bash
aws inspector2 list-findings \
  --filter-criteria '{"findingStatus":[{"comparison":"EQUALS","value":"ACTIVE"}]}' \
  > inspector-findings.json
python -m nullpoint.cli scan --infra infra.json --findings inspector-findings.json --live
```

## Honest limitations

The solver proves reachability over what it can model; everything else
fails closed to human review rather than being silently dropped. The
remaining AWS edge cases, listed instead of chased:

- **Classic ELBs** are inventoried but not modeled — any found become a
  VPC-wide coverage gap, and findings on affected hosts go to review.
- **Missing load-balancer inventory** (no `--elbv2`) is a coverage gap,
  not an assumption of "no load balancers". `scripts/collect_aws.sh`
  always writes the bundle, even when empty, so this only fires on
  hand-rolled imports.
- **ALB→ALB chains and Lambda targets** are unmodeled target types —
  recorded as coverage gaps, never treated as dead ends.
- **IPv6 routes** are not evaluated; route tables with IPv6 routes are a
  coverage gap.
- **Listener-rule conditions** are not evaluated: the importer parses the
  non-default rule targets (so they are not lost) but records a gap —
  host/path-based routing differences are not proven.
- **Weighted forwards** are treated as the union of targets; the weights
  themselves are not modeled.
- **Auth actions before a forward** (Cognito/OIDC) mean the traffic's
  admissibility is unknown — gap, never dismissal.
- **Security-group egress** on load-balancer hops is not evaluated. The
  product's catastrophic failure mode is a false *dismissal*; ignoring an
  egress deny can only produce a false *actionable*, which a human clears.
- **VPC endpoints / PrivateLink, cross-account ENIs, and VPC peering
  specifics** are not modeled as ingress paths.
- **Inspector2 package findings carry no port.** If the host has no
  internet path at all, the any-port proof dismisses them anyway; on hosts
  with an internet path they route to human review (nothing left to prove).
- Only `PACKAGE_VULNERABILITY` findings with a real CVE ID are converted —
  `NETWORK_REACHABILITY` findings ("Port 22 is reachable…") are skipped,
  not coerced into fake CVE IDs.
- Findings on non-EC2 resources (e.g. ECR images) map to host `unknown`
  and route to human review via the unknown-host rule.

Real CVE IDs need live mode (`--live` with `NEBIUS_API_KEY` /
`TAVILY_API_KEY`); offline stubs only cover the fixture CVEs.

## Seeing the fail-closed routes

The bundled demo (`fixtures/cves.json`) resolves to 11 findings → 1
actionable, 10 dismissed, 0 needs-review. To watch the human-review queue
work, run the review demo — one finding on a host missing from the snapshot,
one unprocessable offline:

```bash
python -m nullpoint.cli scan --offline --findings fixtures/findings-review-demo.json
```

Both land in `NEEDS HUMAN REVIEW` via different fail-closed routes, and the
scan completes instead of crashing.

## Layout

```
nullpoint/
  graph.py          deterministic reachability engine (the load-bearing core)
  nemotron.py       Nemotron via Nebius Token Factory (OpenAI-compatible)
  tavily.py         CVE exploitability / weaponization enrichment
  guard.py          fail-closed narrative guard (LLM claim vs solver)
  dismissal_log.py  append-only hash-chained JSONL dismissal log
  scanner.py        pipeline: propose -> prove -> decide
  aws_import.py     read-only AWS describe-* -> infra.json importer
  cli.py            demo CLI (`scan` command)
  report.py         dual-surface UI generator (`python -m nullpoint.report --offline`)
  _report_template.html
                    self-contained HTML shell (inline CSS/JS, zero external assets)
fixtures/
  infra.json        synthetic AWS infra (internal cluster + edge gateway)
  cves.json         11 synthetic Critical findings
  recorded/         recorded Nemotron + Tavily responses (offline mode)
tests/              pytest suite (reachability, guard, offline, reduction)
HYPOTHESES.md       falsifiable hypotheses + status
```

## Roadmap

- Dual-surface UI: done (`python -m nullpoint.report --offline`).
- Nebius live run: done — H3 scored 20/20 live on 2026-09-23.
- Tavily live: verified 2026-09-27 with a one-time key (transient use, never stored); offline recordings cover the demo.
- Remaining: ≤3-min demo video, Devpost submission.
- See `HYPOTHESES.md` for what is proven offline vs deferred to live runs.

## License

Apache-2.0 — see `LICENSE`.
