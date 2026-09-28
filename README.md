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

Instance services (which ports the solver tests) come from an optional
`nullpoint:services` tag, e.g. `8080/TCP:analytics-app,9100/TCP`.
ELBv2 load balancers are supported via an optional `--elbv2` bundle —
see `python -m nullpoint.aws_import --help`.

Scan the imported infrastructure directly:

```bash
python -m nullpoint.cli scan --offline --infra infra.json
python -m nullpoint.report --offline --infra infra.json
```

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
- Tavily live: verified 2026-09-27 (one-time key, since rotated); offline recordings cover the demo.
- Remaining: ≤3-min demo video, Devpost submission.
- See `HYPOTHESES.md` for what is proven offline vs deferred to live runs.

## License

Apache-2.0 — see `LICENSE`.
