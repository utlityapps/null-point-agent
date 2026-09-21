# NullPoint Agent

**Thesis:** more security alerts do not lower risk — they obscure it. NullPoint
falsifies CVE exploitability against network telemetry and refuses to flag
CVEs with zero reachable execution path.

NullPoint is a cloud-posture agent for the **Nebius x NVIDIA Global AI
Hackathon** (Best Apps & Agents track). Instead of dumping hundreds of
"Critical" alerts on DevOps teams, it:

1. **Model proposes** — NVIDIA Nemotron (via Nebius Token Factory) extracts
   structured exploit preconditions (port, protocol, auth, payload) from CVE
   advisories.
2. **Code proves** — a deterministic NetworkX graph engine evaluates AWS
   security groups, NACLs, route tables, load balancers, and transit
   gateways to compute *boolean* reachability from untrusted networks.
3. **Product decides** — reachable findings go to a ranked action queue;
   unreachable ones are dismissed into a tamper-evident, hash-chained log.

A fail-closed **narrative guard** blocks any LLM exposure claim the solver
disagrees with. Numbers never pass through the LLM.

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

## Layout

```
nullpoint/
  graph.py          deterministic reachability engine (the load-bearing core)
  nemotron.py       Nemotron via Nebius Token Factory (OpenAI-compatible)
  tavily.py         CVE exploitability / weaponization enrichment
  guard.py          fail-closed narrative guard (LLM claim vs solver)
  dismissal_log.py  append-only hash-chained JSONL dismissal log
  scanner.py        pipeline: propose -> prove -> decide
  cli.py            demo CLI (`scan` command)
fixtures/
  infra.json        synthetic AWS infra (internal cluster + edge gateway)
  cves.json         11 synthetic Critical findings
  recorded/         stubbed Nemotron + Tavily responses (offline mode)
tests/              pytest suite (reachability, guard, offline, reduction)
HYPOTHESES.md       falsifiable hypotheses + status
```

## Roadmap

- Phase 2: live Nebius/Tavily runs, dual-surface UI (investigation trace +
  action queue), ≤3-min demo video, Devpost submission.
- See `HYPOTHESES.md` for what is proven offline vs deferred to live runs.

## License

Apache-2.0 — see `LICENSE`.
