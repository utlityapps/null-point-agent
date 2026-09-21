# NullPoint Agent — falsify first, alert later

**Track:** Best Apps & Agents · **License:** Apache-2.0

**One-line thesis:** More security alerts do not lower risk — they obscure it.

## The problem

Cloud scanners emit hundreds of "Critical" CVE alerts, and today's AI
security assistants act as glorified scanners: they turn those alerts into
endless remediation checklists without ever asking whether the
vulnerability is reachable. DevOps teams get noise, not risk. Most
"critical" findings describe services with no execution path from an
untrusted network — they can never be exploited, but they drown the one
finding that can.

## What NullPoint does

NullPoint is a cloud-posture agent that treats every CVE alert as
*unproven* and actively attempts to **falsify exploitability** against
network telemetry. If no ingress path can physically reach the vulnerable
socket, it **refuses to flag the CVE** — dismissing it with an attached
falsification trace instead of a ticket.

## How it works — Model Proposes, Code Proves, Product Decides

1. **Model proposes** — NVIDIA Nemotron, served via Nebius Token Factory,
   reads a CVE advisory and extracts structured exploit preconditions:
   port, protocol, auth requirements, payload constraints, plus a
   one-line narrative exposure guess.
2. **Code proves** — a deterministic Python/NetworkX engine traverses the
   cloud network graph (AWS security groups, NACLs with first-match-wins
   semantics, route tables, ALBs, transit gateways, Route53 records) and
   computes *boolean* reachability from untrusted networks. No
   probabilities, no LLM involvement in the verdict. Numbers never pass
   through the LLM.
3. **Product decides** — reachable findings land in a ranked action
   queue; unreachable ones are dismissed into a **tamper-evident,
   hash-chained dismissal log**, each entry carrying its falsification
   reason. A **fail-closed narrative guard** blocks any LLM exposure
   claim the solver disagrees with — the model narrates, the code
   decides.

## The demo: the refusal moment

A generic AI assistant analyzes an infrastructure scan containing a
CRITICAL Log4j-style RCE (CVE-2026-42424) on an internal analytics
cluster: *"Critical risk! Immediately patch 120 instances."*

NullPoint runs the same scan. Nemotron extracts the preconditions (TCP
8080, unauthenticated HTTP). The graph engine traces every hop and finds
the cluster sits behind an **internal-only ALB with no internet ingress
edge** and an **explicit NACL deny on port 8080**. NullPoint halts
escalation, outputs the falsification trace, and marks the CVE
**DISMISSED — Zero Exposure**. The 11-alert incident collapses to **1
actionable ticket**: the single edge-facing gateway that genuinely
accepts untrusted traffic.

## Tested hypotheses (H1–H4)

| # | Claim | Status |
|---|-------|--------|
| H1 | Majority of "Critical" CVEs have no reachable ingress path | SUPPORTED offline — 10/11 dismissed (90.9%) |
| H2 | Solver verdicts match hand-verified review on every fixture | SUPPORTED offline — incl. NACL first-match-wins edge cases |
| H3 | Nemotron extracts correct (port, protocol, auth) ≥90% of the time | NOT YET TESTED — needs a live Nebius Token Factory key; extraction *interface* is tested offline via recorded stubs |
| H4 | ≥10x alert reduction vs naive scanner | SUPPORTED offline — 11 raw alerts → 1 actionable |

See `HYPOTHESES.md` in the repo — it is append-only, and retracted
claims stay visible.

## Honest limitations

- Fixtures are **synthetic** AWS topologies; live-fleet validation is
  future work. H1/H2/H4 are proven on fixtures, not on a real fleet.
- The dismissal log is **tamper-evident** (hash-chained), not
  cryptographic proof: it detects modification or deletion of history,
  but not truncation of the newest entries (external hash anchoring is
  deferred).
- Stateless NACL return traffic is not explicitly modeled; fixtures use
  the realistic egress-allow-all default.
- Nemotron model ID and endpoint are verified against public docs, not
  yet against a live account. Everything runs fully **offline with zero
  credentials** — judges can reproduce every claim without keys.

## Run it yourself (zero credentials, zero network)

```bash
pip install -r requirements.txt
pytest -q                                   # 28 tests
python -m nullpoint.cli scan --offline      # the refusal moment, in your terminal
python -m nullpoint.report --offline        # self-contained HTML UI — open in any browser
```

With a Nebius Token Factory key (`NEBIUS_API_KEY`), the same pipeline
runs live: `python -m nullpoint.cli scan --live`. Keys are read from the
environment only — never written to disk, never logged, never committed.
