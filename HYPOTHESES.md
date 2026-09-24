# HYPOTHESES.md — falsifiable claims behind NullPoint

Per the winning playbook: plan 2–4 falsifiable hypotheses, document the
killed ones with numbers. Status is updated as evidence lands.

## H1 — Most "Critical" CVEs are unreachable from untrusted networks

**Claim:** In a typical cloud fleet, the majority of scanner-reported
Critical CVEs have no reachable execution path from the internet, because
the vulnerable services sit behind internal load balancers, private
subnets, and deny-by-default network controls.

**Falsification bar:** <50% of Critical findings dismissed on the fixture fleet.

**Status:** SUPPORTED (offline). Fixture fleet: 10 of 11 Critical findings
dismissed (90.9%) — only the edge gateway admin API is internet-reachable.
See `tests/test_alert_reduction.py`.

## H2 — The solver matches hand-verified review

**Claim:** The deterministic reachability solver's verdicts agree with
manual, by-hand AWS-console-style review on every fixture case.

**Falsification bar:** any single mismatch between solver output and the
documented manual reasoning.

**Status:** SUPPORTED (offline). Every expectation in
`tests/test_reachability.py` carries the manual derivation in comments;
all pass. Includes NACL first-match-wins semantics (explicit deny rule 95
beats lower-priority allows for 0.0.0.0/0; rule 90 allow wins for the VPC
CIDR).

## H3 — Nemotron extracts correct exploit preconditions

**Claim:** Nemotron extracts (port, protocol, auth_required) correctly from
CVE advisory text with ≥90% accuracy, so the solver always tests the right
(port, protocol) pair.

**Falsification bar:** <90% exact-match on (port, protocol, auth_required)
over a held-out advisory set.

**Status:** SUPPORTED (live). 2026-09-23: ran live against 20 labeled
advisories (`fixtures/h3_advisories.json`) via Nebius Token Factory with
`nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B` — **20/20 exact-match (100%)** on
(port, protocol, auth_required), bar was ≥90%. Raw responses and per-case
labels preserved in `fixtures/recorded/h3_live_run_2026-09-23.json`;
runner at `scripts/h3_live_run.py`.

Live-run corrections worth preserving: the repo's old default model ID
(`nvidia/nemotron-3-nano-30b`) is not in the Nebius catalog and would 400;
the served model is a *reasoning* model, so small `max_tokens` values return
`content: null` (the reasoning trace eats the budget) — the client now
defaults to 4096 and raises a clear error on empty content instead of
crashing in `json.loads`.

## H4 — Order-of-magnitude alert reduction

**Claim:** NullPoint reduces the actionable alert queue by ≥10x versus a
naive scanner that emits one Critical alert per vulnerable service.

**Falsification bar:** reduction ratio <10x on the fixture fleet.

**Status:** SUPPORTED (offline). 11 raw Critical alerts → 1 actionable
(11x). See `tests/test_alert_reduction.py`. Live-fleet validation deferred
to Phase 2.

## Killed hypotheses

None yet. This section is append-only: when a hypothesis fails, record the
numbers, what we learned, and what changed — retracted claims stay visible.
