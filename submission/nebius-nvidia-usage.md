# How NullPoint uses Nebius and NVIDIA

An important distinction up front: **the agent runs on Nebius; AWS is the
audited input data, not the runtime.** NullPoint never deploys to AWS and
never needs AWS credentials. The infrastructure under audit is described
by JSON fixtures (synthetic topologies in this repo; a customer's real
topology in production). All inference and reasoning happen on Nebius.

## NVIDIA on Nebius — the load-bearing AI path

- **NVIDIA Nemotron**, served through **Nebius Token Factory**, is the
  agent's reasoning layer. It ingests raw CVE advisory text and extracts
  structured exploit preconditions: port, protocol, auth requirements,
  payload constraints, plus a one-line narrative exposure guess.
- **Integration:** OpenAI-compatible Chat Completions API at
  `https://api.tokenfactory.nebius.com/v1`, API key in the
  `Authorization: Bearer` header. Extraction uses temperature 0 and
  requests JSON-only output (`response_format: {"type": "json_object"}`).
  Default model `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B` (verified live
  against the Nebius catalog on 2026-09-23), overridable via
  `NEBIUS_MODEL`. The model is a reasoning model, so the client requests
  a generous token budget (4096) — small budgets return empty content.
- **Why it's load-bearing, not decorative:** Nemotron's output is the
  *input* to the deterministic reachability solver — the solver cannot
  test the right (port, protocol) pair without it. The narrative guard
  then checks the model's exposure guess against the solver's boolean
  verdict and blocks any disagreement, fail-closed. This is the "model
  proposes, code proves" contract: Nemotron does what LLMs are good at
  (parsing messy advisory text into structure) and is never trusted with
  the reachability decision.

## Tavily — enrichment, never decision

Tavily's search API fetches real-time exploitability metadata for each
CVE: CISA Known Exploited Vulnerabilities listing and observed
weaponization. This feeds **only the ranking** of already-reachable
findings in the action queue. Reachability is decided solely by the
deterministic solver; Tavily evidence can promote a reachable finding,
never rescue an unreachable one.

## Live vs offline — stated honestly

- **Live mode:** Nemotron precondition extraction and Tavily enrichment,
  keyed via `NEBIUS_API_KEY` / `TAVILY_API_KEY` environment variables
  (`python -m nullpoint.cli scan --live`). H3 (extraction accuracy
  scoring) was exercised live on 2026-09-23: 20/20 exact-match on 20
  labeled advisories via `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B`.
  Tavily live enrichment remains unexercised.
- **Offline / judge mode:** recorded fixture responses serve both
  integrations; the full pipeline — 28 tests, CLI scan, self-contained
  HTML report — runs with **zero credentials and zero network**. Keys
  are read from the environment only: never written to disk, never
  logged, never committed (enforced by `.gitignore` and
  `tests/test_offline.py`).
