# Sponsor tooling feedback — Nebius Token Factory (+ Tavily)

Honest notes from building NullPoint Agent. Nebius feedback below is
**live-tested**: on 2026-09-23 we ran hypothesis H3 against the real
Token Factory API (20 labeled CVE advisories → 20/20 exact-match
precondition extraction via `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B`).
Tavily live enrichment remains unexercised; its notes are integration-
design only. Nothing here is invented.

## What worked well

1. **OpenAI-compatible endpoint.** Pointing an OpenAI-style client at
   `https://api.tokenfactory.nebius.com/v1` with a Bearer key was the
   entire integration — no custom SDK, no new auth dance. Temperature 0
   plus JSON-only responses give us deterministic-shaped extraction
   output, which is exactly what a "model proposes, code proves"
   architecture needs. *(Live-tested: all 20 H3 extractions returned
   clean parseable JSON.)*
2. **Structured output honored.** `response_format: {"type":
   "json_object"}` worked on the Nemotron variant we used — no
   prompt-level fallback was needed in the live run.
3. **NVIDIA model catalog breadth.** Nemotron variants being first-class
   in the catalog is what makes the "NVIDIA model in a load-bearing
   role" requirement satisfiable without contortions — the model isn't
   bolted on for the rubric, it's the precondition extractor the solver
   depends on.

## What was confusing or missing

1. **Two base URLs in Nebius's own materials.** The Token Factory docs
   use `https://api.tokenfactory.nebius.com/v1/`; a Nebius-published
   integration skill lists `https://api.studio.nebius.com/v1/` as the
   default. Both appear in Nebius-owned content. We defaulted to the
   Token Factory docs' URL and made it overridable via
   `NEBIUS_BASE_URL`, but a single canonical URL in the docs would
   remove the guesswork for every hackathon team.
2. **Model IDs must match the live catalog exactly.** Our first default
   (`nvidia/nemotron-3-nano-30b`, guessed from the public catalog page)
   400'd against the live API; the served ID is
   `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B`. A pinned "hackathon
   quickstart model ID" in the docs would save every team this round
   trip. *(Live-tested.)*
3. **Reasoning models eat small token budgets silently.** Nemotron is a
   reasoning model: with a small `max_tokens` the reasoning trace
   consumes the whole budget and the API returns `content: null` with
   no error. We had to raise the budget to 4096 and add explicit
   empty-content handling. A docs note — or a distinct error instead of
   null content — would help. *(Live-tested.)*
4. **Tavily (non-sponsor, for completeness).** The search API was
   straightforward to integrate, but EPSS scores are not available via
   search — we left `epss: null` and documented that a dedicated feed
   would be needed for EPSS-based ranking. *(Integration-design only;
   live call pending key.)*

## Bottom line

Nothing blocked the build: the offline-stub architecture meant
integration code, all 28 tests, and the demo all work with zero keys.
The Nebius key unlocked exactly what we predicted — live
extraction-accuracy scoring (H3: 20/20 on 2026-09-23) — and surfaced
two real gotchas (exact model IDs, reasoning token budgets) that are
worth a docs line each. If those were fixed, the path from "new
account" to "first live Nemotron call" would be under ten minutes.
Tavily live enrichment is still unexercised.
