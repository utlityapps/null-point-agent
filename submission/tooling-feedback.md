# Sponsor tooling feedback — Nebius Token Factory (+ Tavily)

Honest notes from building NullPoint Agent. Live-API experience is
**pending an API key**; the feedback below covers documentation and
integration design, and every item is marked for what is docs-verified
vs live-tested. Nothing here is invented.

## What worked well

1. **OpenAI-compatible endpoint.** Pointing an OpenAI-style client at
   `https://api.tokenfactory.nebius.com/v1` with a Bearer key was the
   entire integration — no custom SDK, no new auth dance. Temperature 0
   plus JSON-only responses give us deterministic-shaped extraction
   output, which is exactly what a "model proposes, code proves"
   architecture needs. *(Docs-verified; live call pending key.)*
2. **Docs clarity.** The Token Factory introduction page walks from key
   creation (API keys section → Create → save once, it can't be viewed
   later) to a working Python snippet in one page. The auth model is
   stated plainly: Bearer header, keep keys out of client-side code,
   rotate on compromise.
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
2. **Model IDs need a live account to verify.** We set a Nemotron
   default (`nvidia/nemotron-3-nano-30b`) from the public catalog, but
   confirming an exact, currently-served model ID requires signing in —
   the public catalog doesn't resolve this for an anonymous reader. A
   small unauthenticated `GET /models`, or a pinned "hackathon
   quickstart model ID," would help teams ship with confidence.
3. **Structured output support is undocumented per model.** The docs
   don't explicitly confirm `response_format: {"type": "json_object"}`
   support on Nemotron variants; we coded for it on OpenAI-compatibility
   grounds but haven't live-tested it. If a variant doesn't honor it,
   our fallback is prompt-level JSON plus parse validation — worth a
   docs line either way.
4. **Tavily (non-sponsor, for completeness).** The search API was
   straightforward to integrate, but EPSS scores are not available via
   search — we left `epss: null` and documented that a dedicated feed
   would be needed for EPSS-based ranking.

## Bottom line

Nothing here blocked the build: the offline-stub architecture meant
integration code, all 28 tests, and the demo all work with zero keys.
The API key unlocks live extraction-accuracy scoring (hypothesis H3),
not the demo itself. If the docs nits above were fixed, the path from
"new account" to "first live Nemotron call" would be under ten minutes.
