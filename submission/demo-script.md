# NullPoint demo video — script & shot list (≤ 3:00)

**Total budget: 180 seconds.** Built around the before/after refusal
arc, recorded from `nullpoint-report.html` (self-contained, no network
needed during recording) plus one terminal window. **The human records
and uploads this** — nothing below requires anyone else.

## 0:00–0:20 — Hook (20s)

*On screen:* terminal running `python -m nullpoint.cli scan --offline`
— 11 CRITICAL alerts scrolling past.

*Narration:*
> "Every scanner does this: eleven critical alerts, patch everything,
> panic. But more alerts don't lower risk — they obscure it. We built
> the agent that says no."

## 0:20–0:50 — The Before (30s)

*On screen:* a generic AI assistant chat (mocked is fine) analyzing the
same scan: *"CRITICAL Log4j-style RCE on the analytics cluster.
Immediately patch 120 instances."*

*Narration:*
> "This is what today's AI security assistants do. Glorified scanners.
> One critical CVE, one hundred and twenty tickets, and zero questions
> asked about whether the vulnerability is even reachable."

## 0:50–1:50 — The Turn (60s)

*On screen:* switch to the NullPoint report. Finding selector on F-001
(CVE-2026-42424, i-analytics-1:8080). Three panels: **Model proposes**
(Nemotron's preconditions — TCP 8080, unauthenticated HTTP), **Code
proves** (hop-by-hop trace: internet → … → internal ALB, no ingress
edge; NACL deny rule 95 on 8080), **Product decides** (verdict pending).

*Narration:*
> "NullPoint does the opposite. NVIDIA Nemotron — served through Nebius
> Token Factory — reads the advisory and proposes the exploit
> preconditions: port 8080, unauthenticated HTTP. Then the deterministic
> graph engine tries to prove an attacker can get there. Every hop,
> every security group, every NACL rule. And it can't. The cluster sits
> behind an internal-only load balancer with no public route, and an
> explicit deny on the port."

## 1:50–2:30 — The Refusal (40s)

*On screen:* verdict banner flips to **DISMISSED — Zero Exposure**.
Falsification trace highlighted. Expand the dismissal-log entry
(hash-chained, tamper-evident).

*Narration:*
> "So NullPoint refuses. Not 'low priority' — dismissed, with the proof
> attached: no ingress path exists. The decision goes into a
> tamper-evident dismissal log, so it's auditable. And the model doesn't
> get a vote — a fail-closed guard blocks any claim the solver
> disagrees with."

## 2:30–2:55 — The After (25s)

*On screen:* the action queue — exactly **1 ticket** (F-011, edge
gateway admin API, genuinely internet-facing). Big stat overlay:
**11 raw alerts → 1 actionable.**

*Narration:*
> "Eleven alerts in, one ticket out — for the DevOps and SOC teams
> drowning in scanner noise. The single host that actually accepts
> untrusted traffic. That's the whole product: falsify first, alert
> later."

## 2:55–3:00 — Close (5s)

*On screen:* thesis line + repo URL.

*Narration:*
> "More alerts don't lower risk. NullPoint proves it."

---

## Shot list / production notes

- Screen-record at 1080p; bump terminal and browser font sizes so text
  reads at video resolution.
- `nullpoint-report.html` is fully self-contained — no network, no
  credentials on screen at any point (offline mode throughout).
- The "generic assistant" before-segment can be a simple mocked chat
  pane; label it as illustrative if there's any doubt.
- Keep narration tight; the timings above total exactly 180s — trim
  pauses, not content, if running long.
- **Human steps:** record, trim to ≤180s, upload to YouTube as
  **public**, paste the link into the Devpost submission.
