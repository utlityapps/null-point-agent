"""Small value objects shared by the NullPoint pipeline."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Preconditions:
    """Structured exploit preconditions extracted from a CVE advisory."""

    port: int
    protocol: str = "TCP"
    auth_required: bool = False
    network_vector: str = "NETWORK"
    payload_constraints: str = ""
    confidence: float = 0.0
    narrative_claim: str = "unknown"  # what the LLM *says* about exposure
    delivery: str = "unknown"  # "direct" | "data_plane" | "unknown"
    # direct: attacker opens a network connection to the service port.
    # data_plane: payload arrives indirectly (logs, headers, queues) — the
    #   reachability solver cannot falsify these; they go to human review.
    # unknown: advisory doesn't say — treated as data_plane (fail closed).


@dataclass
class Verdict:
    """Final decision for one scanner finding."""

    finding_id: str
    cve_id: str
    host: str
    port: int
    protocol: str
    reachable: bool
    trace: list = field(default_factory=list)
    decision: str = "undecided"  # actionable | dismissed | needs-review
    reason: str = ""
    guard_passed: bool = False
    exploitability: dict = field(default_factory=dict)
    # Structured exploit preconditions the model proposed for this finding
    # (port, protocol, auth_required, network_vector, payload_constraints,
    # confidence, narrative_claim). Stored so surfaces can render the
    # "model proposes" half of the pipeline without re-querying.
    preconditions: dict = field(default_factory=dict)
