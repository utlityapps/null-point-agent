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
