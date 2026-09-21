"""NVIDIA Nemotron via Nebius Token Factory — exploit-precondition extraction.

The model *proposes*: given CVE advisory text it extracts structured exploit
preconditions (port, protocol, auth requirements, payload constraints) plus a
one-line narrative claim about exposure. The deterministic solver in
:mod:`nullpoint.graph` then *proves* or falsifies reachability, and
:mod:`nullpoint.guard` blocks any narrative claim the solver disagrees with.

Offline rule: when no ``NEBIUS_API_KEY`` is present (the default in judge
mode, CI, and tests), the client serves recorded fixture responses and never
touches the network. A real key is never required.
"""
from __future__ import annotations

import json
import os

import requests

from .models import Preconditions

DEFAULT_BASE_URL = "https://api.tokenfactory.nebius.com/v1"  # override via NEBIUS_BASE_URL
DEFAULT_MODEL = "nvidia/nemotron-3-nano-30b"  # override via NEBIUS_MODEL; verify against the Nebius catalog

EXTRACTION_SYSTEM_PROMPT = """\
You extract structured exploit preconditions from a CVE advisory.
Respond with JSON only, exactly this shape:
{
  "port": <int>,
  "protocol": "TCP" | "UDP",
  "auth_required": <bool>,
  "network_vector": "NETWORK" | "ADJACENT" | "LOCAL",
  "payload_constraints": "<one sentence>",
  "confidence": <0.0-1.0>,
  "narrative_claim": "exposed" | "isolated" | "unknown"
}
"narrative_claim" is your best guess at whether the vulnerable service is
exposed to untrusted networks, based on the advisory text alone. It is a
guess: the deterministic solver verifies it and the narrative guard blocks
it if it disagrees.
"""


class OfflineError(RuntimeError):
    """Raised when offline mode has no recorded response for a CVE."""


class NemotronClient:
    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        stub_responses: dict | None = None,
        offline: bool | None = None,
    ):
        self.api_key = api_key if api_key is not None else os.environ.get("NEBIUS_API_KEY")
        self.base_url = (base_url or os.environ.get("NEBIUS_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")
        self.model = model or os.environ.get("NEBIUS_MODEL") or DEFAULT_MODEL
        self.stub_responses = stub_responses or {}
        # Offline unless explicitly asked for live AND a key exists.
        self.offline = (not self.api_key) if offline is None else offline

    @classmethod
    def from_fixtures(cls, fixtures_dir: str, **kwargs) -> "NemotronClient":
        path = os.path.join(fixtures_dir, "recorded", "nemotron_extractions.json")
        with open(path) as fh:
            stubs = {k: v for k, v in json.load(fh).items() if not k.startswith("_")}
        return cls(stub_responses=stubs, **kwargs)

    def extract_preconditions(self, cve_id: str, cve_text: str) -> Preconditions:
        if self.offline:
            if cve_id not in self.stub_responses:
                raise OfflineError(f"no recorded Nemotron response for {cve_id} (offline mode)")
            data = dict(self.stub_responses[cve_id])
        else:
            data = self._call_live(cve_id, cve_text)
        return Preconditions(
            port=int(data["port"]),
            protocol=str(data.get("protocol", "TCP")),
            auth_required=bool(data.get("auth_required", False)),
            network_vector=str(data.get("network_vector", "NETWORK")),
            payload_constraints=str(data.get("payload_constraints", "")),
            confidence=float(data.get("confidence", 0.0)),
            narrative_claim=str(data.get("narrative_claim", "unknown")),
        )

    def _call_live(self, cve_id: str, cve_text: str) -> dict:
        # The key is only ever sent to the configured Nebius endpoint, never logged.
        resp = requests.post(
            f"{self.base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}"},
            json={
                "model": self.model,
                "messages": [
                    {"role": "system", "content": EXTRACTION_SYSTEM_PROMPT},
                    {"role": "user", "content": f"CVE {cve_id}: {cve_text}"},
                ],
                "temperature": 0,
                "response_format": {"type": "json_object"},
            },
            timeout=30,
        )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]
        return json.loads(content)
