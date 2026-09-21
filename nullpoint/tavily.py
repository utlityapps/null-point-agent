"""Tavily integration — real-time CVE exploitability / weaponization metadata.

Used to enrich (never to decide): whether a CVE is listed in CISA KEV,
whether weaponized exploits are observed, and EPSS-style context feed the
action-queue ranking. Reachability is decided solely by the deterministic
solver; Tavily evidence only prioritizes *reachable* findings.

Offline rule: without ``TAVILY_API_KEY`` the client serves recorded fixture
responses and never touches the network.
"""
from __future__ import annotations

import json
import os

import requests

TAVILY_SEARCH_URL = "https://api.tavily.com/search"


class OfflineError(RuntimeError):
    """Raised when offline mode has no recorded response for a CVE."""


class TavilyClient:
    def __init__(self, api_key: str | None = None, stub_responses: dict | None = None,
                 offline: bool | None = None):
        self.api_key = api_key if api_key is not None else os.environ.get("TAVILY_API_KEY")
        self.stub_responses = stub_responses or {}
        self.offline = (not self.api_key) if offline is None else offline

    @classmethod
    def from_fixtures(cls, fixtures_dir: str, **kwargs) -> "TavilyClient":
        path = os.path.join(fixtures_dir, "recorded", "tavily_responses.json")
        with open(path) as fh:
            stubs = {k: v for k, v in json.load(fh).items() if not k.startswith("_")}
        return cls(stub_responses=stubs, **kwargs)

    def get_exploitability(self, cve_id: str) -> dict:
        if self.offline:
            if cve_id not in self.stub_responses:
                raise OfflineError(f"no recorded Tavily response for {cve_id} (offline mode)")
            return dict(self.stub_responses[cve_id])
        return self._call_live(cve_id)

    def _call_live(self, cve_id: str) -> dict:
        resp = requests.post(
            TAVILY_SEARCH_URL,
            headers={"Authorization": f"Bearer {self.api_key}"},
            json={
                "query": f"{cve_id} exploit weaponized CISA KEV",
                "search_depth": "advanced",
                "max_results": 5,
            },
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        text = " ".join(r.get("content", "") for r in data.get("results", [])).lower()
        return {
            "cve_id": cve_id,
            "kev_listed": "cisa" in text and "known exploited" in text,
            "weaponized": any(w in text for w in ("exploit in the wild", "actively exploited", "weaponized")),
            "epss": None,  # Tavily search does not return EPSS; left for a dedicated feed
            "summary": (data.get("results", [{}])[0].get("content", "")[:300]
                        if data.get("results") else ""),
            "references": [r.get("url") for r in data.get("results", []) if r.get("url")],
        }
