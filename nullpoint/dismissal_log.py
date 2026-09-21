"""Tamper-evident dismissal log.

Every dismissed alert is appended to a JSONL log with a SHA-256 hash chain:
each entry commits to the previous entry's hash, so any edit, deletion, or
reordering of history is detectable via :meth:`DismissalLog.verify`.

User-facing copy calls this a "tamper-evident dismissal log" — never
"cryptographic proof". It proves *we logged the decision*, not that the
decision was correct; correctness comes from the deterministic solver.

Honest limitation: like any hash chain, this detects modification,
reordering, and deletion of non-tail entries, but NOT truncation of the
tail (dropping the newest entries leaves a valid shorter chain). In
production the latest hash should be anchored externally (e.g., published
alongside each scan report); Phase 2 work.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os

GENESIS_HASH = "0" * 64


def _entry_hash(prev_hash: str, payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()


class DismissalLog:
    def __init__(self, path: str):
        self.path = path
        self._seq = 0
        self._last_hash = GENESIS_HASH
        if os.path.exists(path):
            # Resume an existing chain instead of forking it.
            with open(path) as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    entry = json.loads(line)
                    self._seq = max(self._seq, int(entry.get("seq", 0)))
                    self._last_hash = entry["hash"]

    def append(self, entry: dict) -> dict:
        self._seq += 1
        payload = {
            "seq": self._seq,
            "ts": dt.datetime.now(dt.timezone.utc).isoformat(),
            **entry,
        }
        payload["prev_hash"] = self._last_hash
        payload["hash"] = _entry_hash(self._last_hash, {k: v for k, v in payload.items()
                                                        if k not in ("hash",)})
        self._last_hash = payload["hash"]
        with open(self.path, "a") as fh:
            fh.write(json.dumps(payload, sort_keys=True) + "\n")
        return payload

    def entries(self) -> list[dict]:
        if not os.path.exists(self.path):
            return []
        with open(self.path) as fh:
            return [json.loads(line) for line in fh if line.strip()]

    def verify(self) -> tuple[bool, str]:
        """Recompute the chain. Returns (ok, message)."""
        prev = GENESIS_HASH
        expected_seq = 0
        for entry in self.entries():
            expected_seq += 1
            if int(entry.get("seq", -1)) != expected_seq:
                return False, f"sequence break at entry {entry.get('seq')}"
            if entry.get("prev_hash") != prev:
                return False, f"prev_hash mismatch at seq {entry.get('seq')}"
            # append() hashed sha256(prev_hash + canonical({seq, ts, fields, prev_hash}))
            inner = {k: v for k, v in entry.items() if k != "hash"}
            if _entry_hash(prev, inner) != entry["hash"]:
                return False, f"hash mismatch at seq {entry.get('seq')}: log was tampered with"
            prev = entry["hash"]
        return True, f"chain valid: {expected_seq} entries"
