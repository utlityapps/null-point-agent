"""Tamper-evident dismissal log: append-only hash chain + verification."""
import json

from nullpoint.dismissal_log import DismissalLog


def test_chain_verifies(tmp_path):
    log = DismissalLog(str(tmp_path / "d.jsonl"))
    log.append({"finding_id": "F-001", "decision": "dismissed", "reason": "no path"})
    log.append({"finding_id": "F-002", "decision": "dismissed", "reason": "no path"})
    ok, msg = log.verify()
    assert ok, msg
    assert "2 entries" in msg


def test_tampering_is_detected(tmp_path):
    path = str(tmp_path / "d.jsonl")
    log = DismissalLog(path)
    log.append({"finding_id": "F-001", "decision": "dismissed", "reason": "no path"})
    log.append({"finding_id": "F-002", "decision": "dismissed", "reason": "no path"})
    # Attacker rewrites history: flip a dismissal into an escalation.
    lines = open(path).read().strip().split("\n")
    entry = json.loads(lines[0])
    entry["decision"] = "actionable"
    lines[0] = json.dumps(entry, sort_keys=True)
    open(path, "w").write("\n".join(lines) + "\n")
    ok, msg = log.verify()
    assert ok is False
    assert "tampered" in msg


def test_deletion_is_detected(tmp_path):
    path = str(tmp_path / "d.jsonl")
    log = DismissalLog(path)
    log.append({"finding_id": "F-001", "decision": "dismissed", "reason": "no path"})
    log.append({"finding_id": "F-002", "decision": "dismissed", "reason": "no path"})
    lines = open(path).read().strip().split("\n")
    open(path, "w").write(lines[0] + "\n")  # drop the second entry
    ok, msg = log.verify()
    assert ok is False  # sequence break


def test_chain_resumes_across_runs(tmp_path):
    path = str(tmp_path / "d.jsonl")
    DismissalLog(path).append({"finding_id": "F-001", "decision": "dismissed", "reason": "x"})
    second = DismissalLog(path)  # new process, same file
    second.append({"finding_id": "F-002", "decision": "dismissed", "reason": "y"})
    ok, msg = second.verify()
    assert ok, msg
    assert [e["seq"] for e in second.entries()] == [1, 2]
