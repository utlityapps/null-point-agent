"""NemotronClient._call_live — validates the product's own live client path.

The H3 evidence ran through the nebius-chat CLI (same prompt, model, and
endpoint); these tests pin the client's own HTTP wiring, response parsing,
and fail-closed delivery cleaning against a local stub server, so the live
path is covered without a real key.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from nullpoint.nemotron import NemotronClient

PAYLOAD = {
    "port": 6379,
    "protocol": "TCP",
    "auth_required": False,
    "network_vector": "NETWORK",
    "payload_constraints": "Crafted payload to TCP 6379.",
    "confidence": 0.9,
    "narrative_claim": "exposed",
    "delivery": "direct",
}


def _server(payload, raw=None):
    """Serve one chat-completions-shaped response, then shut down."""
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = raw if raw is not None else {"choices": [{"message": {"content": json.dumps(payload)}}]}
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_call_live_parses_response():
    srv = _server(PAYLOAD)
    try:
        client = NemotronClient(api_key="test-key",
                                base_url=f"http://127.0.0.1:{srv.server_port}",
                                offline=False)
        pre = client.extract_preconditions("CVE-2026-55501", "advisory text")
    finally:
        srv.shutdown()
    assert pre.port == 6379
    assert pre.protocol == "TCP"
    assert pre.narrative_claim == "exposed"
    assert pre.delivery == "direct"


def test_call_live_rejects_empty_content():
    # Reasoning models can return content=null when the trace eats the
    # token budget: the client must raise, never guess.
    srv = _server(None, raw={"choices": [{"message": {"content": None}}]})
    try:
        client = NemotronClient(api_key="test-key",
                                base_url=f"http://127.0.0.1:{srv.server_port}",
                                offline=False)
        with pytest.raises(RuntimeError, match="empty content"):
            client.extract_preconditions("CVE-X", "advisory text")
    finally:
        srv.shutdown()


def test_call_live_delivery_fails_closed():
    srv = _server(dict(PAYLOAD, delivery="weird-value"))
    try:
        client = NemotronClient(api_key="test-key",
                                base_url=f"http://127.0.0.1:{srv.server_port}",
                                offline=False)
        pre = client.extract_preconditions("CVE-X", "advisory text")
    finally:
        srv.shutdown()
    assert pre.delivery == "unknown"  # unknown routes to human review
