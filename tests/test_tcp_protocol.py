"""
Integration tests for the sidecar TCP protocol.

Starts a real SidecarWAF TCP server on an ephemeral port, sends JSONL
messages, and asserts PASS/BLOCK/HEALTH_RESPONSE behavior end-to-end.
"""

import json
import socket
import sys
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_model(attack_proba: float):
    model = MagicMock()
    model.predict.return_value = np.array([1 if attack_proba >= 0.5 else 0])
    model.predict_proba.return_value = np.array([[1.0 - attack_proba, attack_proba]])
    model.n_estimators = 100
    model.max_depth = 10
    return model


def _start_server(attack_proba: float = 0.0, monitor_mode: bool = False):
    """Start a SidecarWAF on an ephemeral port; return (waf, port)."""
    import core.sidecar_agent as sa

    with (
        patch.object(sa.SidecarWAF, "load_model"),
        patch.object(sa.SidecarWAF, "setup_socket"),
    ):
        waf = sa.SidecarWAF(host="127.0.0.1", port=0, monitor_mode=monitor_mode)

    waf.model = _mock_model(attack_proba)
    waf.dataset = MagicMock()
    sa.BLOCK_THRESHOLD = 0.70

    waf.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    waf.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    waf.server.bind(("127.0.0.1", 0))
    waf.server.listen(8)
    waf.server.settimeout(2.0)
    port = waf.server.getsockname()[1]

    def _serve():
        try:
            while True:
                try:
                    conn, _ = waf.server.accept()
                    t = threading.Thread(
                        target=waf._handle_connection, args=(conn, None), daemon=True
                    )
                    t.start()
                except socket.timeout:
                    break
        except OSError:
            pass

    threading.Thread(target=_serve, daemon=True).start()
    return waf, port


def _send_jsonl(port: int, msg: dict) -> dict:
    with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
        s.sendall((json.dumps(msg) + "\n").encode("utf-8"))
        data = b""
        while b"\n" not in data:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    return json.loads(data.split(b"\n")[0])


def _request_check(**overrides) -> dict:
    base = {
        "type": "REQUEST_CHECK",
        "request_id": "tcp-test-001",
        "method": "GET",
        "uri": "/index.php/testjournal/article/view/1",
        "query_string": "",
        "body": "",
        "headers": {"Host": "ojs.local", "User-Agent": "pytest"},
        "source_ip": "127.0.0.1",
        "source_port": 55000,
        "server_ip": "127.0.0.1",
        "server_port": 80,
        "timestamp": "2026-05-20T00:00:00Z",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestTCPPass:
    def test_normal_request_returns_pass(self):
        _, port = _start_server(attack_proba=0.05)
        reply = _send_jsonl(port, _request_check())
        assert reply["type"] == "WAF_DECISION"
        assert reply["decision"] == "PASS"

    def test_response_contains_required_fields(self):
        _, port = _start_server(attack_proba=0.05)
        reply = _send_jsonl(port, _request_check())
        required = {"type", "request_id", "decision", "threat_score", "confidence", "attack_type", "model_version"}
        assert required.issubset(set(reply.keys()))

    def test_request_id_is_echoed(self):
        _, port = _start_server(attack_proba=0.05)
        reply = _send_jsonl(port, _request_check(request_id="echo-test-xyz"))
        assert reply["request_id"] == "echo-test-xyz"


class TestTCPBlock:
    def test_high_threat_returns_block(self):
        _, port = _start_server(attack_proba=0.95)
        reply = _send_jsonl(port, _request_check(
            uri="/index.php/search?query=1' UNION SELECT * FROM users--",
            query_string="query=1' UNION SELECT * FROM users--",
        ))
        assert reply["decision"] == "BLOCK"

    def test_monitor_mode_overrides_block_to_pass(self):
        _, port = _start_server(attack_proba=0.95, monitor_mode=True)
        reply = _send_jsonl(port, _request_check(
            uri="/index.php/search?query=<script>alert(1)</script>",
        ))
        assert reply["decision"] == "PASS"


class TestTCPHealthCheck:
    def test_health_check_returns_ok(self):
        _, port = _start_server()
        reply = _send_jsonl(port, {"type": "HEALTH_CHECK"})
        assert reply["type"] == "HEALTH_RESPONSE"
        assert reply["status"] == "ok"

    def test_health_check_contains_model_version(self):
        _, port = _start_server()
        reply = _send_jsonl(port, {"type": "HEALTH_CHECK"})
        assert "model_version" in reply
        assert reply["model_version"] != ""

    def test_health_check_tracks_request_count(self):
        waf, port = _start_server(attack_proba=0.05)
        _send_jsonl(port, _request_check())
        _send_jsonl(port, _request_check())
        reply = _send_jsonl(port, {"type": "HEALTH_CHECK"})
        assert reply["total_requests"] == 2


class TestTCPMalformed:
    def test_unknown_message_type_does_not_crash(self):
        """Server must stay alive after receiving an unknown message type."""
        _, port = _start_server(attack_proba=0.05)
        with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
            s.sendall(b'{"type":"UNKNOWN_TYPE"}\n')
            s.settimeout(0.5)
            try:
                s.recv(1024)
            except socket.timeout:
                pass
        reply = _send_jsonl(port, _request_check())
        assert reply["decision"] in ("PASS", "BLOCK")
