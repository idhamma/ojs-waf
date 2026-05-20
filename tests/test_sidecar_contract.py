"""
Tests for the sidecar inference contract.

Tests do NOT start the TCP server. They instantiate SidecarWAF with a mock
model so we can verify:
  - Input → feature extraction → model.predict_proba flow
  - Decision logic (BLOCK_THRESHOLD, monitor mode)
  - WAF_DECISION response schema
  - _classify_attack heuristic labels
  - Privacy helpers (masking, hashing)
"""

import json
import pickle
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR))


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _make_mock_model(attack_proba: float = 0.0):
    """Return a sklearn-like mock model for controlled inference."""
    model = MagicMock()
    p_normal = 1.0 - attack_proba
    model.predict.return_value = np.array([1 if attack_proba >= 0.5 else 0])
    model.predict_proba.return_value = np.array([[p_normal, attack_proba]])
    model.n_estimators = 100
    model.max_depth = 10
    return model


def _make_waf(attack_proba=0.0, monitor_mode=False, threshold=0.70):
    """Build a SidecarWAF instance with a mock model and temp dataset dir."""
    import importlib
    import core.sidecar_agent as sa

    with tempfile.TemporaryDirectory() as tmp:
        # Patch model loading and socket to avoid side effects
        with (
            patch.object(sa.SidecarWAF, "load_model"),
            patch.object(sa.SidecarWAF, "setup_socket"),
        ):
            waf = sa.SidecarWAF(host="127.0.0.1", port=9999, monitor_mode=monitor_mode)
            waf.model = _make_mock_model(attack_proba)
            waf.dataset = MagicMock()  # suppress file I/O
            # Override dataset base dir to temp path
            waf.dataset.base_dir = tmp

    # Patch the module-level BLOCK_THRESHOLD used inside predict()
    sa.BLOCK_THRESHOLD = threshold
    return waf


def _request_msg(**overrides):
    base = {
        "type": "REQUEST_CHECK",
        "request_id": "test-req-001",
        "method": "GET",
        "uri": "/index.php/testjournal/article/view/42",
        "query_string": "",
        "body": "",
        "headers": {"Host": "ojs.local", "User-Agent": "Mozilla/5.0"},
        "source_ip": "10.0.0.1",
        "source_port": 54321,
        "server_ip": "10.0.0.2",
        "server_port": 80,
        "timestamp": "2026-05-17T00:00:00Z",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Decision logic
# ---------------------------------------------------------------------------

class TestDecisionLogic:
    def test_low_threat_score_returns_pass(self):
        import core.sidecar_agent as sa
        waf = _make_waf(attack_proba=0.10)
        conn = MagicMock()
        replies = []
        conn.sendall.side_effect = lambda data: replies.append(json.loads(data.decode().strip()))

        waf.handle_request(_request_msg(), conn)

        assert len(replies) == 1
        assert replies[0]["decision"] == "PASS"

    def test_high_threat_score_returns_block(self):
        import core.sidecar_agent as sa
        waf = _make_waf(attack_proba=0.95, threshold=0.70)
        conn = MagicMock()
        replies = []
        conn.sendall.side_effect = lambda data: replies.append(json.loads(data.decode().strip()))

        waf.handle_request(_request_msg(), conn)

        assert replies[0]["decision"] == "BLOCK"

    def test_monitor_mode_overrides_block_to_pass(self):
        import core.sidecar_agent as sa
        waf = _make_waf(attack_proba=0.95, threshold=0.70, monitor_mode=True)
        conn = MagicMock()
        replies = []
        conn.sendall.side_effect = lambda data: replies.append(json.loads(data.decode().strip()))

        waf.handle_request(_request_msg(), conn)

        # Wire decision is PASS due to monitor mode
        assert replies[0]["decision"] == "PASS"

    def test_threat_score_exactly_at_threshold_blocks(self):
        """Score equal to threshold should be BLOCKed (prediction=1 AND score >= threshold)."""
        import core.sidecar_agent as sa
        waf = _make_waf(attack_proba=0.70, threshold=0.70)
        conn = MagicMock()
        replies = []
        conn.sendall.side_effect = lambda data: replies.append(json.loads(data.decode().strip()))

        waf.handle_request(_request_msg(), conn)

        assert replies[0]["decision"] == "BLOCK"


# ---------------------------------------------------------------------------
# WAF_DECISION response schema
# ---------------------------------------------------------------------------

class TestResponseSchema:
    REQUIRED_KEYS = {"type", "request_id", "decision", "threat_score", "confidence", "attack_type", "model_version"}

    def _get_reply(self, attack_proba=0.5):
        import core.sidecar_agent as sa
        waf = _make_waf(attack_proba=attack_proba)
        conn = MagicMock()
        replies = []
        conn.sendall.side_effect = lambda data: replies.append(json.loads(data.decode().strip()))
        waf.handle_request(_request_msg(), conn)
        return replies[0]

    def test_all_required_keys_present(self):
        reply = self._get_reply()
        assert self.REQUIRED_KEYS.issubset(set(reply.keys()))

    def test_type_is_waf_decision(self):
        assert self._get_reply()["type"] == "WAF_DECISION"

    def test_request_id_echoed(self):
        assert self._get_reply()["request_id"] == "test-req-001"

    def test_threat_score_in_range(self):
        reply = self._get_reply(attack_proba=0.82)
        assert 0.0 <= reply["threat_score"] <= 1.0

    def test_confidence_in_range(self):
        reply = self._get_reply(attack_proba=0.82)
        assert 0.0 <= reply["confidence"] <= 1.0

    def test_decision_is_pass_or_block(self):
        for prob in (0.1, 0.5, 0.9):
            reply = self._get_reply(attack_proba=prob)
            assert reply["decision"] in ("PASS", "BLOCK")


# ---------------------------------------------------------------------------
# Attack classification heuristics
# ---------------------------------------------------------------------------

class TestClassifyAttack:
    def setup_method(self):
        import core.sidecar_agent as sa
        with (
            patch.object(sa.SidecarWAF, "load_model"),
            patch.object(sa.SidecarWAF, "setup_socket"),
        ):
            self.waf = sa.SidecarWAF(host="127.0.0.1", port=9999)
            self.waf.model = _make_mock_model()
            self.waf.dataset = MagicMock()

    def test_sql_injection(self):
        assert self.waf._classify_attack("/search?q=1' UNION SELECT * FROM users", "") == "SQL_INJECTION"

    def test_xss(self):
        assert self.waf._classify_attack("/search?q=<script>alert(1)</script>", "") == "XSS"

    def test_path_traversal(self):
        assert self.waf._classify_attack("/download/../../etc/passwd", "") == "PATH_TRAVERSAL"

    def test_command_injection(self):
        assert self.waf._classify_attack("/search?q=test", "`whoami`") == "COMMAND_INJECTION"

    def test_unknown_attack(self):
        assert self.waf._classify_attack("/random/path", "some random payload") == "UNKNOWN_ATTACK"


# ---------------------------------------------------------------------------
# Privacy helpers
# ---------------------------------------------------------------------------

class TestPrivacyHelpers:
    def test_mask_headers_masks_cookie(self):
        import core.sidecar_agent as sa
        headers = {"Cookie": "session=abc123", "Host": "ojs.local"}
        masked = sa.mask_headers(headers)
        assert masked["Cookie"] == "[MASKED]"
        assert masked["Host"] == "ojs.local"

    def test_mask_headers_masks_authorization(self):
        import core.sidecar_agent as sa
        headers = {"Authorization": "Bearer token123", "Accept": "text/html"}
        masked = sa.mask_headers(headers)
        assert masked["Authorization"] == "[MASKED]"
        assert masked["Accept"] == "text/html"

    def test_mask_sensitive_body_password(self):
        import core.sidecar_agent as sa
        body = "username=admin&password=secret123"
        masked = sa._mask_sensitive_body(body)
        assert "secret123" not in masked
        assert "[MASKED]" in masked

    def test_hash_cookie_is_deterministic(self):
        import core.sidecar_agent as sa
        h1 = sa._hash_cookie("session=abc")
        h2 = sa._hash_cookie("session=abc")
        assert h1 == h2

    def test_hash_cookie_different_values(self):
        import core.sidecar_agent as sa
        assert sa._hash_cookie("session=abc") != sa._hash_cookie("session=xyz")

    def test_extract_auth_type_bearer(self):
        import core.sidecar_agent as sa
        assert sa._extract_auth_type("Bearer eyJhbGciOiJ...") == "Bearer"

    def test_extract_auth_type_empty(self):
        import core.sidecar_agent as sa
        assert sa._extract_auth_type("") == ""


# ---------------------------------------------------------------------------
# Feature extraction integration (sidecar → features.py)
# ---------------------------------------------------------------------------

class TestSidecarFeatureIntegration:
    def test_predict_returns_triple(self):
        import core.sidecar_agent as sa
        waf = _make_waf(attack_proba=0.80)
        prediction, threat_score, attack_type = waf.predict(
            method="GET",
            uri="/index.php/search?query=' OR '1'='1",
            query_string="query=' OR '1'='1",
            body="",
            headers_str="Host: ojs.local\r\nUser-Agent: Nikto",
            source_ip="192.168.1.100",
        )
        assert prediction in (0, 1)
        assert 0.0 <= threat_score <= 1.0
        assert isinstance(attack_type, str)

    def test_predict_consistent_with_model_proba(self):
        import core.sidecar_agent as sa
        waf = _make_waf(attack_proba=0.95, threshold=0.70)
        pred, score, _ = waf.predict("GET", "/test", "", "", "", "10.0.0.1")
        assert score == pytest.approx(0.95, abs=1e-6)
        assert pred == 1
