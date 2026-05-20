"""
Tests for ml_training/features.py

Cover:
- Output shape and type
- Determinism (same input → same output)
- Edge cases: empty strings, None-like values, unusual methods
- Known signal hits (SQL, XSS, path traversal, command injection)
- OJS-specific features
- Entropy sanity
"""

import math
import sys
from pathlib import Path

import pytest

PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR))

from ml_training.features import (
    NUM_FEATURES,
    calculate_entropy,
    extract_features,
    FEATURE_NAMES,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def feats(**kwargs) -> list:
    defaults = dict(method="GET", uri="/", query_string="", body="", headers="", stateful_req_rate=0.0)
    defaults.update(kwargs)
    return extract_features(**defaults)


# ---------------------------------------------------------------------------
# Shape / type
# ---------------------------------------------------------------------------

class TestOutputContract:
    def test_returns_list_of_floats_or_ints(self):
        result = feats()
        assert isinstance(result, list)
        assert all(isinstance(v, (int, float)) for v in result)

    def test_length_equals_num_features(self):
        assert len(feats()) == NUM_FEATURES

    def test_num_features_matches_feature_names(self):
        assert NUM_FEATURES == len(FEATURE_NAMES) == 25

    def test_no_nan_or_inf(self):
        result = feats(uri="/index.php/search?query=test", query_string="query=test")
        for v in result:
            assert not math.isnan(v), f"NaN in feature vector"
            assert not math.isinf(v), f"Inf in feature vector"


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------

class TestDeterminism:
    def test_same_input_same_output(self):
        kwargs = dict(
            method="POST",
            uri="/index.php/testjournal/search?query=test",
            query_string="query=test",
            body="username=admin&password=secret",
            headers="Host: example.com\r\nUser-Agent: Mozilla/5.0",
            stateful_req_rate=5.0,
        )
        assert extract_features(**kwargs) == extract_features(**kwargs)

    def test_different_inputs_differ(self):
        a = feats(uri="/normal")
        b = feats(uri="/index.php/search?query=' OR '1'='1")
        assert a != b


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_all(self):
        result = feats(method="", uri="", query_string="", body="", headers="")
        assert len(result) == NUM_FEATURES
        assert result[0] == 0  # uri_len

    def test_very_long_uri(self):
        long_uri = "/index.php?" + "a" * 10000
        result = feats(uri=long_uri, query_string="a" * 10000)
        assert result[0] == len(long_uri)

    def test_req_rate_propagated(self):
        r0 = feats(stateful_req_rate=0.0)
        r100 = feats(stateful_req_rate=100.0)
        assert r0[-1] == 0.0
        assert r100[-1] == 100.0

    def test_risky_methods(self):
        for method in ("TRACE", "TRACK", "CONNECT", "PROPFIND", "PUT"):
            result = feats(method=method)
            is_risky_idx = FEATURE_NAMES.index("is_risky_method")
            assert result[is_risky_idx] == 1, f"Expected risky=1 for method={method}"

    def test_safe_methods_not_risky(self):
        is_risky_idx = FEATURE_NAMES.index("is_risky_method")
        for method in ("GET", "POST", "HEAD", "DELETE"):
            result = feats(method=method)
            assert result[is_risky_idx] == 0

    def test_post_flag(self):
        is_post_idx = FEATURE_NAMES.index("is_post")
        assert feats(method="POST")[is_post_idx] == 1
        assert feats(method="GET")[is_post_idx] == 0

    def test_pct_encoded_ratio(self):
        uri = "/%61%62%63"  # 3 percent signs
        result = feats(uri=uri)
        pct_idx = FEATURE_NAMES.index("pct_encoded")
        assert result[pct_idx] > 0

    def test_body_non_ascii_ratio(self):
        body = "café"  # 'é' is non-ASCII
        result = feats(body=body)
        ratio_idx = FEATURE_NAMES.index("body_non_ascii_ratio")
        assert result[ratio_idx] > 0


# ---------------------------------------------------------------------------
# Known attack signals
# ---------------------------------------------------------------------------

class TestAttackSignals:
    def test_sql_injection_keywords(self):
        sql_idx = FEATURE_NAMES.index("sql_keywords")
        result = feats(uri="/search?query=1' UNION SELECT * FROM users--")
        assert result[sql_idx] >= 2  # UNION, SELECT

    def test_xss_pattern(self):
        xss_idx = FEATURE_NAMES.index("xss_patterns")
        result = feats(uri="/search?q=<script>alert(1)</script>")
        assert result[xss_idx] >= 1

    def test_path_traversal(self):
        pt_idx = FEATURE_NAMES.index("path_traversal")
        result = feats(uri="/download/../../../etc/passwd")
        assert result[pt_idx] >= 3

    def test_command_injection(self):
        ci_idx = FEATURE_NAMES.index("command_inj")
        result = feats(uri="/search?q=test;ls")
        assert result[ci_idx] >= 1

    def test_clean_request_no_attack_features(self):
        result = feats(
            method="GET",
            uri="/index.php/testjournal/article/view/42",
            query_string="",
            headers="Host: ojs.local\r\nUser-Agent: Mozilla/5.0",
        )
        sql_idx = FEATURE_NAMES.index("sql_keywords")
        xss_idx = FEATURE_NAMES.index("xss_patterns")
        pt_idx = FEATURE_NAMES.index("path_traversal")
        ci_idx = FEATURE_NAMES.index("command_inj")
        assert result[sql_idx] == 0
        assert result[xss_idx] == 0
        assert result[pt_idx] == 0
        assert result[ci_idx] == 0


# ---------------------------------------------------------------------------
# OJS-specific features
# ---------------------------------------------------------------------------

class TestOJSFeatures:
    def test_has_ojs_structure(self):
        ojs_idx = FEATURE_NAMES.index("has_ojs_structure")
        assert feats(uri="/index.php/journal/article/view/1")[ojs_idx] == 1
        assert feats(uri="/static/style.css")[ojs_idx] == 0

    def test_ojs_param_abuse_with_special_chars(self):
        abuse_idx = FEATURE_NAMES.index("ojs_param_abuse")
        # many special chars in URI with query= present
        result = feats(uri="/index.php?query='; DROP TABLE users-- UNION SELECT 1,2")
        assert result[abuse_idx] == 1

    def test_ojs_param_abuse_normal(self):
        abuse_idx = FEATURE_NAMES.index("ojs_param_abuse")
        result = feats(uri="/index.php?query=science")
        assert result[abuse_idx] == 0


# ---------------------------------------------------------------------------
# Header features
# ---------------------------------------------------------------------------

class TestHeaderFeatures:
    def test_missing_user_agent(self):
        ua_idx = FEATURE_NAMES.index("missing_user_agent")
        assert feats(headers="Host: example.com")[ua_idx] == 1
        assert feats(headers="Host: example.com\r\nUser-Agent: curl")[ua_idx] == 0

    def test_missing_host_header(self):
        host_idx = FEATURE_NAMES.index("missing_host_header")
        assert feats(headers="User-Agent: curl")[host_idx] == 1
        assert feats(headers="Host: example.com\r\nUser-Agent: curl")[host_idx] == 0

    def test_user_agent_length(self):
        ua_len_idx = FEATURE_NAMES.index("user_agent_length")
        ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        result = feats(headers=f"Host: x\r\nUser-Agent: {ua}")
        assert result[ua_len_idx] == len(ua)


# ---------------------------------------------------------------------------
# Entropy
# ---------------------------------------------------------------------------

class TestEntropy:
    def test_empty_string_zero(self):
        assert calculate_entropy("") == 0.0

    def test_uniform_string_max_entropy(self):
        # A string with all distinct chars has higher entropy than a repeated char
        e_uniform = calculate_entropy("abcdefgh")
        e_repeated = calculate_entropy("aaaaaaaa")
        assert e_uniform > e_repeated

    def test_entropy_non_negative(self):
        for s in ("", "a", "hello world", "\x00\xff", "SELECT * FROM users"):
            assert calculate_entropy(s) >= 0


# ---------------------------------------------------------------------------
# Query features
# ---------------------------------------------------------------------------

class TestQueryFeatures:
    def test_query_params_count_single(self):
        qpc_idx = FEATURE_NAMES.index("query_params_count")
        result = feats(query_string="foo=bar")
        assert result[qpc_idx] == 1

    def test_query_params_count_multiple(self):
        qpc_idx = FEATURE_NAMES.index("query_params_count")
        result = feats(query_string="a=1&b=2&c=3")
        assert result[qpc_idx] == 3

    def test_max_param_length(self):
        mpl_idx = FEATURE_NAMES.index("max_param_length")
        result = feats(query_string="a=short&b=" + "x" * 200)
        assert result[mpl_idx] == 200

    def test_empty_query_string(self):
        qpc_idx = FEATURE_NAMES.index("query_params_count")
        assert feats(query_string="")[qpc_idx] == 0
