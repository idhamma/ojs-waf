"""
Tests for ml_training/features.py (real-attack-detection contract).

Cover:
- Output shape, type, determinism
- Edge cases: empty strings, very long URIs, percent-encoding
- Real-world bypasses: URL-encoded SQLi/XSS, double-encoded path traversal,
  case-mixed and comment-split SQL keywords, IFS-bypass command injection
- OJS route parsing (page/op enum encoding)
- Header features incl. bot user-agent detection
- Entropy sanity
"""

import math
import sys
from pathlib import Path

import pytest

PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR))

from ml_training.features import (  # noqa: E402
    FEATURE_NAMES,
    NUM_FEATURES,
    calculate_entropy,
    extract_features,
)


def feats(**kwargs) -> list:
    defaults = dict(method="GET", uri="/", query_string="", body="", headers="", stateful_req_rate=0.0)
    defaults.update(kwargs)
    return extract_features(**defaults)


def fval(vec: list, name: str) -> float:
    return vec[FEATURE_NAMES.index(name)]


# ---------------------------------------------------------------------------
# Output contract
# ---------------------------------------------------------------------------

class TestOutputContract:
    def test_returns_list_of_numbers(self):
        result = feats()
        assert isinstance(result, list)
        assert all(isinstance(v, (int, float)) for v in result)

    def test_length_matches_feature_names(self):
        assert len(feats()) == NUM_FEATURES == len(FEATURE_NAMES)

    def test_no_nan_or_inf(self):
        result = feats(uri="/index.php/search?query=test", query_string="query=test")
        for v in result:
            assert not math.isnan(v)
            assert not math.isinf(v)


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
        assert fval(result, "uri_len") == 0

    def test_very_long_uri(self):
        long_uri = "/index.php?" + "a" * 10000
        result = feats(uri=long_uri, query_string="a" * 10000)
        assert fval(result, "uri_len") == len(long_uri)

    def test_req_rate_propagated(self):
        assert fval(feats(stateful_req_rate=0.0), "req_rate") == 0.0
        assert fval(feats(stateful_req_rate=100.0), "req_rate") == 100.0

    def test_risky_methods(self):
        for method in ("TRACE", "TRACK", "CONNECT", "PROPFIND", "PUT", "PATCH"):
            assert fval(feats(method=method), "is_risky_method") == 1

    def test_safe_methods_not_risky(self):
        for method in ("GET", "POST", "HEAD"):
            assert fval(feats(method=method), "is_risky_method") == 0

    def test_method_flags(self):
        assert fval(feats(method="GET"), "method_get") == 1
        assert fval(feats(method="POST"), "method_post") == 1
        assert fval(feats(method="POST"), "method_get") == 0

    def test_pct_encoded_ratio(self):
        result = feats(uri="/%61%62%63")
        assert fval(result, "pct_encoded_ratio") > 0

    def test_double_pct_encoded_flag(self):
        assert fval(feats(uri="/foo%252e%252e/bar"), "double_pct_encoded") == 1
        assert fval(feats(uri="/foo%2e%2e/bar"), "double_pct_encoded") == 0


# ---------------------------------------------------------------------------
# Real-world attack signal detection
# ---------------------------------------------------------------------------

class TestSQLInjection:
    def test_plain_union_select(self):
        result = feats(
            uri="/search?query=1' UNION SELECT * FROM users--",
            query_string="query=1' UNION SELECT * FROM users--",
        )
        assert fval(result, "sql_keyword_count") >= 3

    def test_url_encoded_tautology(self):
        encoded_qs = "query=%27+OR+%271%27%3D%271"
        result = feats(uri=f"/search?{encoded_qs}", query_string=encoded_qs)
        assert fval(result, "sql_tautology") == 1
        assert fval(result, "encoded_attack_markers") >= 1

    def test_case_mixed(self):
        result = feats(uri="/search?q=' Or '1'='1", query_string="q=' Or '1'='1")
        assert fval(result, "sql_tautology") == 1

    def test_comment_split(self):
        qs = "query=UN/**/ION/**/SELECT+1,2,3"
        result = feats(uri=f"/search?{qs}", query_string=qs)
        assert fval(result, "sql_metachar_count") >= 1

    def test_time_based(self):
        result = feats(uri="/article/view/1' AND SLEEP(5)--")
        assert fval(result, "sql_time_based") == 1


class TestXSS:
    def test_plain_script(self):
        result = feats(uri="/search?q=<script>alert(1)</script>")
        assert fval(result, "xss_pattern_count") >= 1

    def test_url_encoded_svg(self):
        qs = "query=%3Csvg/onload=alert(1)%3E"
        result = feats(uri=f"/search?{qs}", query_string=qs)
        assert fval(result, "xss_pattern_count") >= 1

    def test_event_handler(self):
        result = feats(uri="/x?q=\"><img src=x onerror=alert(1)>")
        assert fval(result, "xss_pattern_count") >= 1


class TestPathTraversal:
    def test_plain(self):
        result = feats(uri="/download/../../../etc/passwd")
        assert fval(result, "path_traversal_count") >= 1

    def test_url_encoded(self):
        result = feats(uri="/download/..%2f..%2f..%2fetc%2fpasswd")
        assert fval(result, "path_traversal_count") >= 1

    def test_double_encoded(self):
        result = feats(uri="/download/%252e%252e%252fetc%252fpasswd")
        assert fval(result, "path_traversal_count") >= 1

    def test_dotdot_quad(self):
        result = feats(uri="/x/....//....//etc/passwd")
        assert fval(result, "path_traversal_count") >= 1


class TestCommandInjection:
    def test_pipe_with_binary(self):
        result = feats(uri="/x?q=test;ls -la")
        assert fval(result, "command_inj_count") >= 1

    def test_backtick(self):
        result = feats(uri="/x?q=`whoami`")
        assert fval(result, "command_inj_count") >= 1

    def test_ifs_bypass(self):
        result = feats(uri="/x?q=cat${IFS}/etc/passwd")
        assert fval(result, "command_inj_count") >= 1


class TestClean:
    def test_benign_request_has_no_attack_signal(self):
        result = feats(
            method="GET",
            uri="/index.php/testjournal/article/view/42",
            query_string="",
            headers="Host: ojs.local\r\nUser-Agent: Mozilla/5.0",
        )
        assert fval(result, "sql_keyword_count") == 0
        assert fval(result, "sql_tautology") == 0
        assert fval(result, "xss_pattern_count") == 0
        assert fval(result, "path_traversal_count") == 0
        assert fval(result, "command_inj_count") == 0

    def test_benign_search_no_attack_signal(self):
        result = feats(
            uri="/index.php/testjournal/search/search?query=machine+learning",
            query_string="query=machine+learning",
        )
        assert fval(result, "sql_tautology") == 0
        assert fval(result, "xss_pattern_count") == 0


# ---------------------------------------------------------------------------
# OJS route parsing
# ---------------------------------------------------------------------------

class TestOJSRoute:
    def test_index_php_detected(self):
        assert fval(feats(uri="/index.php/journal/article/view/1"), "has_index_php") == 1
        assert fval(feats(uri="/static/style.css"), "has_index_php") == 0

    def test_page_code_known(self):
        page = fval(feats(uri="/index.php/journal/article/view/1"), "ojs_page_code")
        assert page > 0 and page != 99

    def test_page_code_unknown(self):
        page = fval(feats(uri="/index.php/journal/blackmagic/view/1"), "ojs_page_code")
        assert page == 99


# ---------------------------------------------------------------------------
# Headers
# ---------------------------------------------------------------------------

class TestHeaderFeatures:
    def test_missing_host(self):
        assert fval(feats(headers="User-Agent: x"), "missing_host_header") == 1
        assert fval(feats(headers="Host: x\r\nUser-Agent: y"), "missing_host_header") == 0

    def test_missing_user_agent(self):
        assert fval(feats(headers="Host: x"), "missing_user_agent") == 1

    def test_user_agent_length(self):
        ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        assert fval(feats(headers=f"Host: x\r\nUser-Agent: {ua}"), "user_agent_length") == len(ua)

    def test_bot_ua_flag_for_scanner(self):
        for ua in ("sqlmap/1.7.10", "Nikto/2.5.0", "python-requests/2.31.0",
                   "curl/7.81.0", "Wget/1.21.3"):
            result = feats(headers=f"Host: x\r\nUser-Agent: {ua}")
            assert fval(result, "bot_user_agent") == 1, f"missed scanner UA: {ua}"

    def test_bot_ua_not_flagged_for_browser(self):
        ua = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36")
        result = feats(headers=f"Host: x\r\nUser-Agent: {ua}")
        assert fval(result, "bot_user_agent") == 0


# ---------------------------------------------------------------------------
# Entropy
# ---------------------------------------------------------------------------

class TestEntropy:
    def test_empty_string_zero(self):
        assert calculate_entropy("") == 0.0

    def test_uniform_string_higher_than_repeated(self):
        assert calculate_entropy("abcdefgh") > calculate_entropy("aaaaaaaa")

    def test_entropy_non_negative(self):
        for s in ("", "a", "hello world", "\x00\xff", "SELECT * FROM users"):
            assert calculate_entropy(s) >= 0


# ---------------------------------------------------------------------------
# Query parsing
# ---------------------------------------------------------------------------

class TestQueryFeatures:
    def test_single_param(self):
        result = feats(query_string="foo=bar")
        assert fval(result, "query_param_count") == 1

    def test_multiple_params(self):
        result = feats(query_string="a=1&b=2&c=3")
        assert fval(result, "query_param_count") == 3

    def test_max_param_len(self):
        result = feats(query_string="a=short&b=" + "x" * 200)
        assert fval(result, "max_param_len") == 200

    def test_empty_query_string(self):
        assert fval(feats(query_string=""), "query_param_count") == 0
