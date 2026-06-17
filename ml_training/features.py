"""
Feature extractor for the OJS WAF Random Forest model.

Design goals (real-world testing, not template memorization):

- URL-decode payloads (single + double) before pattern matching so that
  attacks delivered as `%27%20OR%201%3D1` are scored equivalently to their
  plaintext form.
- Pattern catalogs reflect what real scanners actually send: sqlmap-style
  tautologies, time-based blind probes, comment-split keywords, SVG/IFrame
  XSS, encoded `..%2F` and double-encoded `%252e%252e/`, `${IFS}` command
  injection, modern bot user-agents.
- Per-component features (method, URI structure, query, decoded payload,
  OJS route, headers, body, request rate) so the model can learn where the
  signal lives instead of treating one concatenated string.
- Pure function: deterministic, no I/O, identical at training and runtime.
"""

from __future__ import annotations

import math
import re
from typing import List, Tuple
from urllib.parse import parse_qsl, unquote, unquote_plus, urlsplit


FEATURE_NAMES: List[str] = [
    # Method
    "method_get",
    "method_post",
    "is_risky_method",
    # URI structure
    "uri_len",
    "path_depth",
    "num_slashes",
    "pct_encoded_ratio",
    "double_pct_encoded",
    "uri_entropy",
    "uri_special_char_ratio",
    # Query
    "query_len",
    "query_entropy",
    "query_param_count",
    "max_param_len",
    # Attack signals (computed on URL-decoded payload)
    "sql_keyword_count",
    "sql_metachar_count",
    "sql_tautology",
    "sql_time_based",
    "xss_pattern_count",
    "path_traversal_count",
    "command_inj_count",
    "encoded_attack_markers",
    # OJS route awareness
    "has_index_php",
    "ojs_page_code",
    "ojs_op_code",
    "has_ojs_ajax",
    # Headers
    "missing_host_header",
    "missing_user_agent",
    "bot_user_agent",
    "user_agent_length",
    # Body / behavior
    "body_len",
    "body_non_ascii_ratio",
    "req_rate",
]

NUM_FEATURES = len(FEATURE_NAMES)  # 33


# ---------------------------------------------------------------------------
# Real-dataset feature subset (XSS + RCE + Normal only)
# ---------------------------------------------------------------------------
#
# The captured OJS dataset contains only two attack families — XSS (payload in
# the POST body of `$$$call$$$` grid routes) and RCE (abuse of the
# `NativeImportExportPlugin` import route). It has NO SQLi, path traversal, or
# command injection, so the detectors for those families carry no signal and
# are dropped from the *model* (the 33-dim extractor itself is unchanged, so
# the regex tests and the synthetic pipeline keep working).
#
# Five IP/User-Agent–derived features are also dropped: in the raw capture all
# attacks originate from a single IP and User-Agent, so keeping them would let
# the model "cheat" by memorising the attacker's identity instead of learning
# the payload (metadata leakage). Dropping them is equivalent to — and simpler
# than — neutralising those columns, and it needs no merge step.
#
# `extract_features` still returns the full 33-dim vector; training and the
# sidecar select these columns via `selected_feature_indices`. The model bundle
# stores this list as `feature_names`, and the sidecar rebuilds the same
# projection at load time, so parity is verified end-to-end.
REALDATA_FEATURE_NAMES: List[str] = [
    # Method
    "method_get",
    "method_post",
    "is_risky_method",
    # URI structure
    "uri_len",
    "path_depth",
    "num_slashes",
    "pct_encoded_ratio",
    "double_pct_encoded",
    "uri_entropy",
    "uri_special_char_ratio",
    # Query
    "query_len",
    "query_entropy",
    "query_param_count",
    "max_param_len",
    # Attack signals present in the data (XSS in body / encoded markers)
    "xss_pattern_count",
    "encoded_attack_markers",
    # OJS route awareness (carries the RCE import-route + $$$call$$$ signal)
    "has_index_php",
    "ojs_page_code",
    "ojs_op_code",
    "has_ojs_ajax",
    # Body / behavior
    "body_len",
    "body_non_ascii_ratio",
]

# Features intentionally removed from the real-data model, grouped by reason.
DROPPED_FEATURE_NAMES: List[str] = [
    # Attack families absent from the dataset
    "sql_keyword_count",
    "sql_metachar_count",
    "sql_tautology",
    "sql_time_based",
    "path_traversal_count",
    "command_inj_count",
    # IP / User-Agent leakage (single attacker IP+UA in the raw capture)
    "missing_host_header",
    "missing_user_agent",
    "bot_user_agent",
    "user_agent_length",
    "req_rate",
]

NUM_REALDATA_FEATURES = len(REALDATA_FEATURE_NAMES)  # 22


def selected_feature_indices(names: List[str]) -> List[int]:
    """Map a list of feature names to their column indices in the full vector.

    Raises ``KeyError`` if any requested name is not produced by
    ``extract_features`` — this is the runtime parity guard the sidecar relies
    on when projecting the 33-dim vector down to a model's training subset.
    """
    index_of = {name: i for i, name in enumerate(FEATURE_NAMES)}
    missing = [n for n in names if n not in index_of]
    if missing:
        raise KeyError(f"Unknown feature names: {missing}")
    return [index_of[n] for n in names]


# ---------------------------------------------------------------------------
# OJS route vocabulary (kept small; an "unknown" code is reserved for OOV)
# ---------------------------------------------------------------------------

_OJS_PAGE_CODES = {
    "": 0,
    "index": 1,
    "article": 2,
    "issue": 3,
    "search": 4,
    "user": 5,
    "login": 6,
    "submission": 7,
    "submissions": 7,
    "api": 8,
    "manager": 9,
    "editor": 10,
    "reviewer": 11,
    "about": 12,
    "announcement": 13,
    "rt": 14,
    "oai": 15,
    "files": 16,
    "dashboard": 17,
    "$$$call$$$": 18,
}
_OJS_OP_CODES = {
    "": 0,
    "index": 1,
    "view": 2,
    "download": 3,
    "search": 4,
    "register": 5,
    "signIn": 6,
    "signOut": 7,
    "profile": 8,
    "save": 9,
    "upload": 10,
    "delete": 11,
    "edit": 12,
    "current": 13,
    "archive": 14,
    "editorialTeam": 15,
}
_OJS_UNKNOWN_CODE = 99


# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

# SQL keyword catalog covering classic + time-based + error-based families.
_SQL_KEYWORDS = re.compile(
    r"(?i)\b("
    r"SELECT|UNION(\s+ALL)?|INSERT|UPDATE|DELETE|DROP|TRUNCATE|EXEC(UTE)?|DECLARE"
    r"|FROM|WHERE|HAVING|GROUP\s+BY|ORDER\s+BY|LIMIT|OFFSET|JOIN"
    r"|INTO\s+OUTFILE|LOAD_FILE|INFORMATION_SCHEMA"
    r"|SLEEP|BENCHMARK|WAITFOR\s+DELAY|PG_SLEEP|DBMS_PIPE\.RECEIVE_MESSAGE"
    r"|XP_CMDSHELL|EXTRACTVALUE|UPDATEXML"
    r"|@@VERSION|VERSION\(\)|DATABASE\(\)|USER\(\)"
    r")\b"
)

# Metacharacters / comment markers that almost always indicate injection
# attempts when they cluster.
_SQL_METACHARS = re.compile(r"(--|#|/\*|\*/|;|\bOR\s+|\bAND\s+)")

# Boolean tautology detector — handles spaced, quoted, and bare-int forms.
# Whitespace and word-char runs use possessive quantifiers (`*+`/`++`) so a
# padded payload with a long space run cannot cause catastrophic backtracking
# (ReDoS). Match semantics for real tautologies are unchanged because the
# delimiters (=, quotes, OR/AND) are disjoint from the possessive classes.
_SQL_TAUTOLOGY = re.compile(
    r"(?i)("
    r"['\"`]?\s*+\)?\s*+(OR|AND)\s++[\"'`]?[\w%]++[\"'`]?\s*+=\s*+[\"'`]?[\w%]++[\"'`]?"
    r"|\b(OR|AND)\s+TRUE\b"
    r"|\b(OR|AND)\s+\d+\s*(>|<|>=|<=|!=|<>)\s*\d+"
    r")"
)

# Time-based blind probes — strong signal when present at all.
_SQL_TIME_BASED = re.compile(
    r"(?i)(SLEEP\s*\(|BENCHMARK\s*\(|WAITFOR\s+DELAY|PG_SLEEP\s*\(|DBMS_PIPE\.RECEIVE_MESSAGE)"
)

# XSS signal catalog — script/iframe/svg, JS sinks, modern event handlers.
_XSS_PATTERNS = re.compile(
    r"(?i)("
    r"<\s*script\b|<\s*/\s*script|javascript\s*:|vbscript\s*:|data\s*:\s*text/html"
    r"|on(error|load|click|focus|mouseover|mouseout|submit|blur|change|key\w+|toggle|wheel|drag\w*|drop|input)\s*="
    r"|<\s*svg\b|<\s*iframe\b|<\s*embed\b|<\s*object\b|<\s*img\b[^>]*on\w+\s*=|<\s*body\b[^>]*on\w+\s*="
    r"|srcdoc\s*=|alert\s*\(|prompt\s*\(|confirm\s*\(|eval\s*\("
    r"|document\.cookie|window\.location|String\.fromCharCode"
    r"|<\s*meta[^>]+http-equiv\s*=\s*[\"']?refresh"
    r")"
)

# Path traversal — raw and percent-encoded forms (`..%2f`, `%2e%2e/`,
# `....//`), absolute Linux/Windows paths.
_PATH_TRAVERSAL = re.compile(
    r"("
    r"\.\./|\.\.\\|"  # plaintext
    r"\.\.%2[Ff]|%2[Ee]%2[Ee]%2[Ff]|%2[Ee]%2[Ee]/|"  # single-encoded
    r"%252[Ee]%252[Ee]|"  # double-encoded
    r"\.{4,}/|"  # ....// variant
    r"/etc/passwd|/etc/shadow|/proc/self/|/proc/cmdline|"
    r"\\windows\\system32|/windows/system32|"
    r"boot\.ini|win\.ini|c:\\windows"
    r")",
    re.IGNORECASE,
)

# Command injection — shell metachars, IFS-bypass, common payload binaries.
# NOTE: the separator before a command keyword uses a possessive `\s*+` so a
# long run of whitespace (e.g. a padded request body) cannot trigger
# catastrophic backtracking / ReDoS in the WAF's own feature extractor.
_CMD_INJ = re.compile(
    r"(?i)("
    r"`[^`]*`|\$\([^)]*\)|"  # backticks, $()
    r"(?:[|&;]{1,2}|\s)\s*+(ls|cat|whoami|id|uname|ps|netstat|ifconfig|route|"
    r"curl|wget|nc|bash|sh|zsh|dash|python|perl|ruby|powershell|cmd)\b|"
    r"\bnc\s+-[el]|/bin/sh|/bin/bash|"
    r"\$\{IFS[^}]*\}|\$IFS\$|\${PATH}"
    r")"
)

# Encoded attack markers — presence is a soft hint even before decoding.
_ENCODED_MARKERS = re.compile(
    r"(?i)("
    r"%27|%22|%3[Cc]\s*script|%3[Cc]/script|%2[Ee]%2[Ee]|%00|%0[adAD]|"
    r"%3[bB]|%60|%7[cC]|%26%26|%24%28|%252[Ee]"
    r")"
)

# Modern attacker / scanner / library UAs. Real browsers must NOT match.
_BOT_UA = re.compile(
    r"(?i)("
    r"\bnikto\b|\bsqlmap\b|\bnmap\b|\bwpscan\b|\bacunetix\b|\bnetsparker\b|"
    r"\bburp(suite)?\b|\bmasscan\b|\bmetasploit\b|\bhydra\b|\bw3af\b|"
    r"\bnessus\b|\bqualys\b|\bzgrab\b|\blibwww\b|"
    r"python-requests|go-http-client|"
    r"^curl/|^Wget/|httpie|^perl/|"
    r"morfeus|hailstorm|gobuster|dirbuster|ffuf|wfuzz|httrack"
    r")"
)

_NON_URI_SAFE = re.compile(r"[^a-zA-Z0-9/_.\-]")
_NON_ASCII = re.compile(r"[^\x00-\x7F]")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def calculate_entropy(s: str) -> float:
    """Shannon entropy of a string (bits per char, base 2)."""
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    e = 0.0
    for c in counts.values():
        p = c / n
        e -= p * math.log2(p)
    return e


def _safe_unquote(value: str, plus: bool = False) -> str:
    """URL-decode once, then attempt a second pass when double-encoded.

    `plus=True` treats `+` as a space (form-encoded query semantics).
    """
    if not value:
        return ""
    decode = unquote_plus if plus else unquote
    once = decode(value)
    twice = decode(once)
    return twice if twice != once else once


def _parse_ojs_route(path: str) -> Tuple[int, int, int]:
    """
    Return (has_index_php, page_code, op_code) derived from an OJS-style URL.

    OJS canonical layout: /index.php/<journal>/<page>/<operation>/...
    """
    segments = [seg for seg in path.split("/") if seg]
    if not segments or segments[0] != "index.php":
        return 0, 0, 0
    page_code = 0
    op_code = 0
    if len(segments) >= 3:
        page_code = _OJS_PAGE_CODES.get(segments[2], _OJS_UNKNOWN_CODE)
    if len(segments) >= 4:
        op_code = _OJS_OP_CODES.get(segments[3], _OJS_UNKNOWN_CODE)
    return 1, page_code, op_code


def _split_uri(uri: str) -> Tuple[str, str]:
    """Return (path, query_string) using urlsplit when possible."""
    try:
        parts = urlsplit(uri)
        return parts.path, parts.query
    except Exception:
        path, _, qs = uri.partition("?")
        return path, qs


def _parse_query(query_string: str) -> list[Tuple[str, str]]:
    if not query_string:
        return []
    try:
        return parse_qsl(query_string, keep_blank_values=True, strict_parsing=False)
    except Exception:
        out: list[Tuple[str, str]] = []
        for piece in query_string.split("&"):
            if "=" in piece:
                k, v = piece.split("=", 1)
            else:
                k, v = piece, ""
            out.append((k, v))
        return out


# ---------------------------------------------------------------------------
# Public extractor
# ---------------------------------------------------------------------------

def extract_features(
    method: str,
    uri: str,
    query_string: str,
    body: str = "",
    headers: str = "",
    stateful_req_rate: float = 0.0,
) -> List[float]:
    """
    Extract the 32-dim feature vector consumed by the WAF Random Forest.

    Inputs are taken verbatim from the HTTP request (no upstream normalization
    is assumed). Pattern matching is performed on the URL-decoded payload so
    that encoded attacks reach the same regex as their plaintext form.
    """
    method_upper = (method or "GET").upper()
    method_get = 1 if method_upper == "GET" else 0
    method_post = 1 if method_upper == "POST" else 0
    is_risky_method = (
        1 if method_upper in {"TRACE", "TRACK", "CONNECT", "PROPFIND", "PUT", "PATCH"} else 0
    )

    path, qs_from_uri = _split_uri(uri)
    effective_qs = query_string if query_string else qs_from_uri

    uri_len = len(uri)
    path_depth = sum(1 for seg in path.split("/") if seg)
    num_slashes = uri.count("/") + uri.count("\\")

    pct_count = uri.count("%")
    pct_encoded_ratio = pct_count / uri_len if uri_len else 0.0
    double_pct_encoded = 1 if "%25" in uri.lower() else 0

    uri_entropy = calculate_entropy(uri)
    uri_special = len(_NON_URI_SAFE.findall(uri))
    uri_special_char_ratio = uri_special / uri_len if uri_len else 0.0

    query_len = len(effective_qs)
    query_entropy = calculate_entropy(effective_qs)
    params = _parse_query(effective_qs)
    query_param_count = len(params)
    max_param_len = max((len(v) for _, v in params), default=0)

    path_decoded = _safe_unquote(path)
    qs_decoded = _safe_unquote(effective_qs, plus=True)
    body_decoded = _safe_unquote(body, plus=True)
    decoded_payload = " ".join((path_decoded, qs_decoded, body_decoded))

    sql_keyword_count = len(_SQL_KEYWORDS.findall(decoded_payload))
    sql_metachar_count = len(_SQL_METACHARS.findall(decoded_payload))
    sql_tautology = 1 if _SQL_TAUTOLOGY.search(decoded_payload) else 0
    sql_time_based = 1 if _SQL_TIME_BASED.search(decoded_payload) else 0

    xss_pattern_count = len(_XSS_PATTERNS.findall(decoded_payload))
    raw_for_path = uri + " " + body  # keep raw to catch encoded traversal forms
    path_traversal_count = len(_PATH_TRAVERSAL.findall(raw_for_path + " " + decoded_payload))
    command_inj_count = len(_CMD_INJ.findall(decoded_payload))
    encoded_attack_markers = len(_ENCODED_MARKERS.findall(uri + " " + body))

    has_index_php, ojs_page_code, ojs_op_code = _parse_ojs_route(path_decoded)
    has_ojs_ajax = 1 if "$$$call$$$" in path else 0

    headers_lower = headers.lower() if headers else ""
    missing_host_header = 0 if "host:" in headers_lower else 1
    missing_user_agent = 0 if "user-agent:" in headers_lower else 1

    ua_match = re.search(r"(?i)user-agent:\s*([^\r\n]*)", headers or "")
    ua_value = ua_match.group(1).strip() if ua_match else ""
    user_agent_length = len(ua_value)
    bot_user_agent = 1 if ua_value and _BOT_UA.search(ua_value) else 0

    body_len = len(body)
    body_non_ascii_ratio = (
        len(_NON_ASCII.findall(body)) / body_len if body_len else 0.0
    )

    req_rate = float(stateful_req_rate)

    return [
        method_get,
        method_post,
        is_risky_method,
        uri_len,
        path_depth,
        num_slashes,
        pct_encoded_ratio,
        double_pct_encoded,
        uri_entropy,
        uri_special_char_ratio,
        query_len,
        query_entropy,
        query_param_count,
        max_param_len,
        sql_keyword_count,
        sql_metachar_count,
        sql_tautology,
        sql_time_based,
        xss_pattern_count,
        path_traversal_count,
        command_inj_count,
        encoded_attack_markers,
        has_index_php,
        ojs_page_code,
        ojs_op_code,
        has_ojs_ajax,
        missing_host_header,
        missing_user_agent,
        bot_user_agent,
        user_agent_length,
        body_len,
        body_non_ascii_ratio,
        req_rate,
    ]
