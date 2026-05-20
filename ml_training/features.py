"""
Shared feature extraction for WAF ML model.

Both the training pipeline and the runtime sidecar import from here
so that train/serve feature parity is enforced by construction.
"""

import math
import re
from typing import List


FEATURE_NAMES: List[str] = [
    "uri_len", "body_len", "header_len", "full_len", "entropy",
    "num_special_chars", "num_quotes", "num_slashes", "pct_encoded",
    "sql_keywords", "xss_patterns", "path_traversal", "command_inj",
    "has_ojs_structure", "ojs_param_abuse",
    "is_risky_method", "is_post",
    "query_params_count", "max_param_length", "query_entropy",
    "missing_user_agent", "missing_host_header", "user_agent_length",
    "body_non_ascii_ratio", "req_rate",
]

NUM_FEATURES = len(FEATURE_NAMES)  # 25


def calculate_entropy(data_string: str) -> float:
    """Shannon entropy of a string (bits per character, base-2)."""
    if not data_string:
        return 0.0
    entropy = 0.0
    for x in range(256):
        p_x = float(data_string.count(chr(x))) / len(data_string)
        if p_x > 0:
            entropy += -p_x * math.log(p_x, 2)
    return entropy


def extract_features(
    method: str,
    uri: str,
    query_string: str,
    body: str = "",
    headers: str = "",
    stateful_req_rate: float = 0.0,
) -> List[float]:
    """
    Extract 25 numerical features from raw HTTP components.

    The feature vector and ordering must stay in sync with FEATURE_NAMES.
    Never reorder or remove features without retraining the model.
    """
    full_payload = uri + " " + body + " " + headers

    uri_len = len(uri)
    body_len = len(body)
    header_len = len(headers)
    full_len = len(full_payload)

    entropy = calculate_entropy(full_payload)

    num_special_chars = len(re.findall(r"[^a-zA-Z0-9\s]", full_payload))
    num_quotes = full_payload.count("'") + full_payload.count('"')
    num_slashes = uri.count("/") + full_payload.count("\\")
    pct_encoded = full_payload.count("%") / full_len if full_len > 0 else 0.0

    sql_keywords = len(re.findall(
        r"(?i)\b(SELECT|UNION|INSERT|UPDATE|DELETE|DROP|AND|OR|WHERE)\b",
        full_payload,
    ))
    xss_patterns = len(re.findall(
        r"(?i)(<script>|javascript:|onerror=|onload=|eval\()",
        full_payload,
    ))
    path_traversal = len(re.findall(r"(\.\./|\.\.\\)", full_payload))
    command_inj = len(re.findall(r"(;|\&\&|\|\||`|\$\()", full_payload))

    has_ojs_structure = 1 if "index.php" in uri else 0
    ojs_param_abuse = 1 if ("query=" in uri and num_special_chars > 5) else 0

    method_upper = method.upper() if method else "GET"
    is_risky_method = 1 if method_upper in {"TRACE", "TRACK", "CONNECT", "PROPFIND", "PUT"} else 0
    is_post = 1 if method_upper == "POST" else 0

    query_params_count = query_string.count("&") + 1 if query_string else 0
    if query_string and "=" in query_string:
        parts = query_string.split("&")
        lengths = [len(p.split("=", 1)[1]) if "=" in p else 0 for p in parts]
        max_param_length = max(lengths) if lengths else 0
    else:
        max_param_length = 0
    query_entropy = calculate_entropy(query_string)

    headers_lower = headers.lower() if headers else ""
    missing_user_agent = 1 if "user-agent:" not in headers_lower else 0
    missing_host_header = 1 if "host:" not in headers_lower else 0

    user_agent_match = re.search(r"(?i)user-agent:\s*([^\r\n]*)", headers)
    user_agent_length = len(user_agent_match.group(1).strip()) if user_agent_match else 0

    body_non_ascii = len(re.findall(r"[^\x00-\x7F]", body)) if body else 0
    body_non_ascii_ratio = body_non_ascii / len(body) if len(body) > 0 else 0.0

    req_rate = float(stateful_req_rate)

    return [
        uri_len, body_len, header_len, full_len, entropy,
        num_special_chars, num_quotes, num_slashes, pct_encoded,
        sql_keywords, xss_patterns, path_traversal, command_inj,
        has_ojs_structure, ojs_param_abuse,
        is_risky_method, is_post,
        query_params_count, max_param_length, query_entropy,
        missing_user_agent, missing_host_header, user_agent_length,
        body_non_ascii_ratio, req_rate,
    ]
