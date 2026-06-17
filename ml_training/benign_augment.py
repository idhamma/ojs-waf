"""
Route-matched benign traffic generator (overfitting fix #1).

Problem
-------
In the raw capture, attacks and benign traffic live on *disjoint* routes:
  - XSS  -> POST /index.php/<j>/$$$call$$$/grid/.../update-section   (long ajax route)
  - RCE  -> POST /index.php/<j>/management/importexport/.../Native...  (long admin route)
  - benign -> short public routes (/index.php/<j>, /login, ...)

So URL length / path depth alone separates the classes perfectly, and the model
learns those structural proxies instead of the actual attack payload (see
`docs`/memory: uri_len/path_depth/body_len dominated feature importance, while
xss_pattern_count was nearly ignored; smoke-tests failed 3/7).

Fix
---
Generate *legitimate* requests that hit the **same routes** as the attacks but
carry benign payloads. Once benign and malicious requests share route length and
shape, the only thing left to separate them is the payload content — forcing the
model onto xss_pattern_count / encoded_attack_markers / body content.

Output schema matches what `ml_training.data_loader` consumes:
    label, method, uri, query_string, body_truncated, headers_raw,
    source_ip, timestamp, host, user_agent

Run
---
    python -m ml_training.benign_augment            # writes route_matched_benign.csv
    python -m ml_training.benign_augment --n 1500   # custom total size
"""

from __future__ import annotations

import argparse
import csv
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote_plus

PROJECT_DIR = Path(__file__).resolve().parent.parent
LABELED_DIR = PROJECT_DIR / "ml_training" / "data_train" / "labeled"
OUT_FILE = LABELED_DIR / "route_matched_benign.csv"

JOURNAL = "publicknowledge"
HOST = "ojs.local"
# Realistic non-bot browser UAs (UA features are dropped from the model anyway,
# but we keep them clean so the data is honest).
_UAS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
]
# A pool of ordinary editor/user IPs so route-matched benign traffic does not
# come from a single address.
_IPS = [f"10.34.100.{n}" for n in range(20, 60)]

_TITLES = [
    "Articles", "Reviews", "Editorials", "Book Reviews", "Research Notes",
    "Case Studies", "Commentaries", "Short Communications", "Letters to the Editor",
    "Perspectives", "Original Research", "Systematic Reviews", "Meta Analyses",
    "Clinical Studies", "Technical Reports", "Special Issue", "Conference Papers",
]
_ABBREVS = ["ART", "REV", "EDI", "BR", "RN", "CS", "COM", "SC", "LE", "PER",
            "OR", "SR", "MA", "CLI", "TR", "SI", "CP"]
_COMMENTS = [
    "Please revise section 2 and add references.",
    "The methodology looks solid, minor language edits needed.",
    "Thank you for the submission, we will assign reviewers shortly.",
    "Could you upload the figures in higher resolution?",
    "This paper examines carbon sequestration in coastal wetlands.",
    "Reviewer 1 recommends acceptance with minor revisions.",
    "Please confirm the author affiliations before publication.",
    "The abstract should be shortened to 250 words.",
]


def _headers(ua: str) -> str:
    return f"Host: {HOST}\\r\\nUser-Agent: {ua}\\r\\nAccept: text/html,application/json"


def _row(rng: random.Random, ts: datetime, method: str, uri: str,
         query_string: str, body: str) -> dict:
    ua = rng.choice(_UAS)
    return {
        "label": "normal",
        "method": method,
        "uri": uri,
        "query_string": query_string,
        "body_truncated": body,
        "headers_raw": _headers(ua),
        "source_ip": rng.choice(_IPS),
        "timestamp": ts.isoformat(),
        "host": HOST,
        "user_agent": ua,
    }


def _benign_section_update(rng: random.Random, ts: datetime) -> dict:
    """Legit section-grid update — SAME route as the XSS attacks, plain text title."""
    sid = rng.randint(1, 40)
    t_en = quote_plus(rng.choice(_TITLES))
    t_fr = quote_plus(rng.choice(_TITLES))
    ab_en = rng.choice(_ABBREVS)
    ab_fr = rng.choice(_ABBREVS)
    uri = (f"/index.php/{JOURNAL}/$$$call$$$/grid/settings/sections/"
           f"section-grid/update-section?sectionId={sid}")
    body = (f"csrfToken=abc123def456&sectionId={sid}"
            f"&title%5Ben_US%5D={t_en}&title%5Bfr_CA%5D={t_fr}"
            f"&abbrev%5Ben_US%5D={ab_en}&abbrev%5Bfr_CA%5D={ab_fr}"
            f"&policy%5Ben_US%5D=&path=section{sid}"
            f"&wordCount=500&submitFormButton=Save")
    return _row(rng, ts, "POST", uri, f"sectionId={sid}", body)


def _benign_query_update(rng: random.Random, ts: datetime) -> dict:
    """Legit discussion/query update — SAME $$$call$$$ ajax route, benign comment."""
    q = rng.randint(1, 60)
    sub = rng.randint(1, 80)
    stage = rng.randint(1, 5)
    comment = quote_plus(rng.choice(_COMMENTS))
    uri = (f"/index.php/{JOURNAL}/$$$call$$$/grid/queries/queries-grid/"
           f"update-query?queryId={q}&wasNew=&submissionId={sub}&stageId={stage}")
    qs = f"queryId={q}&wasNew=&submissionId={sub}&stageId={stage}"
    body = (f"csrfToken=abc123def456&users%5B%5D=32&users%5B%5D=5"
            f"&subject={quote_plus(rng.choice(_TITLES))}"
            f"&comment=%3Cp%3E{comment}%3C%2Fp%3E&submitFormButton=Save")
    return _row(rng, ts, "POST", uri, qs, body)


def _benign_grid_fetch(rng: random.Random, ts: datetime) -> dict:
    """Legit GET ajax grid fetches — keeps $$$call$$$ from being an attack proxy."""
    grids = [
        "grid/settings/sections/section-grid/fetch-grid",
        "grid/queries/queries-grid/fetch-grid",
        "grid/users/user-grid/fetch-grid",
        "grid/submissions/unassigned/unassigned-grid/fetch-grid",
        "grid/issues/future-issue-grid/fetch-grid",
    ]
    g = rng.choice(grids)
    sub = rng.randint(1, 80)
    uri = f"/index.php/{JOURNAL}/$$$call$$$/{g}?submissionId={sub}"
    return _row(rng, ts, "GET", uri, f"submissionId={sub}", "")


def _benign_importexport_nav(rng: random.Random, ts: datetime) -> dict:
    """Legit import/export *navigation & export* — SAME long admin route prefix as
    the RCE upload attack, but benign browsing/export (no malicious import upload)."""
    ops = [
        ("GET", "NativeImportExportPlugin", ""),
        ("GET", "NativeImportExportPlugin/index", ""),
        ("GET", "NativeImportExportPlugin/exportSubmissions", ""),
        ("GET", "NativeImportExportPlugin/exportIssues", ""),
        ("GET", "NativeImportExportPlugin/downloadExportFile", ""),
    ]
    method, op, _ = rng.choice(ops)
    tab = rng.choice(["import", "export"])
    uri = f"/index.php/{JOURNAL}/management/importexport/plugin/{op}?tab={tab}"
    return _row(rng, ts, method, uri, f"tab={tab}", "")


# weight -> generator (relative mix of the route-matched benign families)
_GENERATORS = [
    (_benign_section_update, 28),     # mirror XSS section route
    (_benign_query_update, 14),       # mirror $$$call$$$ query route
    (_benign_grid_fetch, 18),         # benign ajax grid traffic
    (_benign_importexport_nav, 40),   # mirror RCE importexport route prefix
]


def generate(n: int, seed: int = 42) -> list[dict]:
    rng = random.Random(seed)
    pool: list = []
    for fn, w in _GENERATORS:
        pool += [fn] * w
    base = datetime(2026, 6, 12, 9, 0, 0, tzinfo=timezone.utc)
    rows: list[dict] = []
    for i in range(n):
        ts = base + timedelta(seconds=rng.randint(0, 6 * 3600))
        rows.append(rng.choice(pool)(rng, ts))
    return rows


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate route-matched benign traffic")
    ap.add_argument("--n", type=int, default=1600, help="number of benign rows")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", type=Path, default=OUT_FILE)
    args = ap.parse_args()

    rows = generate(args.n, args.seed)
    fields = ["label", "method", "uri", "query_string", "body_truncated",
              "headers_raw", "source_ip", "timestamp", "host", "user_agent"]
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

    # quick mix report
    from collections import Counter
    by_route = Counter(
        "section-update" if "update-section" in r["uri"]
        else "query-update" if "update-query" in r["uri"]
        else "grid-fetch" if "fetch-grid" in r["uri"]
        else "importexport" if "importexport" in r["uri"]
        else "other"
        for r in rows
    )
    print(f"[*] Wrote {len(rows)} route-matched benign rows -> {args.out}")
    print(f"    mix: {dict(by_route)}")


if __name__ == "__main__":
    main()
