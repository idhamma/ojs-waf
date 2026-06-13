"""
Reader / aggregator for the WAF's labeled dataset CSVs.

The sidecar writes one CSV per day to ``dataset/labeled/YYYY-MM-DD.csv`` with the
runtime schema (decision, threat_score, attack_type, ...). This module loads the
most recent day(s), caches by file mtime so repeated dashboard polls are cheap,
and exposes summary stats / recent events / a per-minute time series.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

import pandas as pd

PROJECT_DIR = Path(__file__).resolve().parent.parent
LABELED_DIR = PROJECT_DIR / "dataset" / "labeled"

# Columns we surface to the UI (subset of the 36-col runtime schema).
_EVENT_COLS = [
    "timestamp", "method", "uri", "source_ip", "user_agent",
    "decision", "threat_score", "confidence", "attack_type",
    "response_status", "model_version",
]

# (path, mtime) -> DataFrame
_CACHE: Dict[str, tuple[float, pd.DataFrame]] = {}


def _daily_files() -> List[Path]:
    if not LABELED_DIR.is_dir():
        return []
    return sorted(LABELED_DIR.glob("*.csv"))


def _load_file(path: Path) -> pd.DataFrame:
    """Load one CSV, cached on mtime so unchanged files aren't re-parsed."""
    key = str(path)
    mtime = path.stat().st_mtime
    cached = _CACHE.get(key)
    if cached and cached[0] == mtime:
        return cached[1]

    df = pd.read_csv(path, dtype=str, keep_default_na=False, on_bad_lines="skip")
    # Numeric coercions for the few numeric columns we use.
    for col in ("threat_score", "confidence"):
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0)
    df["_ts"] = pd.to_datetime(
        df.get("timestamp", ""), format="mixed", errors="coerce", utc=True
    )
    _CACHE[key] = (mtime, df)
    return df


def load_recent(days: int = 2) -> pd.DataFrame:
    """Concatenate the most recent ``days`` daily files (newest last)."""
    files = _daily_files()[-days:]
    frames = [_load_file(p) for p in files]
    frames = [f for f in frames if not f.empty]
    if not frames:
        return pd.DataFrame(columns=_EVENT_COLS + ["_ts"])
    return pd.concat(frames, ignore_index=True)


# ---------------------------------------------------------------------------
# Aggregations
# ---------------------------------------------------------------------------

def summary(days: int = 2) -> Dict[str, object]:
    df = load_recent(days)
    total = int(len(df))
    if total == 0:
        return {
            "total": 0, "blocked": 0, "passed": 0, "block_rate": 0.0,
            "attack_types": {}, "top_sources": [], "model_version": None,
            "latest_event_ts": None, "days_loaded": 0,
        }

    decision = df.get("decision", pd.Series([], dtype=str)).str.upper()
    blocked = int((decision == "BLOCK").sum())
    passed = int((decision == "PASS").sum())

    # Attack-type breakdown over genuine attacks (non-NONE).
    atk = df.get("attack_type", pd.Series([], dtype=str)).fillna("NONE")
    attack_counts = (
        atk[atk.str.upper() != "NONE"].value_counts().to_dict()
    )

    # Top source IPs among blocked requests.
    blocked_df = df[decision == "BLOCK"]
    top_sources = [
        {"source_ip": ip, "count": int(c)}
        for ip, c in blocked_df.get("source_ip", pd.Series([], dtype=str))
        .replace("", "unknown").value_counts().head(8).items()
    ]

    model_versions = (
        df.get("model_version", pd.Series([], dtype=str))
        .replace("", pd.NA).dropna().unique().tolist()
    )

    latest = df["_ts"].max()
    return {
        "total": total,
        "blocked": blocked,
        "passed": passed,
        "block_rate": round(100.0 * blocked / total, 2) if total else 0.0,
        "attack_types": {k: int(v) for k, v in attack_counts.items()},
        "top_sources": top_sources,
        "model_version": model_versions[-1] if model_versions else None,
        "latest_event_ts": latest.isoformat() if pd.notna(latest) else None,
        "days_loaded": len(_daily_files()[-days:]),
    }


def recent_events(limit: int = 50, only_blocked: bool = False,
                  days: int = 2) -> List[Dict[str, object]]:
    df = load_recent(days)
    if df.empty:
        return []
    df = df.sort_values("_ts")
    if only_blocked:
        df = df[df.get("decision", "").str.upper() == "BLOCK"]
    df = df.tail(limit).iloc[::-1]  # newest first

    events: List[Dict[str, object]] = []
    for _, row in df.iterrows():
        score = row.get("threat_score", 0.0)
        try:
            score = float(score)
        except (TypeError, ValueError):
            score = 0.0
        events.append({
            "timestamp": row.get("timestamp", ""),
            "method": row.get("method", ""),
            "uri": (row.get("uri", "") or "").strip()[:200],
            "source_ip": row.get("source_ip", "") or "unknown",
            "user_agent": (row.get("user_agent", "") or "")[:160],
            "decision": (row.get("decision", "") or "").upper(),
            "threat_score": round(score, 4),
            "attack_type": row.get("attack_type", "NONE") or "NONE",
            "response_status": row.get("response_status", ""),
        })
    return events


def timeseries(minutes: int = 60, days: int = 2) -> Dict[str, object]:
    """Per-minute counts of total vs blocked requests over the last window."""
    df = load_recent(days)
    if df.empty or df["_ts"].notna().sum() == 0:
        return {"buckets": [], "total": [], "blocked": []}

    now = datetime.now(timezone.utc)
    valid = df[df["_ts"].notna()].copy()
    cutoff = now - pd.Timedelta(minutes=minutes)
    valid = valid[valid["_ts"] >= cutoff]
    if valid.empty:
        # Fall back to the most recent window of data we do have.
        latest = df["_ts"].max()
        cutoff = latest - pd.Timedelta(minutes=minutes)
        valid = df[(df["_ts"] >= cutoff) & df["_ts"].notna()].copy()
        now = latest

    valid["_bucket"] = valid["_ts"].dt.floor("min")
    is_block = valid.get("decision", "").str.upper() == "BLOCK"

    buckets, totals, blocks = [], [], []
    start = (now - pd.Timedelta(minutes=minutes - 1)).floor("min") \
        if hasattr(now, "floor") else pd.Timestamp(now).floor("min")
    grouped_total = valid.groupby("_bucket").size()
    grouped_block = valid[is_block].groupby("_bucket").size()
    for i in range(minutes):
        b = (pd.Timestamp(now) - pd.Timedelta(minutes=minutes - 1 - i)).floor("min")
        buckets.append(b.strftime("%H:%M"))
        totals.append(int(grouped_total.get(b, 0)))
        blocks.append(int(grouped_block.get(b, 0)))
    return {"buckets": buckets, "total": totals, "blocked": blocks}


if __name__ == "__main__":
    import json
    print(json.dumps(summary(), indent=2))
    print("--- recent blocked ---")
    print(json.dumps(recent_events(5, only_blocked=True), indent=2))
