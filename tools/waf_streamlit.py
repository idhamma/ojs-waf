"""
OJS WAF — interactive monitoring dashboard (Streamlit + Plotly).

Visualises the WAF runtime logs written by `core/sidecar_agent.py` to
``dataset/labeled/YYYY-MM-DD.csv`` plus live host health from ``/proc``.

Features
--------
  * KPI cards: total / blocked / passed / block-rate / distinct source IPs
  * Host CPU, memory, and load average
  * Traffic-over-time chart (total vs blocked), per-minute or per-hour
  * Attack-type breakdown, PASS/BLOCK donut, threat-score histogram
  * Top offending source IPs among blocked requests
  * Filterable, searchable recent-events log table

Run
---
    streamlit run tools/waf_streamlit.py
    streamlit run tools/waf_streamlit.py --server.address 0.0.0.0 --server.port 8501

Bind to 127.0.0.1 (default) on a production WAF box and reach it via an SSH
tunnel; expose 0.0.0.0 only on a trusted management network.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# Allow running via `streamlit run tools/waf_streamlit.py` (no package context).
import sys
PROJECT_DIR = Path(__file__).resolve().parent.parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from tools import system_metrics  # noqa: E402

LABELED_DIR = PROJECT_DIR / "dataset" / "labeled"

ATTACK_COLORS = {
    "NONE": "#3b82f6",
    "RCE": "#ef4444",
    "XSS": "#f59e0b",
    "SQL_INJECTION": "#a855f7",
    "PATH_TRAVERSAL": "#14b8a6",
    "COMMAND_INJECTION": "#ec4899",
    "UNKNOWN_ATTACK": "#6b7280",
}

DISPLAY_COLS = [
    "timestamp", "method", "uri", "source_ip", "user_agent",
    "decision", "threat_score", "confidence", "attack_type",
    "response_status", "model_version",
]


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def available_days() -> List[str]:
    if not LABELED_DIR.is_dir():
        return []
    return sorted(p.stem for p in LABELED_DIR.glob("*.csv"))


@st.cache_data(show_spinner=False)
def load_days(days: tuple[str, ...], _mtimes: tuple[float, ...]) -> pd.DataFrame:
    """Load and concatenate the selected daily logs.

    ``_mtimes`` is part of the cache key so edits to a file invalidate the
    cache without us having to disable caching entirely.
    """
    frames = []
    for day in days:
        path = LABELED_DIR / f"{day}.csv"
        if not path.exists():
            continue
        df = pd.read_csv(path, dtype=str, keep_default_na=False, on_bad_lines="skip")
        frames.append(df)
    if not frames:
        return pd.DataFrame(columns=DISPLAY_COLS)

    df = pd.concat(frames, ignore_index=True, sort=False)
    for col in ("threat_score", "confidence"):
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0)
    df["_ts"] = pd.to_datetime(
        df.get("timestamp", ""), format="mixed", errors="coerce", utc=True
    )
    if "decision" in df.columns:
        df["decision"] = df["decision"].str.upper().str.strip()
    if "attack_type" in df.columns:
        df["attack_type"] = df["attack_type"].replace("", "NONE").fillna("NONE")
    return df


def _mtimes_for(days: List[str]) -> tuple[float, ...]:
    out = []
    for day in days:
        p = LABELED_DIR / f"{day}.csv"
        out.append(p.stat().st_mtime if p.exists() else 0.0)
    return tuple(out)


# ---------------------------------------------------------------------------
# UI helpers
# ---------------------------------------------------------------------------

def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def kpi_row(df: pd.DataFrame) -> None:
    total = len(df)
    decision = df.get("decision", pd.Series(dtype=str))
    blocked = int((decision == "BLOCK").sum())
    passed = int((decision == "PASS").sum())
    block_rate = (100.0 * blocked / total) if total else 0.0
    distinct_ips = df.get("source_ip", pd.Series(dtype=str)).replace("", pd.NA).nunique()

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Requests", f"{total:,}")
    c2.metric("Blocked", f"{blocked:,}")
    c3.metric("Passed", f"{passed:,}")
    c4.metric("Block Rate", f"{block_rate:.1f}%")
    c5.metric("Distinct Source IPs", f"{distinct_ips:,}")


def system_row() -> None:
    snap = system_metrics.snapshot()
    mem = snap["memory"]
    load = snap["load_average"]
    net = snap["network"]
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("CPU", f"{snap['cpu_percent']:.0f}%", f"{snap['cpu_count']} cores")
    c2.metric("Memory", f"{mem['percent']:.0f}%",
              f"{human_bytes(mem['used'])} / {human_bytes(mem['total'])}")
    c3.metric("Load (1m)", f"{load[0]:.2f}", f"5m {load[1]:.2f} · 15m {load[2]:.2f}")
    c4.metric("Net rx/tx", f"{human_bytes(net['rx_rate'])}/s",
              f"tx {human_bytes(net['tx_rate'])}/s")


def traffic_chart(df: pd.DataFrame, freq: str) -> None:
    valid = df[df["_ts"].notna()].copy()
    if valid.empty:
        st.info("No timestamped events to plot.")
        return
    valid["_bucket"] = valid["_ts"].dt.floor(freq)
    grp = valid.groupby("_bucket")
    series = pd.DataFrame({
        "total": grp.size(),
        "blocked": grp.apply(
            lambda g: int((g["decision"] == "BLOCK").sum()), include_groups=False
        ),
    }).reset_index()
    series["passed"] = series["total"] - series["blocked"]

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=series["_bucket"], y=series["passed"], name="Passed",
        stackgroup="one", line=dict(width=0.5, color="#3b82f6"),
    ))
    fig.add_trace(go.Scatter(
        x=series["_bucket"], y=series["blocked"], name="Blocked",
        stackgroup="one", line=dict(width=0.5, color="#ef4444"),
    ))
    fig.update_layout(
        height=320, margin=dict(l=10, r=10, t=30, b=10),
        legend=dict(orientation="h", y=1.1), title="Traffic over time",
    )
    st.plotly_chart(fig, use_container_width=True)


def breakdown_charts(df: pd.DataFrame) -> None:
    col1, col2, col3 = st.columns(3)

    # Decision donut
    decision = df.get("decision", pd.Series(dtype=str))
    dec_counts = decision[decision.isin(["PASS", "BLOCK"])].value_counts()
    with col1:
        if dec_counts.empty:
            st.info("No decisions yet.")
        else:
            fig = go.Figure(go.Pie(
                labels=dec_counts.index.tolist(),
                values=dec_counts.values.tolist(), hole=0.55,
                marker=dict(colors=["#3b82f6" if k == "PASS" else "#ef4444"
                                    for k in dec_counts.index]),
            ))
            fig.update_layout(height=300, margin=dict(l=10, r=10, t=40, b=10),
                              title="PASS vs BLOCK")
            st.plotly_chart(fig, use_container_width=True)

    # Attack-type breakdown (exclude NONE)
    atk = df.get("attack_type", pd.Series(dtype=str)).fillna("NONE")
    atk_counts = atk[atk.str.upper() != "NONE"].value_counts()
    with col2:
        if atk_counts.empty:
            st.info("No attacks detected.")
        else:
            fig = px.bar(
                x=atk_counts.values, y=atk_counts.index, orientation="h",
                color=atk_counts.index, color_discrete_map=ATTACK_COLORS,
                labels={"x": "count", "y": ""},
            )
            fig.update_layout(height=300, margin=dict(l=10, r=10, t=40, b=10),
                              showlegend=False, title="Attack types")
            st.plotly_chart(fig, use_container_width=True)

    # Threat score histogram
    with col3:
        if "threat_score" in df.columns and len(df):
            fig = px.histogram(df, x="threat_score", nbins=25)
            fig.update_traces(marker_color="#8b5cf6")
            fig.update_layout(height=300, margin=dict(l=10, r=10, t=40, b=10),
                              title="Threat-score distribution")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No threat scores.")


def top_sources(df: pd.DataFrame) -> None:
    blocked = df[df.get("decision", pd.Series(dtype=str)) == "BLOCK"]
    ips = (blocked.get("source_ip", pd.Series(dtype=str))
           .replace("", "unknown").value_counts().head(10))
    if ips.empty:
        st.info("No blocked requests to rank source IPs.")
        return
    fig = px.bar(x=ips.values, y=ips.index, orientation="h",
                 labels={"x": "blocked requests", "y": ""})
    fig.update_traces(marker_color="#ef4444")
    fig.update_layout(height=320, margin=dict(l=10, r=10, t=40, b=10),
                      title="Top source IPs (blocked)")
    st.plotly_chart(fig, use_container_width=True)


# ---------------------------------------------------------------------------
# Main app
# ---------------------------------------------------------------------------

def main() -> None:
    st.set_page_config(page_title="OJS WAF Monitor", page_icon="🛡️", layout="wide")
    st.title("🛡️ OJS WAF — Monitoring Dashboard")

    days = available_days()
    if not days:
        st.warning(
            f"No log files found in `{LABELED_DIR}`. "
            "Start the sidecar (`python -m core.sidecar_agent`) to generate logs."
        )
        st.stop()

    with st.sidebar:
        st.header("Filters")
        selected_days = st.multiselect(
            "Days", options=days, default=days[-2:] if len(days) >= 2 else days,
        )
        gran = st.radio("Time granularity", ["Per minute", "Per hour"], index=1)
        freq = "min" if gran == "Per minute" else "h"
        only_blocked = st.checkbox("Show only blocked in table", value=False)
        search = st.text_input("Search URI / IP / UA", "")
        row_limit = st.slider("Max table rows", 50, 2000, 300, step=50)
        if st.button("🔄 Refresh data", use_container_width=True):
            st.cache_data.clear()
            st.rerun()
        st.caption("Tip: enable Streamlit auto-rerun from the top-right menu "
                   "for live monitoring.")

    if not selected_days:
        st.info("Select at least one day in the sidebar.")
        st.stop()

    df = load_days(tuple(selected_days), _mtimes_for(selected_days))

    st.subheader("Host health")
    system_row()
    st.subheader("WAF activity")
    kpi_row(df)

    if df.empty:
        st.info("No events in the selected range.")
        st.stop()

    traffic_chart(df, freq)
    breakdown_charts(df)
    top_sources(df)

    # ---- Event log table ----
    st.subheader("Recent events")
    table = df.copy()
    if only_blocked:
        table = table[table.get("decision", pd.Series(dtype=str)) == "BLOCK"]
    if search.strip():
        s = search.strip().lower()
        hay = (
            table.get("uri", "").astype(str).str.lower()
            + " " + table.get("source_ip", "").astype(str).str.lower()
            + " " + table.get("user_agent", "").astype(str).str.lower()
        )
        table = table[hay.str.contains(s, na=False)]

    table = table.sort_values("_ts", ascending=False).head(row_limit)
    cols = [c for c in DISPLAY_COLS if c in table.columns]
    st.caption(f"Showing {len(table):,} of {len(df):,} events")
    st.dataframe(table[cols], use_container_width=True, height=460)

    st.download_button(
        "⬇️ Download filtered events (CSV)",
        data=table[cols].to_csv(index=False).encode(),
        file_name="waf_events_filtered.csv",
        mime="text/csv",
    )


if __name__ == "__main__":
    main()
