"""
Bare-metal system metrics for the WAF dashboard.

Reads directly from the Linux ``/proc`` filesystem so the dashboard needs no
third-party dependency (no psutil). CPU and network figures are *rates*,
sampled over a short window inside a single call.

All functions degrade gracefully: if a ``/proc`` file is missing or malformed
they return zeros instead of raising, so the dashboard never crashes on an
exotic kernel.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Dict

_PROC = Path("/proc")


# ---------------------------------------------------------------------------
# CPU
# ---------------------------------------------------------------------------

def _read_cpu_times() -> tuple[int, int]:
    """Return (idle_all, total) jiffies from the aggregate ``cpu`` line."""
    try:
        line = (_PROC / "stat").read_text().splitlines()[0]
    except (OSError, IndexError):
        return 0, 0
    parts = line.split()[1:]
    nums = [int(x) for x in parts if x.isdigit()]
    if len(nums) < 5:
        return 0, 0
    idle = nums[3] + (nums[4] if len(nums) > 4 else 0)  # idle + iowait
    total = sum(nums)
    return idle, total


def cpu_percent(sample_window: float = 0.2) -> float:
    """Busy CPU percentage averaged across all cores over ``sample_window``."""
    idle1, total1 = _read_cpu_times()
    time.sleep(sample_window)
    idle2, total2 = _read_cpu_times()
    d_total = total2 - total1
    d_idle = idle2 - idle1
    if d_total <= 0:
        return 0.0
    return round(100.0 * (d_total - d_idle) / d_total, 1)


def cpu_count() -> int:
    try:
        return sum(
            1
            for line in (_PROC / "stat").read_text().splitlines()
            if line.startswith("cpu") and line[3:4].isdigit()
        ) or 1
    except OSError:
        return 1


def load_average() -> list[float]:
    try:
        parts = (_PROC / "loadavg").read_text().split()
        return [float(parts[0]), float(parts[1]), float(parts[2])]
    except (OSError, ValueError, IndexError):
        return [0.0, 0.0, 0.0]


# ---------------------------------------------------------------------------
# Memory
# ---------------------------------------------------------------------------

def memory() -> Dict[str, float]:
    """Memory figures in bytes plus a used-percentage."""
    info: Dict[str, int] = {}
    try:
        for line in (_PROC / "meminfo").read_text().splitlines():
            key, _, rest = line.partition(":")
            val = rest.strip().split()
            if val and val[0].isdigit():
                info[key] = int(val[0]) * 1024  # kB -> bytes
    except OSError:
        pass

    total = info.get("MemTotal", 0)
    available = info.get("MemAvailable", info.get("MemFree", 0))
    used = max(total - available, 0)
    swap_total = info.get("SwapTotal", 0)
    swap_free = info.get("SwapFree", 0)
    return {
        "total": total,
        "available": available,
        "used": used,
        "percent": round(100.0 * used / total, 1) if total else 0.0,
        "swap_total": swap_total,
        "swap_used": max(swap_total - swap_free, 0),
    }


# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------

def _read_net_bytes() -> tuple[int, int]:
    """Sum rx/tx bytes over all non-loopback interfaces."""
    rx = tx = 0
    try:
        lines = (_PROC / "net" / "dev").read_text().splitlines()[2:]
    except OSError:
        return 0, 0
    for line in lines:
        iface, _, data = line.partition(":")
        iface = iface.strip()
        if iface == "lo" or not data.strip():
            continue
        cols = data.split()
        if len(cols) >= 9:
            try:
                rx += int(cols[0])
                tx += int(cols[8])
            except ValueError:
                continue
    return rx, tx


def network_rate(sample_window: float = 0.2) -> Dict[str, float]:
    """Aggregate rx/tx throughput in bytes-per-second and cumulative totals."""
    rx1, tx1 = _read_net_bytes()
    time.sleep(sample_window)
    rx2, tx2 = _read_net_bytes()
    span = sample_window or 1.0
    return {
        "rx_bytes": rx2,
        "tx_bytes": tx2,
        "rx_rate": max((rx2 - rx1) / span, 0.0),
        "tx_rate": max((tx2 - tx1) / span, 0.0),
    }


# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------

def snapshot() -> Dict[str, object]:
    """One combined sample. CPU and network share a single sleep window."""
    # Prime CPU + network counters, sleep once, re-read — keeps the call ~0.25s.
    idle1, total1 = _read_cpu_times()
    rx1, tx1 = _read_net_bytes()
    time.sleep(0.25)
    idle2, total2 = _read_cpu_times()
    rx2, tx2 = _read_net_bytes()

    d_total = total2 - total1
    cpu = round(100.0 * (d_total - (idle2 - idle1)) / d_total, 1) if d_total > 0 else 0.0

    return {
        "cpu_percent": cpu,
        "cpu_count": cpu_count(),
        "load_average": load_average(),
        "memory": memory(),
        "network": {
            "rx_bytes": rx2,
            "tx_bytes": tx2,
            "rx_rate": max((rx2 - rx1) / 0.25, 0.0),
            "tx_rate": max((tx2 - tx1) / 0.25, 0.0),
        },
        "uptime_seconds": _uptime(),
    }


def _uptime() -> float:
    try:
        return float((_PROC / "uptime").read_text().split()[0])
    except (OSError, ValueError, IndexError):
        return 0.0


if __name__ == "__main__":
    import json

    print(json.dumps(snapshot(), indent=2))
