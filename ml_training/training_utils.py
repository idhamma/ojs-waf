"""
Shared training/evaluation utilities for the real-data WAF pipeline.

These helpers used to live in `ml_training.train_pipeline` (the synthetic
pipeline). They are pure functions over a DataFrame / arrays and carry no
dependency on the synthetic dataset generator, so the real-data entrypoint
(`ml_training.train_on_real`) imports them from here instead.

Contents
--------
    build_feature_matrix     - DataFrame -> (X, y, attack_labels), with the
                               60s-per-IP req_rate window matching the sidecar.
    print_confusion_matrix   - 2x2 PASS/BLOCK confusion matrix.
    print_per_attack_recall  - recall per attack family + benign FPR.
    threshold_sweep          - precision/recall/F1 across thresholds; returns
                               the best-F1 threshold.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

from ml_training.features import extract_features


# ---------------------------------------------------------------------------
# Feature matrix
# ---------------------------------------------------------------------------

def build_feature_matrix(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """
    Build (X, y, attack_labels) for stratification.

    The `req_rate` feature is computed inline over a 60s rolling window per
    source IP, ordered by timestamp — matching the runtime behavior of
    `core/sidecar_agent.SidecarWAF.predict`.
    """
    df = df.copy()
    df["timestamp_dt"] = pd.to_datetime(
        df["timestamp"], format="mixed", errors="coerce", utc=True
    )
    df = df.sort_values("timestamp_dt").reset_index(drop=True)

    ip_history: dict[str, list[float]] = {}
    rows: list[list[float]] = []
    y: list[int] = []
    attack_labels: list[str] = []

    for _, row in df.iterrows():
        ip = str(row.get("source_ip", ""))
        ts = row.get("timestamp_dt")
        rate = 0.0
        if pd.notna(ts):
            ts_val = ts.timestamp()
            recent = [t for t in ip_history.get(ip, []) if ts_val - t < 60]
            recent.append(ts_val)
            ip_history[ip] = recent
            rate = float(len(recent))

        feats = extract_features(
            method=str(row.get("method", "GET")),
            uri=str(row.get("uri", "")),
            query_string=str(row.get("query_string", "")),
            body=str(row.get("body_truncated", "")),
            headers=str(row.get("headers_raw", "")),
            stateful_req_rate=rate,
        )
        rows.append(feats)
        y.append(1 if str(row.get("decision", "PASS")).upper() == "BLOCK" else 0)
        attack_labels.append(str(row.get("attack_type", "NONE")))

    return np.array(rows, dtype=float), np.array(y, dtype=int), np.array(attack_labels)


# ---------------------------------------------------------------------------
# Evaluation helpers
# ---------------------------------------------------------------------------

def print_confusion_matrix(y_true: np.ndarray, y_pred: np.ndarray) -> None:
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    print("\n  Confusion Matrix:")
    print(f"               Predicted PASS  Predicted BLOCK")
    print(f"  Actual PASS       {tn:6d}          {fp:6d}")
    print(f"  Actual BLOCK      {fn:6d}          {tp:6d}")


def print_per_attack_recall(
    attack_labels_test: np.ndarray,
    y_true: np.ndarray,
    y_pred: np.ndarray,
    attack_types: list[str] | None = None,
) -> None:
    # Default: infer the attack families present in this split (everything that
    # is not the benign "NONE" label). No dependency on a fixed catalog.
    if attack_types is None:
        attack_types = sorted(
            {str(a) for a in np.unique(attack_labels_test) if str(a) != "NONE"}
        )
    print("\n  Per-Attack-Type Recall:")
    for atype in attack_types:
        mask = (attack_labels_test == atype)
        if mask.sum() == 0:
            continue
        total = int(mask.sum())
        true_positive = int(((y_true[mask] == 1) & (y_pred[mask] == 1)).sum())
        missed = int(((y_true[mask] == 1) & (y_pred[mask] == 0)).sum())
        recall = (
            true_positive / (true_positive + missed)
            if (true_positive + missed) else 0.0
        )
        print(
            f"    {atype:<22} total={total:4d}  detected={true_positive:4d}  "
            f"missed={missed:4d}  recall={recall:.2%}"
        )

    benign_mask = (attack_labels_test == "NONE")
    if benign_mask.sum():
        false_positive = int(
            ((y_true[benign_mask] == 0) & (y_pred[benign_mask] == 1)).sum()
        )
        fpr = false_positive / int(benign_mask.sum())
        print(
            f"    {'BENIGN':<22} total={int(benign_mask.sum()):4d}  "
            f"false_positives={false_positive:4d}  fpr={fpr:.2%}"
        )


def threshold_sweep(y_true: np.ndarray, y_proba: np.ndarray) -> float:
    print("\n  Threshold Sweep (attack class):")
    print(f"  {'Threshold':>10}  {'Precision':>10}  {'Recall':>8}  {'F1':>8}")
    best_f1, best_thresh = 0.0, 0.50
    for t in np.arange(0.30, 0.96, 0.05):
        y_pred_t = (y_proba >= t).astype(int)
        p = precision_score(y_true, y_pred_t, zero_division=0)
        r = recall_score(y_true, y_pred_t, zero_division=0)
        f = f1_score(y_true, y_pred_t, zero_division=0)
        marker = " <-- best so far" if f > best_f1 else ""
        print(f"  {t:>10.2f}  {p:>10.4f}  {r:>8.4f}  {f:>8.4f}{marker}")
        if f > best_f1:
            best_f1, best_thresh = f, float(t)
    print(f"\n  Best threshold by F1: {best_thresh:.2f}  (F1={best_f1:.4f})")
    return best_thresh
