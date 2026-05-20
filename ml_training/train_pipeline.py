"""
WAF ML Training Pipeline

Reads real traffic data from dataset/raw/ and dataset/labeled/,
trains a Random Forest classifier, evaluates with confusion matrix /
per-attack-type report, tunes BLOCK_THRESHOLD, and saves the model.

Usage:
    python -m ml_training.train_pipeline            # auto dataset
    python -m ml_training.train_pipeline --synthetic  # force synthetic fallback
    python -m ml_training.train_pipeline --threshold-sweep  # show threshold table
"""

import argparse
import os
import pickle
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

from ml_training.features import NUM_FEATURES, extract_features

PROJECT_DIR = Path(__file__).resolve().parent.parent
DATASET_DIR = PROJECT_DIR / "dataset"
MODEL_PATH = PROJECT_DIR / "ml_training" / "waf_model.pkl"

ATTACK_TYPES = ["SQL_INJECTION", "XSS", "PATH_TRAVERSAL", "COMMAND_INJECTION", "UNKNOWN_ATTACK"]


@dataclass(frozen=True)
class TrainingConfig:
    n_estimators: int = 100
    max_depth: int = 10
    seed: int = 42
    test_size: float = 0.2
    default_threshold: float = 0.70


# ---------------------------------------------------------------------------
# Dataset loaders
# ---------------------------------------------------------------------------

def load_labeled_csvs(labeled_dir: Path) -> Optional[pd.DataFrame]:
    """Load all labeled CSVs; return None if directory is empty."""
    files = sorted(labeled_dir.glob("*.csv"))
    if not files:
        return None
    frames = []
    for f in files:
        try:
            df = pd.read_csv(f, skipinitialspace=True)
            frames.append(df)
        except Exception as exc:
            print(f"[!] Skipping {f.name}: {exc}")
    if not frames:
        return None
    return pd.concat(frames, ignore_index=True)


def _derive_label(row) -> int:
    """Derive binary label from decision column (BLOCK=1, PASS=0)."""
    decision = str(row.get("decision", "")).upper()
    return 1 if decision == "BLOCK" else 0


def build_feature_matrix(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    """Build (X, y) from a labeled DataFrame."""
    rows = []
    labels = []
    for _, row in df.iterrows():
        feats = extract_features(
            method=str(row.get("method", "GET")),
            uri=str(row.get("uri", "")),
            query_string=str(row.get("query_string", "")),
            body=str(row.get("body_raw", row.get("body_truncated", ""))),
            headers=str(row.get("headers_raw", "")),
            stateful_req_rate=0.0,
        )
        rows.append(feats)
        labels.append(_derive_label(row))
    return np.array(rows), np.array(labels)


# ---------------------------------------------------------------------------
# Synthetic fallback (mirrors train_waf_model.py generate_synthetic_dataset)
# ---------------------------------------------------------------------------

def generate_synthetic_dataset() -> pd.DataFrame:
    print("[*] No real labeled data found — generating synthetic dataset...")
    rng = np.random.default_rng(42)
    data = []

    normal_uris = [
        "/index.php/testjournal/index",
        "/index.php/testjournal/article/view/123",
        "/index.php/testjournal/search?query=science",
        "/lib/pkp/styles/pkp.css",
        "/index.php/testjournal/user/register",
        "/index.php/testjournal/about",
    ]
    for _ in range(2500):
        uri = rng.choice(normal_uris)
        query_string = uri.partition("?")[2] if "?" in uri else ""
        data.append({
            "method": "GET", "uri": uri, "query_string": query_string,
            "body_raw": "", "headers_raw": "Host: local-ojs.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html",
            "decision": "PASS", "attack_type": "NONE",
        })

    attacks = [
        ("/index.php/testjournal/search?query=science' OR '1'='1", "GET",
         "Host: local-ojs.com\r\nUser-Agent: Nikto/2.1.6", "SQL_INJECTION"),
        ("/index.php/testjournal/article/view/123", "POST",
         "User-Agent: curl/7.68.0", "SQL_INJECTION"),
        ("/index.php/testjournal/search?query=admin'; DROP TABLE users--", "GET",
         "Host: local-ojs.com", "SQL_INJECTION"),
        ("/index.php/testjournal/search?query=<script>alert('xss')</script>", "GET",
         "Host: local-ojs.com\r\nUser-Agent: Mozilla/5.0", "XSS"),
        ("/index.php/testjournal/user/register?username=\"><svg/onload=alert(1)>", "GET",
         "Host: local-ojs.com", "XSS"),
        ("/index.php/testjournal/article/download/123/../../../../../etc/passwd", "GET",
         "Host: local-ojs.com", "PATH_TRAVERSAL"),
        ("/index.php/testjournal/search?query=../../../windows/win.ini", "TRACE",
         "Host: local-ojs.com\r\nUser-Agent: test", "PATH_TRAVERSAL"),
        ("/index.php/testjournal/search?query=science; ping -c 4 127.0.0.1", "GET",
         "Host: local-ojs.com\r\nUser-Agent: bot", "COMMAND_INJECTION"),
        ("/index.php/testjournal/search?query=`whoami`", "POST",
         "Host: local-ojs.com\r\nUser-Agent: curl", "COMMAND_INJECTION"),
    ]
    for _ in range(1500):
        idx = int(rng.integers(0, len(attacks)))
        uri, method, headers, atype = attacks[idx]
        query_string = uri.partition("?")[2] if "?" in uri else ""
        data.append({
            "method": method, "uri": uri, "query_string": query_string,
            "body_raw": "", "headers_raw": headers,
            "decision": "BLOCK", "attack_type": atype,
        })

    return pd.DataFrame(data)


# ---------------------------------------------------------------------------
# Evaluation helpers
# ---------------------------------------------------------------------------

def print_confusion_matrix(y_true, y_pred) -> None:
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    print("\n  Confusion Matrix:")
    print(f"               Predicted PASS  Predicted BLOCK")
    print(f"  Actual PASS       {tn:6d}          {fp:6d}")
    print(f"  Actual BLOCK      {fn:6d}          {tp:6d}")


def print_per_attack_report(df_test: pd.DataFrame, y_pred: np.ndarray) -> None:
    if "attack_type" not in df_test.columns:
        return
    print("\n  Per-Attack-Type Report:")
    df_eval = df_test.copy().reset_index(drop=True)
    df_eval["y_pred"] = y_pred
    df_eval["y_true"] = (df_eval["decision"].str.upper() == "BLOCK").astype(int)

    for atype in ATTACK_TYPES:
        mask = df_eval["attack_type"] == atype
        if mask.sum() == 0:
            continue
        subset = df_eval[mask]
        tp = int(((subset["y_true"] == 1) & (subset["y_pred"] == 1)).sum())
        fn = int(((subset["y_true"] == 1) & (subset["y_pred"] == 0)).sum())
        total = int(mask.sum())
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        print(f"    {atype:<22} total={total:4d}  detected={tp:4d}  missed={fn:4d}  recall={recall:.2%}")


def threshold_sweep(y_true, y_proba, thresholds=None) -> float:
    """Print precision/recall/F1 for a range of thresholds; return best F1 threshold."""
    if thresholds is None:
        thresholds = np.arange(0.30, 0.96, 0.05)

    print("\n  Threshold Sweep (attack class):")
    print(f"  {'Threshold':>10}  {'Precision':>10}  {'Recall':>8}  {'F1':>8}")
    best_f1, best_thresh = 0.0, 0.70
    for t in thresholds:
        y_pred_t = (y_proba >= t).astype(int)
        p = precision_score(y_true, y_pred_t, zero_division=0)
        r = recall_score(y_true, y_pred_t, zero_division=0)
        f = f1_score(y_true, y_pred_t, zero_division=0)
        marker = " ◄" if f > best_f1 else ""
        print(f"  {t:>10.2f}  {p:>10.4f}  {r:>8.4f}  {f:>8.4f}{marker}")
        if f > best_f1:
            best_f1, best_thresh = f, float(t)
    print(f"\n  Best threshold by F1: {best_thresh:.2f}  (F1={best_f1:.4f})")
    return best_thresh


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def run_pipeline(config: TrainingConfig, force_synthetic: bool = False, show_threshold_sweep: bool = False) -> None:
    print("=" * 56)
    print("  WAF ML Training Pipeline")
    print("=" * 56)

    # 1. Load data
    df = None
    if not force_synthetic:
        df = load_labeled_csvs(DATASET_DIR / "labeled")

    if df is None or len(df) < 100:
        print(f"[!] Real labeled data insufficient ({len(df) if df is not None else 0} rows). Using synthetic.")
        df = generate_synthetic_dataset()
    else:
        print(f"[*] Loaded {len(df)} real labeled records from dataset/labeled/")

    print(f"[*] Label distribution: PASS={int((df['decision'].str.upper()=='PASS').sum())}  "
          f"BLOCK={int((df['decision'].str.upper()=='BLOCK').sum())}")

    # 2. Extract features
    print("[*] Extracting features...")
    X, y = build_feature_matrix(df)
    print(f"[*] Feature matrix: {X.shape}  (expected cols={NUM_FEATURES})")
    assert X.shape[1] == NUM_FEATURES, f"Feature dim mismatch: {X.shape[1]} != {NUM_FEATURES}"

    # 3. Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=config.test_size, random_state=config.seed, stratify=y
    )
    df_test = df.iloc[len(X_train):].reset_index(drop=True)  # approximate — used only for per-attack report

    # 4. Train
    print(f"[*] Training Random Forest (n_estimators={config.n_estimators}, max_depth={config.max_depth})...")
    clf = RandomForestClassifier(
        n_estimators=config.n_estimators,
        max_depth=config.max_depth,
        random_state=config.seed,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    # 5. Evaluate
    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]

    print("\n--- Model Evaluation ---")
    print(f"  Accuracy : {(y_pred == y_test).mean() * 100:.2f}%")
    print(f"  Precision: {precision_score(y_test, y_pred, zero_division=0):.4f}")
    print(f"  Recall   : {recall_score(y_test, y_pred, zero_division=0):.4f}")
    print(f"  F1       : {f1_score(y_test, y_pred, zero_division=0):.4f}")
    try:
        print(f"  AUC-ROC  : {roc_auc_score(y_test, y_proba):.4f}")
    except ValueError:
        pass

    print_confusion_matrix(y_test, y_pred)

    print("\n  Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["PASS", "BLOCK"]))

    # 6. Per-attack-type report (best-effort; relies on attack_type column)
    try:
        # Re-split with same seed to align df_test with X_test
        _, df_test_aligned = train_test_split(df, test_size=config.test_size, random_state=config.seed)
        print_per_attack_report(df_test_aligned, y_pred)
    except Exception:
        pass

    # 7. Threshold sweep
    if show_threshold_sweep:
        best_thresh = threshold_sweep(y_test, y_proba)
        print(f"\n[i] To apply best threshold, set BLOCK_THRESHOLD = {best_thresh:.2f} in sidecar_agent.py")
    else:
        print(f"\n[i] Run with --threshold-sweep to tune BLOCK_THRESHOLD (current default: {config.default_threshold})")

    # 8. Save model
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(clf, f)
    print(f"\n[*] Model saved → {MODEL_PATH}")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="WAF ML Training Pipeline")
    parser.add_argument("--synthetic", action="store_true",
                        help="Force synthetic dataset even when real data exists")
    parser.add_argument("--threshold-sweep", action="store_true",
                        help="Print precision/recall/F1 table across thresholds")
    parser.add_argument("--n-estimators", type=int, default=100)
    parser.add_argument("--max-depth", type=int, default=10)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    config = TrainingConfig(
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        seed=args.seed,
    )
    run_pipeline(config, force_synthetic=args.synthetic, show_threshold_sweep=args.threshold_sweep)


if __name__ == "__main__":
    main()
