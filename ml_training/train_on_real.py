"""
Train the OJS WAF Random Forest on the *real* captured dataset.

This entrypoint reads the labeled capture files directly (via
`ml_training.data_loader`, no `merge.csv`), extracts the full 33-dim feature
vector with the shared `extract_features`, then projects it down to the
22-feature real-data subset (`REALDATA_FEATURE_NAMES`) — dropping the SQLi /
path-traversal / command-injection detectors (no such attacks in the data) and
the five IP/User-Agent leakage features.

The saved bundle records `feature_names = REALDATA_FEATURE_NAMES`, so the
sidecar rebuilds the exact same projection at load time and parity is verified
end-to-end. Reported `attack_types` is `["RCE", "XSS"]` — the only families the
data supports.

CLI
---
    python -m ml_training.train_on_real
    python -m ml_training.train_on_real --no-dedup --seed 7
"""

from __future__ import annotations

import argparse
import pickle
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

from ml_training.data_loader import load_labeled_dataset, summarize
from ml_training.features import (
    REALDATA_FEATURE_NAMES,
    NUM_REALDATA_FEATURES,
    extract_features,
    selected_feature_indices,
)
from ml_training.training_utils import (
    build_feature_matrix,
    print_confusion_matrix,
    print_per_attack_recall,
    threshold_sweep,
)

PROJECT_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = PROJECT_DIR / "ml_training" / "waf_model.pkl"

MODEL_VERSION = "rf-realdata-v1"
REALDATA_ATTACK_TYPES = ["RCE", "XSS"]


@dataclass(frozen=True)
class RealTrainingConfig:
    n_estimators: int = 200
    max_depth: int = 14
    seed: int = 42
    test_size: float = 0.20
    default_threshold: float = 0.50
    deduplicate: bool = True


# ---------------------------------------------------------------------------
# Real-data smoke probes (XSS in body / RCE import route / benign OJS traffic)
# ---------------------------------------------------------------------------
# (name, method, uri, query_string, body, headers, expected_block)
_SMOKE_TESTS = [
    (
        "benign_login",
        "GET", "/index.php/publicknowledge/login", "", "",
        "Host: ojs.local\r\nUser-Agent: Mozilla/5.0", 0,
    ),
    (
        "benign_article_view",
        "GET", "/index.php/publicknowledge/article/view/42", "", "",
        "Host: ojs.local\r\nUser-Agent: Mozilla/5.0", 0,
    ),
    (
        "benign_update_query",
        "POST",
        "/index.php/publicknowledge/$$$call$$$/grid/queries/queries-grid/update-query?queryId=9&submissionId=16",
        "queryId=9&submissionId=16",
        "csrfToken=abc&comment=Please+revise+section+2&subject=Review",
        "Host: ojs.local\r\nUser-Agent: Mozilla/5.0", 0,
    ),
    (
        "xss_svg_in_body",
        "POST",
        "/index.php/publicknowledge/$$$call$$$/grid/settings/sections/section-grid/update-section?sectionId=3",
        "sectionId=3",
        "csrfToken=abc&sectionId=3&title%5Ben_US%5D=%3CSVG+ONLOAD%3Dalert(1)%3E&abbrev%5Ben_US%5D=aa",
        "Host: ojs.local\r\nUser-Agent: Mozilla/5.0", 1,
    ),
    (
        "xss_img_onerror_in_body",
        "POST",
        "/index.php/publicknowledge/$$$call$$$/grid/settings/sections/section-grid/update-section?sectionId=3",
        "sectionId=3",
        "csrfToken=abc&sectionId=3&title%5Ben_US%5D=%3cimg%20src%3dx%20onerror%3dalert(document%2ecookie)%3e",
        "Host: ojs.local\r\nUser-Agent: Mozilla/5.0", 1,
    ),
    (
        "rce_native_import_route",
        "GET",
        "/index.php/publicknowledge/management/importexport/plugin/NativeImportExportPlugin/import?temporaryFileId=4&csrfToken=bb328002",
        "temporaryFileId=4&csrfToken=bb328002",
        "",
        "Host: ojs.local\r\nUser-Agent: Mozilla/5.0", 1,
    ),
    (
        "rce_native_import_upload",
        "POST",
        "/index.php/publicknowledge/management/importexport/plugin/NativeImportExportPlugin/uploadImportXML",
        "",
        "--boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"x.xml\"\r\n",
        "Host: ojs.local\r\nUser-Agent: Mozilla/5.0", 1,
    ),
]


def project(X_full: np.ndarray, indices: list[int]) -> np.ndarray:
    """Project the full 33-dim feature matrix down to the selected columns."""
    return X_full[:, indices]


def report_feature_importance(
    clf: RandomForestClassifier, feature_names: list[str]
) -> None:
    """Print feature importances, highest first — evidence of what the model learned."""
    importances = clf.feature_importances_
    order = np.argsort(importances)[::-1]
    print("\n  Feature importance (real-data model):")
    for rank, idx in enumerate(order, 1):
        print(f"    {rank:2d}. {feature_names[idx]:<24} {importances[idx]:.4f}")


def run_smoke_tests(
    clf: RandomForestClassifier, threshold: float, indices: list[int]
) -> int:
    print("\n  Held-out real-style smoke tests:")
    correct = 0
    for name, method, uri, qs, body, headers, expected in _SMOKE_TESTS:
        full = extract_features(
            method=method, uri=uri, query_string=qs, body=body,
            headers=headers, stateful_req_rate=1.0,
        )
        feats = [full[i] for i in indices]
        proba = float(clf.predict_proba(np.array([feats]))[0, 1])
        pred = 1 if proba >= threshold else 0
        ok = (pred == expected)
        correct += int(ok)
        status = "PASS" if ok else "FAIL"
        verdict = "BLOCK" if pred == 1 else "PASS"
        expect_str = "BLOCK" if expected == 1 else "PASS"
        print(
            f"    [{status}] {name:<28} pred={verdict:<5} (score={proba:.3f})  "
            f"expected={expect_str}"
        )
    print(f"\n  Smoke-test accuracy: {correct}/{len(_SMOKE_TESTS)}")
    return correct


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def run(config: RealTrainingConfig) -> None:
    print("=" * 64)
    print(f"  WAF ML Training — REAL dataset ({MODEL_VERSION})")
    print("=" * 64)

    print("[*] Loading combined labeled dataset (no merge.csv)...")
    df = load_labeled_dataset(deduplicate=config.deduplicate)
    summ = summarize(df)
    print(f"    Rows: {summ['rows']}  (dropped {summ['dropped_duplicates']} duplicates)")
    print(f"    Attack types: {summ['attack_type']}")
    print(f"    By origin   : {summ['by_origin']}")

    print("[*] Extracting features (33-dim) and projecting to 22-dim subset...")
    X_full, y, attack_labels = build_feature_matrix(df)
    indices = selected_feature_indices(REALDATA_FEATURE_NAMES)
    X = project(X_full, indices)
    print(f"    Feature matrix: {X.shape}  (expected cols={NUM_REALDATA_FEATURES})")
    assert X.shape[1] == NUM_REALDATA_FEATURES, (
        f"Feature dim mismatch: {X.shape[1]} != {NUM_REALDATA_FEATURES}"
    )
    print(f"    Dropped features: {X_full.shape[1] - X.shape[1]} "
          f"(SQLi/path/cmd detectors + IP/UA leakage)")

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
    print_per_attack_recall(atk_test, y_test, y_pred_default, REALDATA_ATTACK_TYPES)

    best_thresh = threshold_sweep(y_test, y_proba)
    y_pred_best = (y_proba >= best_thresh).astype(int)
    print(f"\n--- Evaluation at best threshold ({best_thresh:.2f}) ---")
    print(f"  Precision: {precision_score(y_test, y_pred_best, zero_division=0):.4f}")
    print(f"  Recall   : {recall_score(y_test, y_pred_best, zero_division=0):.4f}")
    print(f"  F1       : {f1_score(y_test, y_pred_best, zero_division=0):.4f}")
    print_per_attack_recall(atk_test, y_test, y_pred_best, REALDATA_ATTACK_TYPES)

    report_feature_importance(clf, REALDATA_FEATURE_NAMES)
    run_smoke_tests(clf, best_thresh, indices)

    bundle = {
        "model": clf,
        "feature_names": list(REALDATA_FEATURE_NAMES),
        "block_threshold": float(best_thresh),
        "attack_types": REALDATA_ATTACK_TYPES,
        "model_version": MODEL_VERSION,
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    with MODEL_PATH.open("wb") as f:
        pickle.dump(bundle, f)
    print(f"\n[*] Model bundle saved -> {MODEL_PATH}")
    print(f"    feature_names: {len(REALDATA_FEATURE_NAMES)} cols   "
          f"attack_types: {REALDATA_ATTACK_TYPES}")
    print(f"    Recommended BLOCK_THRESHOLD = {best_thresh:.2f} (stored in bundle).")


def main() -> None:
    parser = argparse.ArgumentParser(description="WAF training on the real labeled dataset")
    parser.add_argument("--n-estimators", type=int, default=200)
    parser.add_argument("--max-depth", type=int, default=14)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--test-size", type=float, default=0.20)
    parser.add_argument(
        "--no-dedup", action="store_true",
        help="Keep duplicate payloads (default: drop them before the split).",
    )
    args = parser.parse_args()

    config = RealTrainingConfig(
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        seed=args.seed,
        test_size=args.test_size,
        deduplicate=not args.no_dedup,
    )
    run(config)


if __name__ == "__main__":
    main()
