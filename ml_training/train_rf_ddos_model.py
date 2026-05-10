"""
DDoS Detection — Random Forest for eBPF In-Kernel Inference

Trains a Random Forest on CIC-IDS-2017 using the top 15 ANOVA F-test features.
Exports every tree's structure as flat node arrays for loading into BPF maps.

15 ANOVA F-test Features (index order for kernel):
  0:  Idle Min
  1:  Bwd Packet Length Min
  2:  Idle Mean
  3:  Fwd IAT Total
  4:  Bwd Packet Length Mean
  5:  Fwd IAT Mean
  6:  Min Packet Length
  7:  Packet Length Mean
  8:  Fwd IAT Max
  9:  Average Packet Size
  10: Max Packet Length
  11: Packet Length Variance
  12: Avg Bwd Segment Size
  13: Bwd Packet Length Max
  14: Idle Max
"""

import os
import sys
import json
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from sklearn.feature_selection import f_classif

class NumpyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (np.integer,)):
            return int(obj)
        elif isinstance(obj, (np.floating,)):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        elif isinstance(obj, np.bool_):
            return bool(obj)
        return super().default(obj)

print("=" * 60)
print("  DDoS Random Forest Trainer (RF → eBPF Multi-Tree)")
print("=" * 60)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SCALE = 1000
MAX_DEPTH = 8
N_ESTIMATORS = 10  # Number of trees (keep low for BPF map limits)
MAX_NODES_PER_TREE = 512
MAX_TOTAL_NODES = N_ESTIMATORS * MAX_NODES_PER_TREE  # 5120

MODEL_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_JSON = os.path.join(MODEL_DIR, "rf_model_ebpf.json")

# The 15 ANOVA F-test features in kernel extraction order
# These map to CIC-IDS-2017 CSV column names
ANOVA_FEATURE_NAMES = [
    "idle_min",
    "bwd_pkt_len_min",
    "idle_mean",
    "fwd_iat_total",
    "bwd_pkt_len_mean",
    "fwd_iat_mean",
    "min_pkt_len",
    "pkt_len_mean",
    "fwd_iat_max",
    "avg_pkt_size",
    "max_pkt_len",
    "pkt_len_variance",
    "avg_bwd_seg_size",
    "bwd_pkt_len_max",
    "idle_max",
]

# CIC-IDS-2017 CSV column → our feature name
CIC_COLUMN_MAP = {
    " Idle Min":               "idle_min",
    " Bwd Packet Length Min":  "bwd_pkt_len_min",
    "Idle Mean":               "idle_mean",
    "Fwd IAT Total":           "fwd_iat_total",
    " Bwd Packet Length Mean": "bwd_pkt_len_mean",
    " Fwd IAT Mean":           "fwd_iat_mean",
    " Min Packet Length":      "min_pkt_len",
    " Packet Length Mean":     "pkt_len_mean",
    " Fwd IAT Max":            "fwd_iat_max",
    " Average Packet Size":    "avg_pkt_size",
    " Max Packet Length":      "max_pkt_len",
    " Packet Length Variance": "pkt_len_variance",
    " Avg Bwd Segment Size":   "avg_bwd_seg_size",
    "Bwd Packet Length Max":   "bwd_pkt_len_max",
    " Idle Max":               "idle_max",
}

NUM_FEATURES = len(ANOVA_FEATURE_NAMES)

# ---------------------------------------------------------------------------
# Dataset loading
# ---------------------------------------------------------------------------

def load_cicids_csv(csv_path):
    """Load CIC-IDS-2017 CSV and extract the 15 ANOVA features."""
    print(f"[*] Loading dataset from {csv_path}...")
    df = pd.read_csv(csv_path, low_memory=False)

    # Strip column names
    df.columns = df.columns.str.strip()

    # Re-add leading space variants for mapping (CIC-IDS-2017 has inconsistent spacing)
    # Build a normalized lookup: strip all column names, then map
    col_stripped = {c.strip(): c for c in df.columns}

    print(f"[*] Dataset shape: {df.shape}")

    mapped = {}
    for cic_col_raw, feat_name in CIC_COLUMN_MAP.items():
        cic_col = cic_col_raw.strip()
        if cic_col in col_stripped:
            orig_col = col_stripped[cic_col]
            mapped[feat_name] = df[orig_col]
        else:
            print(f"    [!] Missing column: '{cic_col}' → {feat_name}")

    if len(mapped) < 10:
        print(f"[!] Only {len(mapped)}/15 features found. Available: {list(df.columns)}")
        return None, None

    features_df = pd.DataFrame(mapped)

    # Handle label
    label_col = None
    for candidate in ["Label", "label", " Label"]:
        c = candidate.strip()
        if c in col_stripped:
            label_col = col_stripped[c]
            break

    if label_col is None:
        print("[!] No 'Label' column found.")
        return None, None

    labels = df[label_col].str.strip()
    y = (labels != "BENIGN").astype(int)

    print(f"[*] Label distribution:")
    print(f"    BENIGN (0): {(y == 0).sum():,}")
    print(f"    ATTACK (1): {(y == 1).sum():,}")

    features_df = features_df.replace([np.inf, -np.inf], np.nan).fillna(0)

    for feat in ANOVA_FEATURE_NAMES:
        if feat not in features_df.columns:
            features_df[feat] = 0

    X = features_df[ANOVA_FEATURE_NAMES].values.astype(np.float64)
    return X, y.values


def generate_synthetic_dataset():
    """Synthetic dataset when CIC-IDS-2017 is not available."""
    print("[*] Generating synthetic DDoS dataset (ANOVA features)...")
    np.random.seed(42)
    data = []

    # NORMAL traffic
    for _ in range(5000):
        data.append({
            "idle_min": np.random.uniform(0, 5000000),
            "bwd_pkt_len_min": np.random.randint(0, 1500),
            "idle_mean": np.random.uniform(0, 10000000),
            "fwd_iat_total": np.random.uniform(1000, 50000000),
            "bwd_pkt_len_mean": np.random.uniform(100, 2000),
            "fwd_iat_mean": np.random.uniform(1000, 5000000),
            "min_pkt_len": np.random.randint(40, 100),
            "pkt_len_mean": np.random.uniform(100, 800),
            "fwd_iat_max": np.random.uniform(5000, 30000000),
            "avg_pkt_size": np.random.uniform(100, 900),
            "max_pkt_len": np.random.randint(500, 1500),
            "pkt_len_variance": np.random.uniform(1000, 200000),
            "avg_bwd_seg_size": np.random.uniform(100, 2000),
            "bwd_pkt_len_max": np.random.randint(200, 1500),
            "idle_max": np.random.uniform(0, 20000000),
            "label": 0,
        })

    # DDoS: SYN FLOOD
    for _ in range(2000):
        data.append({
            "idle_min": 0,
            "bwd_pkt_len_min": 0,
            "idle_mean": 0,
            "fwd_iat_total": np.random.uniform(0, 500),
            "bwd_pkt_len_mean": 0,
            "fwd_iat_mean": np.random.uniform(0, 50),
            "min_pkt_len": np.random.randint(40, 60),
            "pkt_len_mean": np.random.uniform(40, 80),
            "fwd_iat_max": np.random.uniform(0, 200),
            "avg_pkt_size": np.random.uniform(40, 80),
            "max_pkt_len": np.random.randint(60, 80),
            "pkt_len_variance": np.random.uniform(0, 100),
            "avg_bwd_seg_size": 0,
            "bwd_pkt_len_max": 0,
            "idle_max": 0,
            "label": 1,
        })

    # DDoS: HTTP FLOOD
    for _ in range(1500):
        data.append({
            "idle_min": 0,
            "bwd_pkt_len_min": np.random.randint(0, 50),
            "idle_mean": 0,
            "fwd_iat_total": np.random.uniform(100, 5000),
            "bwd_pkt_len_mean": np.random.uniform(0, 100),
            "fwd_iat_mean": np.random.uniform(1, 100),
            "min_pkt_len": np.random.randint(40, 60),
            "pkt_len_mean": np.random.uniform(50, 200),
            "fwd_iat_max": np.random.uniform(10, 500),
            "avg_pkt_size": np.random.uniform(50, 200),
            "max_pkt_len": np.random.randint(100, 300),
            "pkt_len_variance": np.random.uniform(0, 5000),
            "avg_bwd_seg_size": np.random.uniform(0, 100),
            "bwd_pkt_len_max": np.random.randint(0, 200),
            "idle_max": 0,
            "label": 1,
        })

    # DDoS: VOLUMETRIC
    for _ in range(1500):
        data.append({
            "idle_min": 0,
            "bwd_pkt_len_min": 0,
            "idle_mean": 0,
            "fwd_iat_total": np.random.uniform(50, 3000),
            "bwd_pkt_len_mean": 0,
            "fwd_iat_mean": np.random.uniform(0.5, 30),
            "min_pkt_len": np.random.randint(500, 800),
            "pkt_len_mean": np.random.uniform(800, 1400),
            "fwd_iat_max": np.random.uniform(5, 100),
            "avg_pkt_size": np.random.uniform(800, 1400),
            "max_pkt_len": np.random.randint(1200, 1500),
            "pkt_len_variance": np.random.uniform(0, 2000),
            "avg_bwd_seg_size": 0,
            "bwd_pkt_len_max": 0,
            "idle_max": 0,
            "label": 1,
        })

    df = pd.DataFrame(data)
    print(f"[*] Generated {len(df)} samples (BENIGN={( df['label']==0).sum()}, ATTACK={(df['label']==1).sum()})")
    X = df[ANOVA_FEATURE_NAMES].values
    y = df["label"].values
    return X, y


# ---------------------------------------------------------------------------
# Export Random Forest → BPF Nodes
# ---------------------------------------------------------------------------

def export_single_tree(estimator, scale=SCALE):
    """Convert one sklearn DecisionTree into a flat array of BPF node dicts."""
    tree = estimator.tree_
    n_nodes = tree.node_count
    nodes = []

    for i in range(n_nodes):
        is_leaf = (tree.children_left[i] == -1)
        if is_leaf:
            class_counts = tree.value[i][0]
            class_id = int(np.argmax(class_counts))
            nodes.append({
                "feature_idx": 0,
                "is_leaf": True,
                "class_id": class_id,
                "left_child": -1,
                "right_child": -1,
                "threshold": 0,
            })
        else:
            feature_idx = int(tree.feature[i])
            threshold_fp = int(float(tree.threshold[i]) * scale)
            nodes.append({
                "feature_idx": feature_idx,
                "is_leaf": False,
                "class_id": 0,
                "left_child": int(tree.children_left[i]),
                "right_child": int(tree.children_right[i]),
                "threshold": threshold_fp,
            })

    return nodes


def export_rf_to_bpf(clf, scale=SCALE):
    """Export all trees of a Random Forest into BPF-compatible format."""
    trees_data = []
    total_nodes = 0

    for i, estimator in enumerate(clf.estimators_):
        nodes = export_single_tree(estimator, scale)
        n = len(nodes)

        if n > MAX_NODES_PER_TREE:
            print(f"[!] Tree {i} has {n} nodes (max {MAX_NODES_PER_TREE}). Skipping.")
            continue

        trees_data.append({
            "tree_idx": i,
            "n_nodes": n,
            "depth": estimator.tree_.max_depth,
            "offset": total_nodes,  # start index in flattened array
            "nodes": nodes,
        })
        total_nodes += n

    if total_nodes > MAX_TOTAL_NODES:
        print(f"[!] Total nodes {total_nodes} exceeds BPF limit {MAX_TOTAL_NODES}!")

    return trees_data, total_nodes


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    # 1. Load dataset
    dataset_dir = os.path.join(os.path.dirname(MODEL_DIR), "dataset")
    csv_candidates = []

    for search_dir in [dataset_dir, os.path.join(dataset_dir, "features")]:
        if os.path.isdir(search_dir):
            for f in os.listdir(search_dir):
                if f.endswith(".csv"):
                    csv_candidates.append(os.path.join(search_dir, f))

    X, y = None, None

    if csv_candidates:
        print(f"[*] Found {len(csv_candidates)} CSV files:")
        for f in csv_candidates:
            print(f"    - {os.path.basename(f)}")

        X_parts, y_parts = [], []
        for csv_path in csv_candidates:
            Xi, yi = load_cicids_csv(csv_path)
            if Xi is not None:
                X_parts.append(Xi)
                y_parts.append(yi)

        if X_parts:
            X = np.vstack(X_parts)
            y = np.concatenate(y_parts)

    if X is None:
        X, y = generate_synthetic_dataset()

    # 2. Clean
    print(f"\n[*] Dataset: {X.shape[0]:,} samples, {X.shape[1]} features")
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

    # 3. ANOVA F-test verification
    print("\n[*] ANOVA F-test scores:")
    f_scores, p_values = f_classif(X, y)
    for i, name in enumerate(ANOVA_FEATURE_NAMES):
        print(f"    {i:2d}. {name:.<30s} F={f_scores[i]:12.2f}  p={p_values[i]:.2e}")

    # 4. Train/Test Split (80/20)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\n[*] Train: {X_train.shape[0]:,}, Test: {X_test.shape[0]:,}")

    # 5. Train Random Forest
    print(f"\n[*] Training Random Forest (n_trees={N_ESTIMATORS}, max_depth={MAX_DEPTH})...")
    clf = RandomForestClassifier(
        n_estimators=N_ESTIMATORS,
        max_depth=MAX_DEPTH,
        min_samples_split=10,
        min_samples_leaf=5,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    # Print per-tree stats
    print(f"[✓] Random Forest trained:")
    for i, est in enumerate(clf.estimators_):
        t = est.tree_
        print(f"    Tree {i:2d}: {t.node_count:4d} nodes, depth={t.max_depth}")

    # 6. Evaluate
    y_pred = clf.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)

    print(f"\n--- Model Evaluation ---")
    print(f"Accuracy: {accuracy * 100:.2f}%")
    print(classification_report(y_test, y_pred, target_names=["BENIGN", "DDOS"]))

    cm = confusion_matrix(y_test, y_pred)
    print(f"Confusion Matrix:")
    print(f"  TN={cm[0][0]:5d}  FP={cm[0][1]:5d}")
    print(f"  FN={cm[1][0]:5d}  TP={cm[1][1]:5d}")

    cv_scores = cross_val_score(clf, X, y, cv=5, scoring="accuracy")
    print(f"\nCross-Validation (5-fold): {cv_scores.mean()*100:.2f}% ± {cv_scores.std()*100:.2f}%")

    # Feature importance
    print(f"\nFeature Importance (sorted):")
    importances = clf.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    for rank, idx in enumerate(sorted_idx):
        print(f"  {rank+1:2d}. {ANOVA_FEATURE_NAMES[idx]:.<35s} {importances[idx]:.4f}")

    # 7. Export to BPF JSON
    print(f"\n[*] Exporting Random Forest to BPF format...")
    trees_data, total_nodes = export_rf_to_bpf(clf, scale=SCALE)

    model_output = {
        "metadata": {
            "model_type": "RandomForestClassifier",
            "n_trees": len(trees_data),
            "total_nodes": total_nodes,
            "max_depth": MAX_DEPTH,
            "accuracy": round(float(accuracy), 4),
            "cv_accuracy_mean": round(float(cv_scores.mean()), 4),
            "scale": SCALE,
            "feature_names": ANOVA_FEATURE_NAMES,
            "n_features": NUM_FEATURES,
            "training_samples": int(X_train.shape[0]),
            "created_at": pd.Timestamp.now().isoformat(),
        },
        "trees": trees_data,
    }

    with open(OUTPUT_JSON, "w") as f:
        json.dump(model_output, f, indent=2, cls=NumpyEncoder)

    print(f"[✓] RF model exported to {OUTPUT_JSON}")
    print(f"    Trees: {len(trees_data)}, Total nodes: {total_nodes}")
    print(f"    File size: {os.path.getsize(OUTPUT_JSON):,} bytes")

    # 8. Verification
    print(f"\n[*] BPF simulation verification...")

    def bpf_sim_tree(features, tree_nodes, scale):
        node_idx = 0
        for _ in range(MAX_DEPTH + 2):
            if node_idx < 0 or node_idx >= len(tree_nodes):
                return 0
            node = tree_nodes[node_idx]
            if node["is_leaf"]:
                return node["class_id"]
            fidx = node["feature_idx"]
            val_fp = int(features[fidx] * scale)
            if val_fp <= node["threshold"]:
                node_idx = node["left_child"]
            else:
                node_idx = node["right_child"]
        return 0

    def bpf_sim_rf(features, trees, scale):
        votes = [0, 0]
        for tree in trees:
            pred = bpf_sim_tree(features, tree["nodes"], scale)
            votes[pred] += 1
        return 1 if votes[1] > votes[0] else 0

    n_verify = min(500, len(X_test))
    mismatches = 0
    for i in range(n_verify):
        sk_pred = clf.predict(X_test[i:i+1])[0]
        bpf_pred = bpf_sim_rf(X_test[i], trees_data, SCALE)
        if sk_pred != bpf_pred:
            mismatches += 1

    match_rate = (n_verify - mismatches) / n_verify * 100
    print(f"[✓] BPF simulation match rate: {match_rate:.1f}% ({n_verify - mismatches}/{n_verify})")

    if mismatches > 0:
        print(f"[!] {mismatches} mismatches (fixed-point rounding)")

    print(f"\n[✓] Random Forest training complete!")
    print(f"    Next: sudo python ebpf_capture/ebpf_loader.py")


if __name__ == "__main__":
    main()
