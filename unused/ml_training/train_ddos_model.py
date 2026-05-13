"""
DDoS Detection Model Trainer — Decision Tree for eBPF In-Kernel Inference

Trains a shallow Decision Tree on CIC-IDS-2017-style flow features and exports
the tree structure as a JSON array of nodes that can be loaded into BPF maps
by the eBPF loader for real-time DDoS detection at XDP level.

15 CIC-IDS-2017 Flow Features (all scaled ×1000 for fixed-point BPF):
  0: Flow Duration (ms)
  1: Total Fwd Packets
  2: Total Bwd Packets
  3: Total Length Fwd Packets (bytes)
  4: Total Length Bwd Packets (bytes)
  5: Fwd Packet Length Mean (bytes)
  6: Bwd Packet Length Mean (bytes)
  7: Flow Bytes/s
  8: Flow Packets/s
  9: Flow IAT Mean (ms)
  10: Min Packet Length (bytes)
  11: Max Packet Length (bytes)
  12: FIN Flag Count (0 or 1)
  13: SYN Flag Count (0 or 1)
  14: RST Flag Count (0 or 1)
"""

import os
import sys
import json
import numpy as np
import pandas as pd
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix


class NumpyEncoder(json.JSONEncoder):
    """Custom JSON encoder that handles numpy types."""
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

print("=" * 56)
print("  DDoS Detection Model Trainer (Decision Tree → eBPF)")
print("=" * 56)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Fixed-point scale factor (must match capture_https.c SCALE)
SCALE = 1000

# Maximum tree depth (must fit within BPF verifier loop and 512-node array)
MAX_DEPTH = 8

# Output paths
MODEL_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_JSON = os.path.join(MODEL_DIR, "dt_model_ebpf.json")

# CIC-IDS-2017 feature names (matching kernel extraction order)
FEATURE_NAMES = [
    "flow_duration_ms",
    "total_fwd_packets",
    "total_bwd_packets",
    "total_length_fwd",
    "total_length_bwd",
    "fwd_packet_length_mean",
    "bwd_packet_length_mean",
    "flow_bytes_per_sec",
    "flow_packets_per_sec",
    "flow_iat_mean_ms",
    "min_packet_length",
    "max_packet_length",
    "fin_flag_count",
    "syn_flag_count",
    "rst_flag_count",
]

# ---------------------------------------------------------------------------
# Dataset loading
# ---------------------------------------------------------------------------

def load_cicids_csv(csv_path):
    """
    Load CIC-IDS-2017 CSV and map columns to our 15 features.
    Handles both the original CIC-IDS-2017 format and custom CSV formats.
    """
    print(f"[*] Loading dataset from {csv_path}...")
    df = pd.read_csv(csv_path, low_memory=False)

    # Strip whitespace from column names (CIC-IDS-2017 has leading spaces)
    df.columns = df.columns.str.strip()

    print(f"[*] Dataset shape: {df.shape}")
    print(f"[*] Columns: {list(df.columns[:10])}...")

    # Map CIC-IDS-2017 column names to our feature indices
    column_mapping = {
        "Flow Duration": "flow_duration_ms",
        "Total Fwd Packets": "total_fwd_packets",
        "Total Backward Packets": "total_bwd_packets",
        "Total Length of Fwd Packets": "total_length_fwd",
        "Total Length of Bwd Packets": "total_length_bwd",
        "Fwd Packet Length Mean": "fwd_packet_length_mean",
        "Bwd Packet Length Mean": "bwd_packet_length_mean",
        "Flow Bytes/s": "flow_bytes_per_sec",
        "Flow Packets/s": "flow_packets_per_sec",
        "Flow IAT Mean": "flow_iat_mean_ms",
        "Min Packet Length": "min_packet_length",
        "Max Packet Length": "max_packet_length",
        "FIN Flag Count": "fin_flag_count",
        "SYN Flag Count": "syn_flag_count",
        "RST Flag Count": "rst_flag_count",
    }

    # Check which columns exist
    mapped = {}
    for orig_col, feat_name in column_mapping.items():
        if orig_col in df.columns:
            mapped[feat_name] = df[orig_col]

    if len(mapped) < 10:
        print(f"[!] Only {len(mapped)}/15 features found in CSV.")
        print(f"[!] Available columns: {list(df.columns)}")
        return None, None

    features_df = pd.DataFrame(mapped)

    # Handle label column
    label_col = None
    for candidate in ["Label", "label", " Label"]:
        if candidate in df.columns:
            label_col = candidate
            break

    if label_col is None:
        print("[!] No 'Label' column found in dataset.")
        return None, None

    # Binary classification: BENIGN=0, everything else (DDoS, etc)=1
    labels = df[label_col].str.strip()
    y = (labels != "BENIGN").astype(int)

    print(f"[*] Label distribution:")
    print(f"    BENIGN (0): {(y == 0).sum():,}")
    print(f"    ATTACK (1): {(y == 1).sum():,}")

    # Clean: replace inf/nan
    features_df = features_df.replace([np.inf, -np.inf], np.nan)
    features_df = features_df.fillna(0)

    # Ensure all columns present
    for feat in FEATURE_NAMES:
        if feat not in features_df.columns:
            features_df[feat] = 0

    X = features_df[FEATURE_NAMES].values.astype(np.float64)
    return X, y.values


def generate_synthetic_ddos_dataset():
    """
    Generate a synthetic dataset simulating DDoS and normal HTTP traffic.
    Used when CIC-IDS-2017 CSV is not available for initial development.
    """
    print("[*] Generating synthetic DDoS dataset...")
    np.random.seed(42)
    data = []

    # ----- NORMAL HTTP TRAFFIC -----
    for _ in range(5000):
        data.append({
            "flow_duration_ms": np.random.uniform(100, 30000),     # 100ms - 30s
            "total_fwd_packets": np.random.randint(1, 20),
            "total_bwd_packets": np.random.randint(1, 25),
            "total_length_fwd": np.random.uniform(100, 5000),
            "total_length_bwd": np.random.uniform(200, 50000),     # responses are larger
            "fwd_packet_length_mean": np.random.uniform(50, 500),
            "bwd_packet_length_mean": np.random.uniform(100, 2000),
            "flow_bytes_per_sec": np.random.uniform(100, 50000),
            "flow_packets_per_sec": np.random.uniform(0.5, 50),
            "flow_iat_mean_ms": np.random.uniform(10, 5000),       # 10ms - 5s IAT
            "min_packet_length": np.random.randint(40, 100),
            "max_packet_length": np.random.randint(500, 1500),
            "fin_flag_count": np.random.choice([0, 1], p=[0.3, 0.7]),
            "syn_flag_count": 1,                                    # normal SYN handshake
            "rst_flag_count": np.random.choice([0, 1], p=[0.9, 0.1]),
            "label": 0,
        })

    # ----- DDoS: SYN FLOOD -----
    for _ in range(1500):
        data.append({
            "flow_duration_ms": np.random.uniform(1, 500),          # very short flows
            "total_fwd_packets": np.random.randint(1, 3),           # just SYN packets
            "total_bwd_packets": np.random.randint(0, 1),           # no response
            "total_length_fwd": np.random.uniform(40, 80),          # tiny packets
            "total_length_bwd": np.random.uniform(0, 40),
            "fwd_packet_length_mean": np.random.uniform(40, 80),
            "bwd_packet_length_mean": np.random.uniform(0, 40),
            "flow_bytes_per_sec": np.random.uniform(50000, 500000), # high rate
            "flow_packets_per_sec": np.random.uniform(500, 10000),  # very high PPS
            "flow_iat_mean_ms": np.random.uniform(0.01, 2),         # sub-ms IAT
            "min_packet_length": np.random.randint(40, 60),
            "max_packet_length": np.random.randint(60, 80),
            "fin_flag_count": 0,                                     # no FIN (incomplete)
            "syn_flag_count": 1,                                     # SYN flood
            "rst_flag_count": np.random.choice([0, 1], p=[0.5, 0.5]),
            "label": 1,
        })

    # ----- DDoS: HTTP FLOOD -----
    for _ in range(1500):
        data.append({
            "flow_duration_ms": np.random.uniform(10, 2000),
            "total_fwd_packets": np.random.randint(50, 500),        # many requests
            "total_bwd_packets": np.random.randint(0, 10),          # ignores responses
            "total_length_fwd": np.random.uniform(5000, 100000),
            "total_length_bwd": np.random.uniform(0, 1000),
            "fwd_packet_length_mean": np.random.uniform(60, 200),
            "bwd_packet_length_mean": np.random.uniform(0, 100),
            "flow_bytes_per_sec": np.random.uniform(100000, 1000000),
            "flow_packets_per_sec": np.random.uniform(100, 5000),
            "flow_iat_mean_ms": np.random.uniform(0.1, 10),
            "min_packet_length": np.random.randint(40, 60),
            "max_packet_length": np.random.randint(150, 300),
            "fin_flag_count": 0,
            "syn_flag_count": 1,
            "rst_flag_count": 0,
            "label": 1,
        })

    # ----- DDoS: VOLUMETRIC FLOOD -----
    for _ in range(1000):
        data.append({
            "flow_duration_ms": np.random.uniform(50, 5000),
            "total_fwd_packets": np.random.randint(100, 1000),
            "total_bwd_packets": np.random.randint(0, 5),
            "total_length_fwd": np.random.uniform(100000, 1000000), # massive volume
            "total_length_bwd": np.random.uniform(0, 500),
            "fwd_packet_length_mean": np.random.uniform(800, 1500),
            "bwd_packet_length_mean": np.random.uniform(0, 100),
            "flow_bytes_per_sec": np.random.uniform(500000, 5000000),
            "flow_packets_per_sec": np.random.uniform(200, 3000),
            "flow_iat_mean_ms": np.random.uniform(0.05, 5),
            "min_packet_length": np.random.randint(500, 800),
            "max_packet_length": np.random.randint(1200, 1500),
            "fin_flag_count": 0,
            "syn_flag_count": np.random.choice([0, 1]),
            "rst_flag_count": np.random.choice([0, 1], p=[0.7, 0.3]),
            "label": 1,
        })

    # ----- DDoS: SLOW LORIS -----
    for _ in range(1000):
        data.append({
            "flow_duration_ms": np.random.uniform(30000, 120000),   # very long flows
            "total_fwd_packets": np.random.randint(50, 200),
            "total_bwd_packets": np.random.randint(0, 5),
            "total_length_fwd": np.random.uniform(100, 2000),       # tiny payloads
            "total_length_bwd": np.random.uniform(0, 500),
            "fwd_packet_length_mean": np.random.uniform(1, 20),     # 1-byte payloads
            "bwd_packet_length_mean": np.random.uniform(0, 100),
            "flow_bytes_per_sec": np.random.uniform(1, 100),        # very low throughput
            "flow_packets_per_sec": np.random.uniform(0.5, 5),
            "flow_iat_mean_ms": np.random.uniform(5000, 30000),     # huge IAT (slow)
            "min_packet_length": np.random.randint(40, 50),
            "max_packet_length": np.random.randint(50, 100),
            "fin_flag_count": 0,                                     # never completes
            "syn_flag_count": 1,
            "rst_flag_count": 0,
            "label": 1,
        })

    df = pd.DataFrame(data)
    print(f"[*] Generated {len(df)} samples:")
    print(f"    BENIGN: {(df['label'] == 0).sum()}")
    print(f"    ATTACK: {(df['label'] == 1).sum()}")

    X = df[FEATURE_NAMES].values
    y = df["label"].values
    return X, y


# ---------------------------------------------------------------------------
# Decision Tree → BPF Nodes Export
# ---------------------------------------------------------------------------

def export_tree_to_bpf_nodes(clf, scale=SCALE):
    """
    Convert a trained sklearn DecisionTreeClassifier into a flat array
    of node dicts suitable for loading into BPF_ARRAY map.

    Each node: {
        "feature_idx": int,   # 0-14
        "is_leaf": bool,
        "class_id": int,      # 0=BENIGN, 1=ATTACK (leaf only)
        "left_child": int,    # index in array
        "right_child": int,   # index in array
        "threshold": int,     # fixed-point (value × scale)
    }
    """
    tree = clf.tree_
    n_nodes = tree.node_count

    if n_nodes > 512:
        print(f"[!] WARNING: Tree has {n_nodes} nodes, BPF map max is 512.")
        print(f"[!] Consider reducing max_depth (currently {clf.max_depth}).")

    nodes = []
    for i in range(n_nodes):
        is_leaf = (tree.children_left[i] == -1)

        if is_leaf:
            # Leaf node: determine class from value array
            # tree.value[i] = [[count_class_0, count_class_1]]
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
            # Internal node
            feature_idx = int(tree.feature[i])
            threshold_raw = float(tree.threshold[i])

            # Convert to fixed-point: threshold × SCALE
            # The kernel features are also × SCALE, so comparison works directly
            threshold_fp = int(threshold_raw * scale)

            nodes.append({
                "feature_idx": feature_idx,
                "is_leaf": False,
                "class_id": 0,
                "left_child": int(tree.children_left[i]),
                "right_child": int(tree.children_right[i]),
                "threshold": threshold_fp,
            })

    return nodes


# ---------------------------------------------------------------------------
# Main Training Pipeline
# ---------------------------------------------------------------------------

def main():
    # ---- 1. Load or generate dataset ----

    # Check for CIC-IDS-2017 CSV files in dataset directory
    dataset_dir = os.path.join(os.path.dirname(MODEL_DIR), "dataset")
    cicids_files = []

    # Look for CSV files in common locations
    search_paths = [
        os.path.join(dataset_dir, "features"),
        os.path.join(dataset_dir, "raw"),
        dataset_dir,
    ]

    for search_dir in search_paths:
        if os.path.isdir(search_dir):
            for f in os.listdir(search_dir):
                if f.endswith(".csv") and "ddos" in f.lower():
                    cicids_files.append(os.path.join(search_dir, f))

    X, y = None, None

    if cicids_files:
        print(f"[*] Found {len(cicids_files)} DDoS CSV files:")
        for f in cicids_files:
            print(f"    - {f}")

        # Load and concatenate all CSV files
        X_parts, y_parts = [], []
        for csv_path in cicids_files:
            Xi, yi = load_cicids_csv(csv_path)
            if Xi is not None:
                X_parts.append(Xi)
                y_parts.append(yi)

        if X_parts:
            X = np.vstack(X_parts)
            y = np.concatenate(y_parts)
    else:
        print("[*] No CIC-IDS-2017 CSV found, using synthetic dataset.")
        print(f"    (Place DDoS CSV files in {os.path.join(dataset_dir, 'features')}/)")

    if X is None:
        X, y = generate_synthetic_ddos_dataset()

    # ---- 2. Clean data ----
    print(f"\n[*] Dataset: {X.shape[0]} samples, {X.shape[1]} features")

    # Replace inf/nan
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

    # ---- 3. Train/Test Split ----
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"[*] Train: {X_train.shape[0]}, Test: {X_test.shape[0]}")

    # ---- 4. Train Decision Tree ----
    print(f"\n[*] Training Decision Tree (max_depth={MAX_DEPTH})...")
    clf = DecisionTreeClassifier(
        max_depth=MAX_DEPTH,
        min_samples_split=10,
        min_samples_leaf=5,
        class_weight="balanced",  # Handle imbalanced datasets
        random_state=42,
    )
    clf.fit(X_train, y_train)

    n_nodes = clf.tree_.node_count
    n_leaves = clf.tree_.n_leaves
    actual_depth = clf.tree_.max_depth
    print(f"[✓] Tree trained: {n_nodes} nodes, {n_leaves} leaves, depth={actual_depth}")

    # ---- 5. Evaluate ----
    y_pred = clf.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)

    print(f"\n--- Model Evaluation ---")
    print(f"Accuracy: {accuracy * 100:.2f}%")
    print(f"\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["BENIGN", "DDOS"]))

    print("Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"  TN={cm[0][0]:5d}  FP={cm[0][1]:5d}")
    print(f"  FN={cm[1][0]:5d}  TP={cm[1][1]:5d}")

    # Cross-validation
    cv_scores = cross_val_score(clf, X, y, cv=5, scoring="accuracy")
    print(f"\nCross-Validation (5-fold): {cv_scores.mean()*100:.2f}% ± {cv_scores.std()*100:.2f}%")

    # Feature importance
    print(f"\nFeature Importance (top 10):")
    importances = clf.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    for rank, idx in enumerate(sorted_idx[:10]):
        print(f"  {rank+1}. {FEATURE_NAMES[idx]:.<35s} {importances[idx]:.4f}")

    # ---- 6. Export to BPF-compatible JSON ----
    print(f"\n[*] Exporting Decision Tree to BPF format...")
    nodes = export_tree_to_bpf_nodes(clf, scale=SCALE)

    model_output = {
        "metadata": {
            "model_type": "DecisionTreeClassifier",
            "max_depth": int(actual_depth),
            "n_nodes": int(n_nodes),
            "n_leaves": int(n_leaves),
            "accuracy": round(float(accuracy), 4),
            "cv_accuracy_mean": round(float(cv_scores.mean()), 4),
            "scale": SCALE,
            "feature_names": FEATURE_NAMES,
            "n_features": len(FEATURE_NAMES),
            "training_samples": int(X_train.shape[0]),
            "created_at": pd.Timestamp.now().isoformat(),
            "max_tree_depth_bpf": MAX_DEPTH,
        },
        "nodes": nodes,
    }

    with open(OUTPUT_JSON, "w") as f:
        json.dump(model_output, f, indent=2, cls=NumpyEncoder)

    print(f"[✓] Model exported to {OUTPUT_JSON}")
    print(f"    Nodes: {len(nodes)}")
    print(f"    File size: {os.path.getsize(OUTPUT_JSON):,} bytes")
    print(f"    Scale factor: ×{SCALE}")

    # ---- 7. Verification ----
    print(f"\n[*] Verification: Re-running inference on test set with exported nodes...")

    def bpf_simulate_classify(features, nodes, scale):
        """Simulate BPF dt_classify using exported nodes (Python verification)."""
        node_idx = 0
        for _ in range(MAX_DEPTH + 1):
            node = nodes[node_idx]
            if node["is_leaf"]:
                return node["class_id"]

            fidx = node["feature_idx"]
            val_fp = int(features[fidx] * scale)  # simulate fixed-point

            if val_fp <= node["threshold"]:
                node_idx = node["left_child"]
            else:
                node_idx = node["right_child"]

            if node_idx < 0 or node_idx >= len(nodes):
                return 0
        return 0

    # Verify a sample of predictions match
    n_verify = min(200, len(X_test))
    mismatches = 0
    for i in range(n_verify):
        sklearn_pred = clf.predict(X_test[i:i+1])[0]
        bpf_pred = bpf_simulate_classify(X_test[i], nodes, SCALE)
        if sklearn_pred != bpf_pred:
            mismatches += 1

    match_rate = (n_verify - mismatches) / n_verify * 100
    print(f"[✓] BPF simulation match rate: {match_rate:.1f}% ({n_verify - mismatches}/{n_verify})")

    if mismatches > 0:
        print(f"[!] {mismatches} mismatches due to fixed-point rounding — acceptable if < 5%")

    print(f"\n[✓] DDoS model training complete!")
    print(f"    Next: Run `sudo python ebpf_capture/ebpf_loader.py` to load into kernel.")


if __name__ == "__main__":
    main()
