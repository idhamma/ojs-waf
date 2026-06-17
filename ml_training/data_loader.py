"""
Loader for the real captured OJS dataset (labeled CSV files).

Unlike the older `merge.csv` path — which collapsed the 31/33-column captures
down to an 11-column canonical schema, neutralised `source_ip`/`headers_raw`,
and deduplicated — this loader reads the labeled files *directly* and keeps
their full column set. Leakage is handled downstream by training on the
reduced feature subset (`REALDATA_FEATURE_NAMES`) instead of by destroying
columns here, so nothing is silently thrown away.

Pipeline
--------
    labeled/*.csv ──▶ load_labeled_dataset() ──▶ canonical DataFrame
                                                 (timestamp, source_ip, method,
                                                  uri, query_string,
                                                  body_truncated, headers_raw,
                                                  decision, attack_type)

The canonical columns are exactly what `train_pipeline.build_feature_matrix`
consumes, so the 60-second-per-IP `req_rate` window matches runtime behaviour.

CLI
---
    python -m ml_training.data_loader            # print a summary of the merge
"""

from __future__ import annotations

from pathlib import Path
from typing import List

import pandas as pd

PROJECT_DIR = Path(__file__).resolve().parent.parent
LABELED_DIR = PROJECT_DIR / "ml_training" / "data_train" / "labeled"

# Source labeled files to combine (merge.csv is intentionally excluded).
DEFAULT_SOURCE_FILES: List[str] = [
    "12-06-2026_labeled_1.csv",   # RCE + Normal
    "12-06-2026_labeled_2.csv",   # XSS + Normal
    "normal_labeled.csv",         # Normal only
    "route_matched_benign.csv",   # Benign traffic on the SAME routes as attacks
                                  # (overfitting fix #1; see benign_augment.py)
]

# Columns the feature matrix builder needs. Anything missing is back-filled
# with an empty string so the extractor sees a stable schema.
CANONICAL_COLUMNS: List[str] = [
    "timestamp", "source_ip", "method", "uri", "query_string",
    "body_truncated", "headers_raw", "decision", "attack_type",
]

# Dedup key: two requests are "the same payload" when these match.
DEDUP_SUBSET: List[str] = ["method", "uri", "query_string", "body_truncated"]

# Raw label string -> (attack_type, decision). Case-insensitive.
_LABEL_MAP = {
    "rce": ("RCE", "BLOCK"),
    "xss": ("XSS", "BLOCK"),
    "normal": ("NONE", "PASS"),
    "benign": ("NONE", "PASS"),
}


def _normalize_label(raw: str) -> tuple[str, str]:
    """Map a raw label to (attack_type, decision); unknown -> treated as attack."""
    key = str(raw).strip().lower()
    if key in _LABEL_MAP:
        return _LABEL_MAP[key]
    # Unknown, non-empty label: be conservative and treat as a (typed) attack.
    return (str(raw).strip().upper(), "BLOCK")


def load_labeled_dataset(
    labeled_dir: Path = LABELED_DIR,
    source_files: List[str] | None = None,
    deduplicate: bool = True,
) -> pd.DataFrame:
    """Read and combine the labeled capture files into a canonical DataFrame.

    Parameters
    ----------
    labeled_dir : directory holding the labeled CSVs.
    source_files : file names to combine (defaults to the three captures).
    deduplicate : drop rows with identical (method, uri, query, body) so the
        same payload cannot land in both the train and test split.
    """
    files = source_files if source_files is not None else DEFAULT_SOURCE_FILES
    frames: List[pd.DataFrame] = []

    for name in files:
        path = labeled_dir / name
        if not path.exists():
            raise FileNotFoundError(f"Labeled source not found: {path}")
        df = pd.read_csv(path, dtype=str, keep_default_na=False, on_bad_lines="skip")
        df.columns = [str(c).strip() for c in df.columns]

        if "label" not in df.columns:
            raise ValueError(f"{name}: missing required 'label' column")

        mapped = df["label"].map(_normalize_label)
        df["attack_type"] = mapped.map(lambda t: t[0])
        df["decision"] = mapped.map(lambda t: t[1])
        df["origin_file"] = name
        frames.append(df)

    combined = pd.concat(frames, ignore_index=True, sort=False)

    # Guarantee every canonical column exists; back-fill missing ones.
    for col in CANONICAL_COLUMNS:
        if col not in combined.columns:
            combined[col] = ""
    combined[CANONICAL_COLUMNS] = combined[CANONICAL_COLUMNS].fillna("")

    # The captures store some fields with surrounding whitespace (e.g. the
    # method column holds "POST  "). Left unstripped, "POST  ".upper() != "POST"
    # in the feature extractor, so method_get/method_post would be 0 in training
    # but 1 at runtime — a silent train/serve skew. Strip the short structured
    # fields; the body is left intact so payload bytes are preserved.
    for col in ("method", "uri", "query_string", "source_ip", "decision",
                "attack_type", "timestamp"):
        if col in combined.columns:
            combined[col] = combined[col].astype(str).str.strip()

    if deduplicate:
        before = len(combined)
        combined = combined.drop_duplicates(subset=DEDUP_SUBSET).reset_index(drop=True)
        combined.attrs["dropped_duplicates"] = before - len(combined)
    else:
        combined.attrs["dropped_duplicates"] = 0

    return combined


def summarize(df: pd.DataFrame) -> dict:
    """Return a compact distribution summary for logging / sanity checks."""
    return {
        "rows": int(len(df)),
        "dropped_duplicates": int(df.attrs.get("dropped_duplicates", 0)),
        "attack_type": df["attack_type"].value_counts().to_dict(),
        "decision": df["decision"].value_counts().to_dict(),
        "by_origin": df["origin_file"].value_counts().to_dict()
        if "origin_file" in df.columns else {},
    }


def main() -> None:
    import json

    df = load_labeled_dataset()
    print(json.dumps(summarize(df), indent=2))


if __name__ == "__main__":
    main()
