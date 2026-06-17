"""
Invariant tests for the real-dataset training path.

These assert *structure*, not accuracy: feature-subset integrity, the 33->22
projection, dedup, and label mapping. They are fast (no full model fit on the
whole dataset) and protect the train/serve parity contract.
"""

from __future__ import annotations

import numpy as np
import pytest

from ml_training.data_loader import (
    DEDUP_SUBSET,
    load_labeled_dataset,
)
from ml_training.features import (
    DROPPED_FEATURE_NAMES,
    FEATURE_NAMES,
    NUM_FEATURES,
    NUM_REALDATA_FEATURES,
    REALDATA_FEATURE_NAMES,
    selected_feature_indices,
)
from ml_training.train_on_real import REALDATA_ATTACK_TYPES, project


# ---------------------------------------------------------------------------
# Feature-subset invariants
# ---------------------------------------------------------------------------

class TestFeatureSubset:
    def test_subset_size(self):
        assert NUM_REALDATA_FEATURES == 22
        assert len(REALDATA_FEATURE_NAMES) == 22

    def test_selected_and_dropped_partition_full_set(self):
        # Every full feature is either selected or dropped, with no overlap.
        selected = set(REALDATA_FEATURE_NAMES)
        dropped = set(DROPPED_FEATURE_NAMES)
        assert selected.isdisjoint(dropped)
        assert selected | dropped == set(FEATURE_NAMES)
        assert len(selected) + len(dropped) == NUM_FEATURES

    def test_sqli_and_leakage_features_dropped(self):
        for name in (
            "sql_keyword_count", "sql_metachar_count", "sql_tautology",
            "sql_time_based", "path_traversal_count", "command_inj_count",
            "req_rate", "bot_user_agent", "user_agent_length",
            "missing_user_agent", "missing_host_header",
        ):
            assert name not in REALDATA_FEATURE_NAMES
            assert name in DROPPED_FEATURE_NAMES

    def test_xss_and_route_features_kept(self):
        for name in ("xss_pattern_count", "encoded_attack_markers",
                     "ojs_page_code", "ojs_op_code", "has_ojs_ajax",
                     "body_len", "body_non_ascii_ratio"):
            assert name in REALDATA_FEATURE_NAMES

    def test_indices_map_back_to_names(self):
        idx = selected_feature_indices(REALDATA_FEATURE_NAMES)
        assert len(idx) == NUM_REALDATA_FEATURES
        assert [FEATURE_NAMES[i] for i in idx] == REALDATA_FEATURE_NAMES

    def test_unknown_feature_raises(self):
        with pytest.raises(KeyError):
            selected_feature_indices(["not_a_real_feature"])


class TestProjection:
    def test_project_shape(self):
        rng = np.random.default_rng(0)
        X_full = rng.random((10, NUM_FEATURES))
        idx = selected_feature_indices(REALDATA_FEATURE_NAMES)
        X = project(X_full, idx)
        assert X.shape == (10, NUM_REALDATA_FEATURES)

    def test_project_preserves_values(self):
        X_full = np.arange(NUM_FEATURES, dtype=float).reshape(1, -1)
        idx = selected_feature_indices(REALDATA_FEATURE_NAMES)
        X = project(X_full, idx)
        assert list(X[0]) == [float(i) for i in idx]


# ---------------------------------------------------------------------------
# Dataset / loader invariants
# ---------------------------------------------------------------------------

class TestLoader:
    @classmethod
    def setup_class(cls):
        cls.df = load_labeled_dataset(deduplicate=True)

    def test_canonical_columns_present(self):
        for col in ("timestamp", "source_ip", "method", "uri", "query_string",
                    "body_truncated", "headers_raw", "decision", "attack_type"):
            assert col in self.df.columns

    def test_only_expected_attack_types(self):
        assert set(self.df["attack_type"].unique()) <= {"RCE", "XSS", "NONE"}

    def test_decision_maps_to_binary(self):
        assert set(self.df["decision"].unique()) <= {"BLOCK", "PASS"}
        # BLOCK iff attack, PASS iff NONE
        blocked = self.df[self.df["decision"] == "BLOCK"]["attack_type"]
        passed = self.df[self.df["decision"] == "PASS"]["attack_type"]
        assert (blocked != "NONE").all()
        assert (passed == "NONE").all()

    def test_no_duplicate_payloads(self):
        dups = self.df.duplicated(subset=DEDUP_SUBSET).sum()
        assert dups == 0

    def test_method_has_no_surrounding_whitespace(self):
        methods = self.df["method"].tolist()
        assert all(m == m.strip() for m in methods)

    def test_attack_types_constant_matches_data(self):
        # The model bundle claims exactly the families present in the data.
        present = {t for t in self.df["attack_type"].unique() if t != "NONE"}
        assert set(REALDATA_ATTACK_TYPES) == present
