"""
Unit tests for runtime ML inference engine (Ticket 2.6).

Tests:
- Missing model handling (graceful degradation)
- Feature vector alignment with training feature names
- Mock model prediction and latency (< 10ms)
- Real trained model loading and prediction
"""
import time
from pathlib import Path
from unittest.mock import MagicMock

import numpy as np
import pytest

from backend.app.ml.inference import PhishingInference
from backend.app.ml.model_loader import load_model


class TestPhishingInferenceGracefulDegradation:
    def test_none_bundle(self):
        engine = PhishingInference(None)
        assert not engine.is_loaded
        assert engine.predict({"url_length": 25}) is None
        info = engine.model_info()
        assert not info["loaded"]
        assert info["feature_count"] == 0

    def test_missing_components_in_bundle(self):
        engine = PhishingInference({"model": None, "scaler": None, "feature_names": []})
        assert not engine.is_loaded
        assert engine.predict({"url_length": 25}) is None


class TestPhishingInferenceWithMock:
    @pytest.fixture()
    def mock_engine(self):
        mock_model = MagicMock()
        mock_model.predict_proba.return_value = np.array([[0.08, 0.92]])

        mock_scaler = MagicMock()
        mock_scaler.transform.side_effect = lambda x: x

        bundle = {
            "model": mock_model,
            "scaler": mock_scaler,
            "feature_names": ["feat_a", "feat_b", "feat_c"],
            "model_name": "mock_rf",
        }
        return PhishingInference(bundle)

    def test_predict_returns_calibrated_float(self, mock_engine):
        result = mock_engine.predict({"feat_a": 1, "feat_b": 2, "feat_c": 3})
        assert isinstance(result, float)
        assert pytest.approx(result, rel=1e-3) == 0.92

    def test_feature_ordering_matches_feature_names(self, mock_engine):
        # Pass features in arbitrary order
        mock_engine.predict({"feat_c": 30, "feat_a": 10, "feat_b": 20})

        # Scaler should receive [[10.0, 20.0, 30.0]]
        args, _ = mock_engine._scaler.transform.call_args
        passed_matrix = args[0]
        np.testing.assert_array_equal(passed_matrix, [[10.0, 20.0, 30.0]])

    def test_missing_features_default_to_zero(self, mock_engine):
        # Omit feat_b
        mock_engine.predict({"feat_a": 5, "feat_c": 15})
        args, _ = mock_engine._scaler.transform.call_args
        np.testing.assert_array_equal(args[0], [[5.0, 0.0, 15.0]])

    def test_predict_latency_under_10ms(self, mock_engine):
        t0 = time.perf_counter()
        for _ in range(50):
            mock_engine.predict({"feat_a": 1, "feat_b": 2, "feat_c": 3})
        elapsed_avg_ms = ((time.perf_counter() - t0) / 50) * 1000
        assert elapsed_avg_ms < 10.0, f"Average latency too high: {elapsed_avg_ms:.2f}ms"


class TestRealModelInference:
    def test_load_real_trained_model(self):
        model_path = Path("models/phishguard_v1.joblib")
        if not model_path.exists():
            pytest.skip("models/phishguard_v1.joblib does not exist yet")

        engine = load_model(str(model_path))
        assert engine.is_loaded

        info = engine.model_info()
        assert info["loaded"]
        assert info["feature_count"] > 20

        # Predict on synthetic benign-looking features
        benign_feats = {name: 0 for name in info["feature_names"]}
        benign_feats["is_https"] = 1
        benign_feats["url_length"] = 22
        benign_feats["hostname_length"] = 11

        prob = engine.predict(benign_feats)
        assert isinstance(prob, float)
        assert 0.0 <= prob <= 1.0

    def test_load_nonexistent_model_raises_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            load_model("models/nonexistent_model_xyz.joblib")
