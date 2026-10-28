"""
Runtime inference: takes extracted features, returns calibrated probability.

Handles missing model gracefully — returns None instead of crashing.
"""
import time
from typing import Any

import numpy as np
import structlog

logger = structlog.get_logger()


class PhishingInference:
    """Runtime ML inference engine for PhishGuard."""

    def __init__(self, model_bundle: dict[str, Any] | None):
        if model_bundle is None:
            self._model = None
            self._scaler = None
            self._feature_names = []
            self._model_name = "unavailable"
            return

        self._model = model_bundle.get("model")
        self._scaler = model_bundle.get("scaler")
        self._feature_names = model_bundle.get("feature_names", [])
        self._model_name = model_bundle.get("model_name", "phishguard_v1")

    @property
    def is_loaded(self) -> bool:
        """Return True if model and scaler are loaded and ready."""
        return self._model is not None and self._scaler is not None

    def predict(self, features: dict[str, int | float]) -> float | None:
        """
        Return calibrated phishing probability (0.0 to 1.0).

        Returns None if model is unavailable.
        """
        if not self.is_loaded:
            return None

        start = time.perf_counter()

        # Order features to match training order exactly
        feature_vector = np.array(
            [[features.get(name, 0.0) for name in self._feature_names]],
            dtype=float,
        )

        scaled = self._scaler.transform(feature_vector)
        proba = float(self._model.predict_proba(scaled)[0][1])

        latency_ms = (time.perf_counter() - start) * 1000
        logger.debug(
            "ml_inference_completed",
            latency_ms=round(latency_ms, 2),
            probability=round(proba, 4),
            model_name=self._model_name,
        )

        return float(np.clip(proba, 0.0, 1.0))

    def model_info(self) -> dict[str, Any]:
        """Return metadata about current model status."""
        return {
            "loaded": self.is_loaded,
            "model_name": self._model_name,
            "feature_count": len(self._feature_names),
            "feature_names": self._feature_names,
        }
