"""Model loading and inference engine factory."""
import os
from typing import Any

import joblib
import structlog

from .inference import PhishingInference

logger = structlog.get_logger()


def load_model(model_path: str) -> PhishingInference:
    """
    Load a trained model bundle and return a PhishingInference instance.

    Raises FileNotFoundError if the file does not exist.
    """
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model file not found: {model_path}")

    bundle: dict[str, Any] = joblib.load(model_path)
    return PhishingInference(bundle)
