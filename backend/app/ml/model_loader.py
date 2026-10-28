"""Model loading — stub for Phase 0. Full implementation in Phase 2."""
import os

import joblib


def load_model(model_path: str):
    """
    Attempt to load a trained model.
    Raises FileNotFoundError if the model file doesn't exist.
    """
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model file not found: {model_path}")
    return joblib.load(model_path)
