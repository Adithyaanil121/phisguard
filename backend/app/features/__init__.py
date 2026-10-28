"""Unified feature extraction pipeline."""
from .lexical import extract_lexical_features
from .normalize import validate_and_normalize
from .structural import extract_structural_features

# Deterministic feature order (must match training)
FEATURE_NAMES: list[str] = []


def _ensure_feature_names(sample_features: dict | None = None) -> list[str]:
    global FEATURE_NAMES
    if not FEATURE_NAMES:
        if sample_features is not None:
            FEATURE_NAMES = sorted(sample_features.keys())
        else:
            dummy_lex = extract_lexical_features(
                "http://example.com/",
                {
                    "hostname": "example.com",
                    "path": "/",
                    "query": "",
                    "registered_domain": "example.com",
                    "subdomain": "",
                    "suffix": "com",
                    "scheme": "http",
                    "port": None,
                },
            )
            dummy_struct = extract_structural_features(
                "http://example.com/",
                {
                    "hostname": "example.com",
                    "path": "/",
                    "query": "",
                    "registered_domain": "example.com",
                    "subdomain": "",
                    "suffix": "com",
                    "scheme": "http",
                    "port": None,
                },
            )
            FEATURE_NAMES = sorted({**dummy_lex, **dummy_struct}.keys())
    return FEATURE_NAMES


def extract_all_features(url: str) -> tuple[dict, str, dict]:
    """
    Extract all features from a URL.

    Returns:
        (features_dict, normalized_url, components)
    """
    normalized_url, components = validate_and_normalize(url)
    lexical = extract_lexical_features(normalized_url, components)
    structural = extract_structural_features(normalized_url, components)

    features = {**lexical, **structural}
    _ensure_feature_names(features)

    return features, normalized_url, components


def get_feature_names() -> list[str]:
    """Return the ordered list of feature names."""
    return _ensure_feature_names().copy()


__all__ = [
    "FEATURE_NAMES",
    "extract_all_features",
    "extract_lexical_features",
    "extract_structural_features",
    "get_feature_names",
    "validate_and_normalize",
]
