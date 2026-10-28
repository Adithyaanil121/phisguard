"""
Lexical features extracted from the URL string alone.

No network requests. All features are numeric (int or float).
Uses tldextract from the normalizer output for accurate subdomain
counting (handles multi-part suffixes like .co.uk).
"""
import math
import re
from collections import Counter
from urllib.parse import parse_qs

# Known URL shortener domains (weak risk signal, not a verdict)
KNOWN_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "bl.ink",
    "short.io",
    "cutt.ly",
}

# TLDs disproportionately used in phishing (free registration, minimal oversight)
HIGH_RISK_TLDS = {
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "top",
    "xyz",
    "buzz",
    "club",
    "work",
    "info",
    "online",
    "site",
    "icu",
}


def shannon_entropy(s: str) -> float:
    """Compute the Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def extract_lexical_features(url: str, components: dict) -> dict[str, int | float]:
    """
    Extract lexical features from a URL.

    Args:
        url: The normalized URL string.
        components: Parsed components from validate_and_normalize().

    Returns:
        Dict of feature_name -> numeric value (int or float).
    """
    hostname = components.get("hostname", "") or ""
    path = components.get("path", "") or ""
    query = components.get("query", "") or ""
    registered_domain = (components.get("registered_domain") or "").lower()
    subdomain = components.get("subdomain", "") or ""
    suffix = (components.get("suffix") or "").lower()

    # Count subdomains using tldextract output (accurate for .co.uk etc.)
    subdomain_count = len(subdomain.split(".")) if subdomain else 0

    return {
        # Length features
        "url_length": len(url),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "query_length": len(query),
        # Character distribution
        "digit_ratio": sum(c.isdigit() for c in url) / max(len(url), 1),
        "special_char_count": sum(
            1 for c in url if c in "@!#$%^&*()+={}[]|\\:;\"'<>,?"
        ),
        "dot_count_hostname": hostname.count("."),
        "hyphen_count_hostname": hostname.count("-"),
        "slash_count_path": path.count("/"),
        # Structure
        "subdomain_count": subdomain_count,
        "path_depth": path.strip("/").count("/") + 1 if path.strip("/") else 0,
        "query_param_count": len(parse_qs(query)) if query else 0,
        # Entropy
        "hostname_entropy": round(shannon_entropy(hostname), 4),
        "url_entropy": round(shannon_entropy(url), 4),
        # Binary indicators
        "is_ip_address": int(bool(components.get("is_ip_address", False))),
        "has_at_symbol": int("@" in url),
        "has_non_standard_port": int(
            components.get("port") is not None
            and components.get("port") not in (80, 443)
        ),
        "is_https": int(components.get("scheme") == "https"),
        "has_double_slash_in_path": int("//" in path),
        "has_credentials": int(bool(components.get("has_credentials", False))),
        # Shortener detection (weak signal, not a verdict)
        "is_known_shortener": int(registered_domain in KNOWN_SHORTENERS),
        # TLD risk (informational, not deterministic)
        "tld_risk_score": int(suffix in HIGH_RISK_TLDS),
        # Encoding signals
        "punycode_detected": int("xn--" in hostname.lower()),
        "has_base64_pattern": int(
            bool(re.search(r"[A-Za-z0-9+/]{20,}={0,2}", url))
        ),
    }
