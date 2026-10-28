"""
Structural features: higher-level patterns that require domain
knowledge about phishing techniques.

All features return numeric values (int), never bool or None.
"""

SUSPICIOUS_TOKENS = [
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "confirm",
    "banking",
    "signin",
    "password",
    "credential",
    "suspend",
    "unusual",
    "authenticate",
    "wallet",
]

# Brands and their legitimate domains (for mismatch detection)
BRAND_DOMAINS: dict[str, set[str]] = {
    "paypal": {"paypal.com", "paypal.me"},
    "microsoft": {"microsoft.com", "live.com", "outlook.com", "office.com"},
    "apple": {"apple.com", "icloud.com"},
    "google": {"google.com", "gmail.com", "youtube.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "aws.amazon.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "twitter": {"twitter.com", "x.com"},
    "linkedin": {"linkedin.com"},
}


def extract_structural_features(url: str, components: dict) -> dict[str, int]:
    """
    Extract structural features based on phishing patterns.

    Args:
        url: The normalized URL string.
        components: Parsed components from validate_and_normalize().

    Returns:
        Dict of feature_name -> int.
    """
    url_lower = url.lower()
    registered_domain = (components.get("registered_domain") or "").lower()
    subdomain = (components.get("subdomain") or "").lower()

    # Suspicious tokens
    found_tokens = [t for t in SUSPICIOUS_TOKENS if t in url_lower]

    # Brand analysis
    brand_in_subdomain = False
    brand_domain_mismatch = False
    scheme_mismatch = False

    for brand, legit_domains in BRAND_DOMAINS.items():
        if brand in url_lower and registered_domain not in legit_domains:
            brand_domain_mismatch = True
            if subdomain and brand in subdomain:
                brand_in_subdomain = True
            if components.get("scheme") != "https":
                scheme_mismatch = True

    subdomain_count = len(subdomain.split(".")) if subdomain else 0

    return {
        "suspicious_token_count": len(found_tokens),
        "suspicious_tokens_found": int(len(found_tokens) > 0),
        "brand_in_subdomain": int(brand_in_subdomain),
        "brand_domain_mismatch": int(brand_domain_mismatch),
        "scheme_mismatch": int(scheme_mismatch),
        "excessive_subdomains": int(subdomain_count > 3),
        "redirect_token_in_url": int(
            any(
                t in url_lower
                for t in ["redirect=", "url=", "goto=", "next=", "return="]
            )
        ),
    }
