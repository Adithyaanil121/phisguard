"""
URL normalization and validation.

Design decisions:
- Scheme detection is case-insensitive (handles HTTPS://, Http://, etc.)
- Malformed ports raise URLValidationError, not ValueError
- IPv6 addresses are handled with bracket notation for reconstruction
- Subdomain and registered-domain extraction uses tldextract, not dot counting
- Credentials in URLs (user:pass@host) are flagged but not silently stripped
- IDNA/punycode domains are accepted and normalized
"""
import ipaddress
import re
from urllib.parse import urlparse, urlunparse

import tldextract

SUPPORTED_SCHEMES = {"http", "https"}
MAX_URL_LENGTH = 2048


class URLValidationError(ValueError):
    """Raised for URLs that cannot be safely analyzed."""
    pass


def validate_and_normalize(raw_url: str) -> tuple[str, dict]:
    """
    Validate and normalize a URL for analysis.

    Returns:
        (normalized_url, parsed_components)

    Raises:
        URLValidationError for malformed or unsupported URLs.
    """
    raw_url = raw_url.strip()

    if not raw_url:
        raise URLValidationError("Empty URL")

    if len(raw_url) > MAX_URL_LENGTH:
        raise URLValidationError(f"URL exceeds maximum length of {MAX_URL_LENGTH}")

    # Case-insensitive scheme detection
    scheme_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+\-.]*):\/\/", raw_url)
    if scheme_match:
        detected_scheme = scheme_match.group(1).lower()
        if detected_scheme not in SUPPORTED_SCHEMES:
            raise URLValidationError(f"Unsupported scheme: {detected_scheme}")
        raw_url = detected_scheme + raw_url[len(detected_scheme):]
    elif ":" in raw_url:
        prefix, after_colon = raw_url.split(":", 1)
        # If the colon is followed by a port number before any path
        if after_colon and after_colon[0].isdigit():
            raw_url = "https://" + raw_url
        else:
            # Non-hierarchical scheme (e.g. javascript:, data:, mailto:)
            raise URLValidationError(f"Unsupported scheme: {prefix.lower()}")
    else:
        # No scheme found — prepend https://
        raw_url = "https://" + raw_url

    try:
        parsed = urlparse(raw_url)
    except Exception as e:
        raise URLValidationError(f"Cannot parse URL: {e}") from e

    if parsed.scheme not in SUPPORTED_SCHEMES:
        raise URLValidationError(f"Unsupported scheme: {parsed.scheme}")

    if not parsed.hostname:
        raise URLValidationError("No hostname found")

    # Catch malformed ports (urlparse can raise ValueError on access)
    try:
        port = parsed.port
    except ValueError as e:
        raise URLValidationError(f"Malformed port: {e}") from e

    # Flag credentials in URL (don't silently strip them)
    has_credentials = bool(parsed.username or parsed.password)

    hostname = parsed.hostname.lower()

    # Check if hostname is an IP address
    is_ipv4 = False
    is_ipv6 = False
    try:
        ipaddress.IPv4Address(hostname)
        is_ipv4 = True
    except ValueError:
        pass
    if not is_ipv4:
        # IPv6: urlparse strips brackets from hostname
        try:
            ipaddress.IPv6Address(hostname)
            is_ipv6 = True
        except ValueError:
            pass

    # Remove trailing dot from hostname (FQDN normalization)
    hostname = hostname.rstrip(".")

    # Extract registered domain and subdomain using tldextract
    extracted = tldextract.extract(raw_url)
    top_domain = getattr(extracted, "top_domain_under_public_suffix", None)
    if top_domain is None:
        top_domain = getattr(extracted, "registered_domain", "")
    registered_domain = top_domain.lower() if top_domain else ""
    subdomain = extracted.subdomain.lower() if extracted.subdomain else ""
    suffix = extracted.suffix.lower() if extracted.suffix else ""

    # Rebuild netloc with proper handling
    netloc_host = f"[{hostname}]" if is_ipv6 else hostname

    netloc = netloc_host
    if port and port not in (80, 443):
        netloc = f"{netloc_host}:{port}"
    elif (port == 80 and parsed.scheme == "http") or (port == 443 and parsed.scheme == "https"):
        netloc = netloc_host  # default port, omit

    # Reconstruct normalized URL (drop fragment and credentials)
    normalized = urlunparse((
        parsed.scheme,
        netloc,
        parsed.path or "/",
        parsed.params,
        parsed.query,
        "",  # Drop fragment
    ))

    components = {
        "scheme": parsed.scheme,
        "hostname": hostname,
        "port": port,
        "path": parsed.path or "/",
        "query": parsed.query,
        "fragment": parsed.fragment,
        "netloc": netloc,
        "registered_domain": registered_domain,
        "subdomain": subdomain,
        "suffix": suffix,
        "is_ip_address": is_ipv4 or is_ipv6,
        "is_ipv4": is_ipv4,
        "is_ipv6": is_ipv6,
        "has_credentials": has_credentials,
    }

    return normalized, components
