"""
Unit tests for lexical, structural, and unified feature extraction.

Tests all required test cases from Tickets 1.3, 1.4, and 1.5.
"""
from backend.app.features import (
    extract_all_features,
    extract_lexical_features,
    extract_structural_features,
    get_feature_names,
    validate_and_normalize,
)
from backend.app.features.lexical import shannon_entropy


class TestShannonEntropy:
    def test_empty_string(self):
        assert shannon_entropy("") == 0.0

    def test_single_repeated_char_zero_entropy(self):
        assert shannon_entropy("aaaaa") == 0.0

    def test_random_string_higher_entropy_than_repeated(self):
        low_entropy = shannon_entropy("aaaa.com")
        high_entropy = shannon_entropy("x7k2m.com")
        assert high_entropy > low_entropy


class TestLexicalFeatures:
    def test_baseline_benign_url(self):
        url, comp = validate_and_normalize("https://example.com/")
        feats = extract_lexical_features(url, comp)

        assert feats["url_length"] == len("https://example.com/")
        assert feats["hostname_length"] == len("example.com")
        assert feats["path_length"] == 1
        assert feats["query_length"] == 0
        assert feats["is_https"] == 1
        assert feats["is_ip_address"] == 0
        assert feats["has_at_symbol"] == 0
        assert feats["has_non_standard_port"] == 0
        assert feats["is_known_shortener"] == 0
        assert feats["tld_risk_score"] == 0
        assert feats["punycode_detected"] == 0

    def test_ip_address_detection(self):
        url, comp = validate_and_normalize("http://192.168.1.1/admin")
        feats = extract_lexical_features(url, comp)
        assert feats["is_ip_address"] == 1
        assert feats["is_https"] == 0

    def test_multiple_phishing_signals(self):
        url, comp = validate_and_normalize(
            "https://login.paypal.com.evil.tk/verify?id=abc"
        )
        feats = extract_lexical_features(url, comp)
        assert feats["tld_risk_score"] == 1  # .tk is high-risk
        assert feats["subdomain_count"] >= 3

    def test_shortener_detection(self):
        url, comp = validate_and_normalize("https://bit.ly/3xF2k")
        feats = extract_lexical_features(url, comp)
        assert feats["is_known_shortener"] == 1

    def test_punycode_detection(self):
        url, comp = validate_and_normalize("https://xn--pple-43d.com/")
        feats = extract_lexical_features(url, comp)
        assert feats["punycode_detected"] == 1

    def test_excessive_subdomains(self):
        url, comp = validate_and_normalize("https://a.b.c.d.example.com/")
        feats = extract_lexical_features(url, comp)
        assert feats["subdomain_count"] == 4

    def test_non_standard_port(self):
        url, comp = validate_and_normalize("http://example.com:8080/path")
        feats = extract_lexical_features(url, comp)
        assert feats["has_non_standard_port"] == 1

    def test_query_param_count(self):
        url, comp = validate_and_normalize("https://example.com/path?a=1&b=2&c=3")
        feats = extract_lexical_features(url, comp)
        assert feats["query_param_count"] == 3

    def test_credentials_in_url(self):
        url, comp = validate_and_normalize("https://user:pass@evil.com/")
        feats = extract_lexical_features(url, comp)
        assert feats["has_credentials"] == 1

    def test_high_risk_tld(self):
        url, comp = validate_and_normalize("https://example.tk/")
        feats = extract_lexical_features(url, comp)
        assert feats["tld_risk_score"] == 1

    def test_all_lexical_values_are_numeric(self):
        url, comp = validate_and_normalize("https://login.paypal.com.evil.tk/verify?id=abc")
        feats = extract_lexical_features(url, comp)
        for key, val in feats.items():
            assert isinstance(val, (int, float)), f"Feature {key} is {type(val)}"
            assert not isinstance(val, bool), f"Feature {key} is a bool, must be int/float"


class TestStructuralFeatures:
    def test_brand_in_subdomain_and_mismatch(self):
        url, comp = validate_and_normalize("https://paypal.evil.com/login")
        feats = extract_structural_features(url, comp)
        assert feats["brand_in_subdomain"] == 1
        assert feats["brand_domain_mismatch"] == 1
        assert feats["suspicious_tokens_found"] == 1
        assert feats["suspicious_token_count"] >= 1

    def test_legitimate_brand_domain_no_mismatch(self):
        url, comp = validate_and_normalize("https://paypal.com/login")
        feats = extract_structural_features(url, comp)
        assert feats["brand_in_subdomain"] == 0
        assert feats["brand_domain_mismatch"] == 0

    def test_scheme_mismatch_for_brand(self):
        url, comp = validate_and_normalize("http://paypal-secure.com/verify")
        feats = extract_structural_features(url, comp)
        assert feats["brand_domain_mismatch"] == 1
        assert feats["scheme_mismatch"] == 1

    def test_redirect_tokens_detected(self):
        url, comp = validate_and_normalize("https://example.com/auth?redirect=https://evil.com")
        feats = extract_structural_features(url, comp)
        assert feats["redirect_token_in_url"] == 1

    def test_all_structural_values_are_numeric(self):
        url, comp = validate_and_normalize("https://login.paypal.com.evil.com/")
        feats = extract_structural_features(url, comp)
        for key, val in feats.items():
            assert isinstance(val, int), f"Feature {key} is {type(val)}"
            assert not isinstance(val, bool), f"Feature {key} is a bool, must be int"


class TestUnifiedPipeline:
    def test_extract_all_features_combined(self):
        feats, norm_url, comp = extract_all_features("https://paypal.evil.tk/login?redirect=1")
        assert "url_length" in feats
        assert "brand_domain_mismatch" in feats
        assert feats["tld_risk_score"] == 1
        assert feats["brand_domain_mismatch"] == 1
        assert norm_url.startswith("https://")

    def test_get_feature_names_sorted_and_deterministic(self):
        names = get_feature_names()
        assert len(names) >= 20
        assert names == sorted(names)
        # Calling again yields identical list
        assert get_feature_names() == names
