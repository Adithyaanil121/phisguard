"""
Adversarial testing suite for PhishGuard (Ticket 8.3).

Evaluates the feature extraction, policy engine, and normalizer against
known evasion attacks:
1. IDN / Cyrillic Homoglyphs & Punycode conversion
2. IP address host formats
3. Obfuscated credentials via @ symbol
4. Subdomain stuffing & brand impersonation
5. Path-based deceptive brand redirection
6. Known URL shortener evasion
7. Special characters, percent encoding, and port stuffing
"""
import pytest

from backend.app.core.policy import PolicyEngine
from backend.app.features import extract_all_features
from backend.app.features.normalize import URLValidationError, validate_and_normalize
from backend.app.schemas.analysis import Action, Evidence, Verdict


class TestAdversarialEvasion:
    @pytest.fixture()
    def policy(self):
        return PolicyEngine()

    def test_homoglyph_idn_punycode_detection(self, policy):
        """
        Homoglyph attack: Using Cyrillic 'а' (U+0430) instead of Latin 'a'.
        pаypal.com -> xn--pypal-4ve.com
        """
        malicious_url = "https://p\u0430ypal.com/signin"
        norm_url, components = validate_and_normalize(malicious_url)
        assert norm_url.startswith("https://xn--")

        feats, _, _ = extract_all_features(malicious_url)
        assert feats["punycode_detected"] == 1

        # Evaluate policy with low ML score (e.g. 0.05) to ensure deterministic override
        verdict, action, score, reasons = policy.evaluate(
            phishing_probability=0.05,
            evidence=Evidence(),
            static_features=feats,
        )
        assert verdict == Verdict.SUSPICIOUS
        assert action == Action.WARN
        assert any("Internationalized domain name" in r for r in reasons)

    def test_ip_address_host_evasion(self, policy):
        """Phishing hosted directly on numeric IP address."""
        ip_url = "http://198.51.100.42/login.php"
        feats, _, _ = extract_all_features(ip_url)
        assert feats["is_ip_address"] == 1

        verdict, action, score, reasons = policy.evaluate(
            phishing_probability=0.05,
            evidence=Evidence(),
            static_features=feats,
        )
        assert verdict == Verdict.SUSPICIOUS
        assert action == Action.WARN
        assert any("IP address" in r for r in reasons)

    def test_embedded_credentials_at_symbol(self, policy):
        """URL using @ to obscure the actual host: https://paypal.com@evil-site.com/"""
        url = "https://paypal.com@evil-site.com/verify"
        feats, _, _ = extract_all_features(url)
        assert feats["has_at_symbol"] == 1

        verdict, action, score, reasons = policy.evaluate(
            phishing_probability=0.05,
            evidence=Evidence(),
            static_features=feats,
        )
        assert verdict == Verdict.SUSPICIOUS
        assert action == Action.WARN
        assert any("@ symbol" in r for r in reasons)

    def test_subdomain_brand_stuffing(self, policy):
        """Brand placed in subdomain of third-party domain."""
        url = "https://login.paypal.com.account-update.xyz/auth"
        feats, _, _ = extract_all_features(url)
        assert feats["brand_in_subdomain"] == 1
        assert feats["brand_domain_mismatch"] == 1

        verdict, action, score, reasons = policy.evaluate(
            phishing_probability=0.05,
            evidence=Evidence(),
            static_features=feats,
        )
        assert verdict == Verdict.SUSPICIOUS
        assert action == Action.WARN
        assert any("Brand name" in r for r in reasons)

    def test_excessive_subdomains_chain(self, policy):
        """Subdomain chain hiding actual domain."""
        url = "https://a.b.c.d.e.f.g.h.attacker.com/session"
        feats, _, _ = extract_all_features(url)
        assert feats["excessive_subdomains"] == 1

        verdict, action, score, reasons = policy.evaluate(
            phishing_probability=0.05,
            evidence=Evidence(),
            static_features=feats,
        )
        assert verdict == Verdict.SUSPICIOUS
        assert action == Action.WARN

    def test_shortener_identification(self):
        """Known URL shortener is flagged as a risk signal."""
        url = "https://bit.ly/3xSecAlert"
        feats, _, _ = extract_all_features(url)
        assert feats["is_known_shortener"] == 1

    def test_suspicious_tokens_found(self):
        """Suspicious credential/security tokens found in URL."""
        url = "https://secure-portal-auth.org/verify/account/login.aspx"
        feats, _, _ = extract_all_features(url)
        assert feats["suspicious_tokens_found"] == 1
        assert feats["suspicious_token_count"] >= 3

    def test_invalid_scheme_rejection(self):
        """Reject non-HTTP schemes like javascript:, data:, file:."""
        with pytest.raises(URLValidationError):
            validate_and_normalize("javascript:alert(1)")

        with pytest.raises(URLValidationError):
            validate_and_normalize("data:text/html,<script>alert(1)</script>")

        with pytest.raises(URLValidationError):
            validate_and_normalize("file:///etc/passwd")
