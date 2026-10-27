from backend.app.core.policy import PolicyEngine
from backend.app.schemas.analysis import (
    Action,
    Evidence,
    EvidenceDetail,
    EvidenceStatus,
    Verdict,
)


def test_rule_1_known_malicious_reputation_overrides_low_ml():
    """Rule 1: Known-malicious reputation → PHISHING/BLOCK even with ML = 0.01."""
    engine = PolicyEngine()
    ev = Evidence(
        reputation=EvidenceDetail(
            status=EvidenceStatus.COMPLETED,
            details={"known_malicious": True, "source": "openphish"},
        )
    )
    verdict, action, score, reasons = engine.evaluate(
        phishing_probability=0.01,
        evidence=ev,
        static_features={"has_ip_address": False},
    )
    assert verdict == Verdict.PHISHING
    assert action == Action.BLOCK
    assert score == 99
    assert any("known malicious feed" in r for r in reasons)


def test_rule_2_low_ml_with_deterministic_flags_is_suspicious():
    """Rule 2: Low ML (0.10) + red flags → SUSPICIOUS/WARN (never safe)."""
    engine = PolicyEngine()
    verdict, action, score, reasons = engine.evaluate(
        phishing_probability=0.10,
        evidence=Evidence(),
        static_features={"has_ip_address": True, "brand_domain_mismatch": True},
    )
    assert verdict == Verdict.SUSPICIOUS
    assert action == Action.WARN
    assert score >= 50
    assert any("IP address" in r for r in reasons)


def test_rule_3a_high_ml_alone_is_high_risk():
    """Rule 3a: High ML (0.90) alone → HIGH_RISK/BLOCK."""
    engine = PolicyEngine()
    verdict, action, score, reasons = engine.evaluate(
        phishing_probability=0.90,
        evidence=Evidence(),
        static_features={},
    )
    assert verdict == Verdict.HIGH_RISK
    assert action == Action.BLOCK
    assert score == 90
    assert any("High phishing probability" in r for r in reasons)


def test_rule_3b_high_ml_plus_flags_is_phishing():
    """Rule 3b: High ML (0.90) + deterministic flags → PHISHING/BLOCK."""
    engine = PolicyEngine()
    verdict, action, score, reasons = engine.evaluate(
        phishing_probability=0.90,
        evidence=Evidence(),
        static_features={"has_at_symbol": True},
    )
    assert verdict == Verdict.PHISHING
    assert action == Action.BLOCK
    assert score >= 95
    assert any("High phishing probability" in r for r in reasons)


def test_rule_4_medium_ml_is_suspicious():
    """Rule 4: Medium ML (0.65) → SUSPICIOUS/WARN."""
    engine = PolicyEngine()
    verdict, action, score, reasons = engine.evaluate(
        phishing_probability=0.65,
        evidence=Evidence(),
        static_features={},
    )
    assert verdict == Verdict.SUSPICIOUS
    assert action == Action.WARN
    assert score == 65
    assert any("Moderate phishing probability" in r for r in reasons)


def test_rule_5_low_ml_no_flags_is_no_known_threat():
    """Rule 5: Low ML (0.10) + no red flags → NO_KNOWN_THREAT/ALLOW."""
    engine = PolicyEngine()
    verdict, action, score, reasons = engine.evaluate(
        phishing_probability=0.10,
        evidence=Evidence(),
        static_features={},
    )
    assert verdict == Verdict.NO_KNOWN_THREAT
    assert action == Action.ALLOW
    assert score == 10
    assert len(reasons) == 0


def test_rule_6a_no_ml_with_red_flags():
    """Rule 6a: No ML + red flags → SUSPICIOUS/WARN."""
    engine = PolicyEngine()
    verdict, action, score, reasons = engine.evaluate(
        phishing_probability=None,
        evidence=Evidence(),
        static_features={"punycode_detected": True},
    )
    assert verdict == Verdict.SUSPICIOUS
    assert action == Action.WARN
    assert score == 60
    assert any("ML model unavailable" in r for r in reasons)


def test_rule_6b_no_ml_without_flags_never_safe():
    """Rule 6b: No ML + no flags → SUSPICIOUS/WARN (never NO_KNOWN_THREAT)."""
    engine = PolicyEngine()
    verdict, action, score, reasons = engine.evaluate(
        phishing_probability=None,
        evidence=Evidence(),
        static_features={},
    )
    assert verdict == Verdict.SUSPICIOUS
    assert action == Action.WARN
    assert score == 50
    assert verdict != Verdict.NO_KNOWN_THREAT
    assert action != Action.ALLOW


def test_low_ml_with_red_flags_is_not_safe_regression():
    """
    Regression: v1 policy returned SAFE/ALLOW while listing
    suspicious reasons. This must never happen.
    """
    engine = PolicyEngine()
    verdict, action, score, reasons = engine.evaluate(
        phishing_probability=0.10,
        evidence=Evidence(),
        static_features={
            "has_ip_address": True,
            "excessive_subdomains": True,
        },
    )
    assert verdict != Verdict.NO_KNOWN_THREAT
    assert action != Action.ALLOW
    assert verdict == Verdict.SUSPICIOUS
    assert action == Action.WARN
