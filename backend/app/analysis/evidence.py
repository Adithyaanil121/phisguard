"""
Evidence Fusion Engine (Ticket 3.5.3).

Transparent, rule-based fusion of multi-source evidence:
1. Static analysis (31 lexical & structural features)
2. Calibrated ML classification
3. Reputation blocklists
4. TLS certificate inspection
5. Dynamic sandbox observations (forms, redirects, DOM)
"""
from typing import Any

from ..schemas.analysis import Action, Evidence, EvidenceStatus, Verdict


class EvidenceFusionEngine:
    """Combines static, ML, TLS, reputation, and dynamic sandbox evidence."""

    def fuse(
        self,
        evidence: Evidence,
        phishing_probability: float | None = None,
        static_features: dict[str, Any] | None = None,
        dynamic_results: dict[str, Any] | None = None,
    ) -> tuple[Verdict, Action, int, list[str]]:
        """
        Produce synthesized (verdict, action, risk_score, reasons) from all evidence.
        """
        reasons: list[str] = []
        risk_score = 0
        critical_flags = 0

        # 1. Reputation Check (P0 Deterministic Override)
        if evidence.reputation.status == EvidenceStatus.COMPLETED:
            rep_details = evidence.reputation.details or {}
            if rep_details.get("known_malicious"):
                reasons.append("URL identified on verified malicious threat intelligence feed")
                return Verdict.PHISHING, Action.BLOCK, 99, reasons

        # 2. Dynamic Sandbox Observations
        if dynamic_results and dynamic_results.get("status") == "completed":
            is_harvesting = (
                dynamic_results.get("has_cross_domain_form")
                and dynamic_results.get("has_password_field")
            )
            if is_harvesting:
                reasons.append("Credential harvesting: password form submits to external domain")
                critical_flags += 2
                risk_score = max(risk_score, 90)

            hop_count = dynamic_results.get("hop_count", 0)
            if hop_count >= 3:
                reasons.append(f"Excessive redirect chain detected ({hop_count} hops)")
                risk_score = max(risk_score, 65)

        # 3. TLS Certificate Findings
        if evidence.tls.status == EvidenceStatus.COMPLETED:
            tls_details = evidence.tls.details or {}
            if tls_details.get("valid") is False:
                err_msg = tls_details.get("error", "invalid")
                reasons.append(f"TLS certificate validation failed: {err_msg}")
                risk_score = max(risk_score, 70)
            elif tls_details.get("is_expired"):
                reasons.append("TLS certificate is expired")
                risk_score = max(risk_score, 60)

        # 4. Static Deterministic Indicators
        if static_features:
            if static_features.get("is_ip_address"):
                reasons.append("Host is a bare IP address rather than a domain name")
                critical_flags += 1

            if static_features.get("has_credentials"):
                reasons.append("URL contains embedded user credentials")
                critical_flags += 1

            if static_features.get("brand_domain_mismatch"):
                reasons.append("Well-known brand name used in non-legitimate domain")
                critical_flags += 1

            if static_features.get("punycode_detected"):
                reasons.append("Punycode detected: potential homograph impersonation")

            if static_features.get("tld_risk_score"):
                reasons.append("Domain registered under high-risk TLD")

        # 5. ML Probability Integration
        if phishing_probability is not None:
            ml_score = int(phishing_probability * 100)
            risk_score = max(risk_score, ml_score)
            if phishing_probability >= 0.85:
                reasons.append(
                    f"ML classified as phishing with high confidence ({phishing_probability:.1%})"
                )
            elif phishing_probability >= 0.50:
                reasons.append(f"ML model classified as suspicious ({phishing_probability:.1%})")
        else:
            reasons.append("ML inference unavailable; relying on deterministic rules")
            risk_score = max(risk_score, 50)

        # 6. Verdict and Action Assignment
        if critical_flags >= 2 or risk_score >= 85:
            verdict = Verdict.PHISHING
            action = Action.BLOCK
        elif critical_flags >= 1 or risk_score >= 65:
            verdict = Verdict.HIGH_RISK
            action = Action.BLOCK
        elif risk_score >= 45:
            verdict = Verdict.SUSPICIOUS
            action = Action.WARN
        elif risk_score >= 20:
            verdict = Verdict.LOW_RISK
            action = Action.ALLOW
        else:
            verdict = Verdict.NO_KNOWN_THREAT
            action = Action.ALLOW

        return verdict, action, min(100, risk_score), reasons
