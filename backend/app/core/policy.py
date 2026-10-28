"""
Policy engine: translates evidence into verdict, risk_score, and action.

Rules (evaluated in order):
1. Known-malicious reputation hit → PHISHING / BLOCK
   (regardless of ML score)
2. Strong deterministic evidence (IP host, embedded credentials,
   brand mismatch + suspicious tokens) → at least SUSPICIOUS / WARN
   (regardless of ML score)
3. High ML probability → HIGH_RISK / BLOCK
   High ML probability + suspicious static features → PHISHING / BLOCK
4. Medium ML probability → SUSPICIOUS / WARN
5. Low ML probability with no deterministic red flags → NO_KNOWN_THREAT / ALLOW
6. ML unavailable → cap at SUSPICIOUS / WARN, never NO_KNOWN_THREAT

The blocking threshold should be selected using validation results and
your false-positive tolerance. The defaults below are starting points,
not final values.
"""
from ..schemas.analysis import Action, Evidence, EvidenceStatus, Verdict


class PolicyEngine:
    # Starting-point thresholds — to be tuned using validation data
    HIGH_THRESHOLD: float = 0.85
    MEDIUM_THRESHOLD: float = 0.50

    def evaluate(
        self,
        phishing_probability: float | None,
        evidence: Evidence,
        static_features: dict | None = None,
    ) -> tuple[Verdict, Action, int, list[str]]:
        """
        Returns (verdict, action, risk_score, reasons).

        Evaluates deterministic evidence BEFORE considering ML probability,
        so that strong red flags are never overridden by a low model score.
        """
        reasons: list[str] = []
        risk_score = 0
        deterministic_flags: list[str] = []

        # --- Step 1: Collect deterministic evidence ---
        if static_features:
            deterministic_flags = self._collect_deterministic_flags(static_features)
            reasons.extend(deterministic_flags)

        # --- Step 2: Reputation override (Rule 1) ---
        if evidence.reputation.status == EvidenceStatus.COMPLETED:
            rep_details = evidence.reputation.details or {}
            if rep_details.get("known_malicious"):
                reasons.append("URL found in known malicious feed")
                return Verdict.PHISHING, Action.BLOCK, 99, reasons

        # --- Step 3: Evaluate ML + deterministic together ---
        has_deterministic_red_flags = len(deterministic_flags) > 0

        if phishing_probability is not None:
            risk_score = int(phishing_probability * 100)

            # Rule 3: High ML probability
            if phishing_probability >= self.HIGH_THRESHOLD:
                reasons.append(
                    f"High phishing probability: {phishing_probability:.2f}"
                )
                if has_deterministic_red_flags:
                    # High ML + deterministic evidence → strongest signal
                    return Verdict.PHISHING, Action.BLOCK, max(risk_score, 95), reasons
                return Verdict.HIGH_RISK, Action.BLOCK, risk_score, reasons

            # Rule 4: Medium ML probability
            if phishing_probability >= self.MEDIUM_THRESHOLD:
                reasons.append(
                    f"Moderate phishing probability: {phishing_probability:.2f}"
                )
                return Verdict.SUSPICIOUS, Action.WARN, risk_score, reasons

            # Below medium threshold — but check deterministic evidence first
            # Rule 2: Strong deterministic evidence overrides low ML
            if has_deterministic_red_flags:
                risk_score = max(risk_score, 50)
                return Verdict.SUSPICIOUS, Action.WARN, risk_score, reasons

            # Rule 5: Low ML, no red flags
            return Verdict.NO_KNOWN_THREAT, Action.ALLOW, risk_score, reasons

        else:
            # Rule 6: ML unavailable — never declare NO_KNOWN_THREAT
            reasons.append("ML model unavailable; using static analysis only")
            if has_deterministic_red_flags:
                return Verdict.SUSPICIOUS, Action.WARN, 60, reasons
            # Cannot confirm or deny — default to uncertain
            return Verdict.SUSPICIOUS, Action.WARN, 50, reasons

    def _collect_deterministic_flags(self, features: dict) -> list[str]:
        """
        Identify strong deterministic signals from static features.
        These are facts about the URL, not model predictions.
        """
        flags = []
        if features.get("has_ip_address") or features.get("is_ip_address"):
            flags.append("URL uses an IP address instead of a domain name")
        if features.get("has_at_symbol"):
            flags.append("URL contains @ symbol (possible credential embedding)")
        if features.get("brand_domain_mismatch"):
            flags.append("Brand name present but domain does not match the brand")
        if features.get("brand_in_subdomain"):
            flags.append("Brand name used as a subdomain of a different domain")
        if features.get("punycode_detected"):
            flags.append(
                "Internationalized domain name detected (possible homoglyph attack)"
            )
        if features.get("excessive_subdomains"):
            flags.append("Excessive number of subdomains")
        if features.get("scheme_mismatch"):
            flags.append("Brand-related URL served over insecure HTTP")
        return flags
