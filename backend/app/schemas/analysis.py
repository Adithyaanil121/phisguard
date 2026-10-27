"""
Core schemas for scan requests and analysis results.

Design decisions:
- Verdict uses NO_KNOWN_THREAT instead of SAFE. A low ML score
  is absence of detected threat, not proof of safety.
- phishing_probability can be null when the model is unavailable.
- risk_score is 0-100; it is an application-defined assessment,
  not a direct mapping of ML probability.
- action is a policy decision, separate from model output.
"""
import uuid
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class ScanMode(StrEnum):
    QUICK = "quick"
    DEEP = "deep"


class EvidenceStatus(StrEnum):
    COMPLETED = "completed"
    NOT_CHECKED = "not_checked"
    NOT_FOUND = "not_found"
    NOT_RUN = "not_run"
    FAILED = "failed"
    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"


class Verdict(StrEnum):
    NO_KNOWN_THREAT = "no_known_threat"
    LOW_RISK = "low_risk"
    SUSPICIOUS = "suspicious"
    HIGH_RISK = "high_risk"
    PHISHING = "phishing"


class Action(StrEnum):
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"
    MANUAL_REVIEW = "manual_review"


class EvidenceDetail(BaseModel):
    status: EvidenceStatus
    details: dict | None = None
    error: str | None = None
    latency_ms: float | None = None


class Evidence(BaseModel):
    static_analysis: EvidenceDetail = Field(
        default_factory=lambda: EvidenceDetail(status=EvidenceStatus.NOT_CHECKED)
    )
    ml_prediction: EvidenceDetail = Field(
        default_factory=lambda: EvidenceDetail(status=EvidenceStatus.NOT_CHECKED)
    )
    reputation: EvidenceDetail = Field(
        default_factory=lambda: EvidenceDetail(status=EvidenceStatus.NOT_CHECKED)
    )
    tls: EvidenceDetail = Field(
        default_factory=lambda: EvidenceDetail(status=EvidenceStatus.NOT_CHECKED)
    )
    dynamic_analysis: EvidenceDetail = Field(
        default_factory=lambda: EvidenceDetail(status=EvidenceStatus.NOT_CHECKED)
    )


class AnalysisResult(BaseModel):
    url: str
    normalized_url: str | None = None
    scan_mode: ScanMode
    verdict: Verdict
    action: Action
    risk_score: int = Field(ge=0, le=100)
    phishing_probability: float | None = Field(None, ge=0.0, le=1.0)
    model_version: str | None = None
    evidence: Evidence
    reasons: list[str] = []
    cached: bool = False
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    api_version: str = "v1"


class ScanRequest(BaseModel):
    url: str = Field(..., max_length=2048, description="URL to analyze")


class DeepScanResponse(BaseModel):
    scan_id: str
    status: str
    reason: str | None = None
    result: AnalysisResult | None = None
