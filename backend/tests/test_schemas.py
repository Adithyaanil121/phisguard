import uuid

import pytest
from pydantic import ValidationError

from backend.app.schemas.analysis import (
    Action,
    AnalysisResult,
    Evidence,
    EvidenceStatus,
    ScanMode,
    ScanRequest,
    Verdict,
)


def test_verdict_values_and_no_safe():
    """Verify NO_KNOWN_THREAT exists and SAFE does not exist."""
    assert Verdict.NO_KNOWN_THREAT.value == "no_known_threat"
    assert "SAFE" not in Verdict.__members__
    assert not any(v.value == "safe" for v in Verdict)


def test_evidence_status_has_seven_values():
    """EvidenceStatus must have exactly 7 defined values."""
    assert len(EvidenceStatus) == 7
    expected = {
        "completed",
        "not_checked",
        "not_found",
        "not_run",
        "failed",
        "timeout",
        "unavailable",
    }
    assert {s.value for s in EvidenceStatus} == expected


def test_default_evidence_all_not_checked():
    """Default Evidence has all 5 categories set to NOT_CHECKED."""
    ev = Evidence()
    assert ev.static_analysis.status == EvidenceStatus.NOT_CHECKED
    assert ev.ml_prediction.status == EvidenceStatus.NOT_CHECKED
    assert ev.reputation.status == EvidenceStatus.NOT_CHECKED
    assert ev.tls.status == EvidenceStatus.NOT_CHECKED
    assert ev.dynamic_analysis.status == EvidenceStatus.NOT_CHECKED


def test_risk_score_boundaries():
    """risk_score must accept 0 and 100, reject -1 and 101."""
    base_kwargs = {
        "url": "https://example.com",
        "scan_mode": ScanMode.QUICK,
        "verdict": Verdict.NO_KNOWN_THREAT,
        "action": Action.ALLOW,
        "evidence": Evidence(),
    }
    # 0 is valid
    res_0 = AnalysisResult(risk_score=0, **base_kwargs)
    assert res_0.risk_score == 0

    # 100 is valid
    res_100 = AnalysisResult(risk_score=100, **base_kwargs)
    assert res_100.risk_score == 100

    # -1 is invalid
    with pytest.raises(ValidationError):
        AnalysisResult(risk_score=-1, **base_kwargs)

    # 101 is invalid
    with pytest.raises(ValidationError):
        AnalysisResult(risk_score=101, **base_kwargs)


def test_phishing_probability_boundaries():
    """phishing_probability accepts None, 0.0, 1.0, and rejects out-of-range values."""
    base_kwargs = {
        "url": "https://example.com",
        "scan_mode": ScanMode.QUICK,
        "verdict": Verdict.NO_KNOWN_THREAT,
        "action": Action.ALLOW,
        "risk_score": 10,
        "evidence": Evidence(),
    }
    # None is valid
    res_none = AnalysisResult(phishing_probability=None, **base_kwargs)
    assert res_none.phishing_probability is None

    # 0.0 and 1.0 are valid
    res_0 = AnalysisResult(phishing_probability=0.0, **base_kwargs)
    assert res_0.phishing_probability == 0.0

    res_1 = AnalysisResult(phishing_probability=1.0, **base_kwargs)
    assert res_1.phishing_probability == 1.0

    # -0.1 and 1.1 are invalid
    with pytest.raises(ValidationError):
        AnalysisResult(phishing_probability=-0.1, **base_kwargs)

    with pytest.raises(ValidationError):
        AnalysisResult(phishing_probability=1.1, **base_kwargs)


def test_scan_request_url_length():
    """ScanRequest rejects URLs longer than 2048 characters."""
    valid_url = "https://example.com/" + "a" * 2000
    req = ScanRequest(url=valid_url)
    assert req.url == valid_url

    too_long_url = "https://example.com/" + "a" * 2050
    with pytest.raises(ValidationError):
        ScanRequest(url=too_long_url)


def test_analysis_result_serialization_and_uuid():
    """AnalysisResult serializes to JSON with all expected fields and UUID scan_id."""
    res = AnalysisResult(
        url="https://example.com",
        scan_mode=ScanMode.QUICK,
        verdict=Verdict.NO_KNOWN_THREAT,
        action=Action.ALLOW,
        risk_score=5,
        evidence=Evidence(),
    )
    # scan_id is a valid UUID
    parsed_uuid = uuid.UUID(res.scan_id)
    assert parsed_uuid.version == 4

    # JSON serialization
    json_data = res.model_dump(mode="json")
    assert json_data["url"] == "https://example.com"
    assert json_data["verdict"] == "no_known_threat"
    assert json_data["action"] == "allow"
    assert json_data["risk_score"] == 5
    assert json_data["evidence"]["static_analysis"]["status"] == "not_checked"
    assert "timestamp" in json_data
    assert json_data["api_version"] == "v1"
