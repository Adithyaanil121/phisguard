import uuid

from fastapi import APIRouter, Depends, HTTPException, Request

from ..core.config import Settings, get_settings
from ..core.limiter import limiter
from ..core.security import authorize_deep_scan, verify_api_key, verify_origin
from ..features.normalize import URLValidationError, validate_and_normalize
from ..schemas.analysis import (
    Action,
    AnalysisResult,
    DeepScanResponse,
    Evidence,
    ScanMode,
    ScanRequest,
    Verdict,
)

router = APIRouter()


@router.get("/health")
async def health(request: Request, _settings: Settings = Depends(get_settings)):
    """No authentication required."""
    model_loaded = getattr(request.app.state, "model_loaded", False)
    return {"status": "ok", "model_loaded": model_loaded}


@router.get(
    "/model-info",
    dependencies=[Depends(verify_api_key), Depends(verify_origin)],
)
async def model_info(settings: Settings = Depends(get_settings)):
    return {
        "model_version": settings.model_version,
        "model_path": settings.model_path,
    }


@router.post(
    "/api/v1/check-url",
    response_model=AnalysisResult,
    dependencies=[Depends(verify_api_key), Depends(verify_origin)],
)
@limiter.limit(get_settings().rate_limit_quick)
async def check_url(request: Request, body: ScanRequest):
    """Quick Scan — stub in Phase 0, implemented fully in Phase 3."""
    try:
        normalized_url, _ = validate_and_normalize(body.url)
    except URLValidationError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    # In Phase 0 / degraded mode: ML model is absent, evidence is not_checked
    return AnalysisResult(
        url=body.url,
        normalized_url=normalized_url,
        scan_mode=ScanMode.QUICK,
        verdict=Verdict.SUSPICIOUS,
        action=Action.WARN,
        risk_score=50,
        phishing_probability=None,
        evidence=Evidence(),
        reasons=["ML model unavailable; using static analysis only"],
    )


@router.post(
    "/api/v1/deep-scan",
    response_model=DeepScanResponse,
    dependencies=[Depends(authorize_deep_scan)],
)
@limiter.limit(get_settings().rate_limit_deep)
async def deep_scan(request: Request, body: ScanRequest):
    """Deep Scan — returns unavailable until Phase 3.5."""
    try:
        validate_and_normalize(body.url)
    except URLValidationError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    return DeepScanResponse(
        scan_id=str(uuid.uuid4()),
        status="not_available",
        reason="deep_scan_worker_not_implemented",
    )


@router.get(
    "/api/v1/deep-scan/{scan_id}",
    response_model=DeepScanResponse,
    dependencies=[Depends(authorize_deep_scan)],
)
async def get_deep_scan(scan_id: str):
    return DeepScanResponse(
        scan_id=scan_id,
        status="not_available",
        reason="deep_scan_worker_not_implemented",
    )
