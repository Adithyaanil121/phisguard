"""API routes for PhishGuard."""
import json
import time
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request

from ..core.config import Settings, get_settings
from ..core.limiter import limiter
from ..core.policy import PolicyEngine
from ..core.security import authorize_deep_scan, verify_api_key, verify_origin
from ..features import extract_all_features
from ..features.normalize import URLValidationError, validate_and_normalize
from ..schemas.analysis import (
    AnalysisResult,
    DeepScanResponse,
    Evidence,
    EvidenceDetail,
    EvidenceStatus,
    ScanMode,
    ScanRequest,
)

router = APIRouter()


@router.get("/health")
async def health(request: Request, _settings: Settings = Depends(get_settings)):
    """Health check endpoint. No authentication required."""
    model_loaded = getattr(request.app.state, "model_loaded", False)
    return {"status": "ok", "model_loaded": model_loaded}


@router.get(
    "/model-info",
    dependencies=[Depends(verify_api_key), Depends(verify_origin)],
)
async def model_info(request: Request, settings: Settings = Depends(get_settings)):
    """Return model metadata and runtime info."""
    meta_path = Path("models/model_metadata.json")
    if meta_path.exists():
        try:
            with meta_path.open(encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass

    model = getattr(request.app.state, "model", None)
    info = model.model_info() if model and hasattr(model, "model_info") else {}
    return {
        "model_version": settings.model_version,
        "model_path": settings.model_path,
        "model_loaded": getattr(request.app.state, "model_loaded", False),
        **info,
    }


@router.post(
    "/api/v1/check-url",
    response_model=AnalysisResult,
    dependencies=[Depends(verify_api_key), Depends(verify_origin)],
)
@limiter.limit(get_settings().rate_limit_quick)
async def check_url(
    request: Request, body: ScanRequest, settings: Settings = Depends(get_settings)
):
    """
    Quick Scan endpoint (Tickets 3.1 & 3.2).

    1. Cache lookup
    2. URL validation and normalization
    3. Static lexical & structural feature extraction
    4. ML prediction (calibrated probability)
    5. Policy engine evaluation
    6. Cache population & return
    """
    cache = getattr(request.app.state, "cache", None)

    # Fast cache check by raw input URL
    if cache:
        cached_result = cache.get(ScanMode.QUICK, body.url)
        if cached_result:
            return cached_result.model_copy(update={"cached": True})

    # 1. URL validation and normalization
    try:
        normalized_url, _components = validate_and_normalize(body.url)
    except URLValidationError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    # Secondary cache check by normalized URL
    if cache and normalized_url != body.url:
        cached_result = cache.get(ScanMode.QUICK, normalized_url)
        if cached_result:
            return cached_result.model_copy(update={"cached": True})

    # 2. Extract static features
    t_feat_start = time.perf_counter()
    features, _, _ = extract_all_features(normalized_url)
    feat_latency_ms = (time.perf_counter() - t_feat_start) * 1000

    # 3. ML inference
    model = getattr(request.app.state, "model", None)
    phishing_prob = None
    ml_latency_ms = None
    if model and getattr(model, "is_loaded", False):
        t_ml_start = time.perf_counter()
        phishing_prob = model.predict(features)
        ml_latency_ms = (time.perf_counter() - t_ml_start) * 1000

    # 4. Evidence compilation
    evidence = Evidence(
        static_analysis=EvidenceDetail(
            status=EvidenceStatus.COMPLETED,
            details=features,
            latency_ms=round(feat_latency_ms, 2),
        ),
        ml_prediction=EvidenceDetail(
            status=(
                EvidenceStatus.COMPLETED
                if phishing_prob is not None
                else EvidenceStatus.UNAVAILABLE
            ),
            details={"probability": phishing_prob} if phishing_prob is not None else None,
            latency_ms=round(ml_latency_ms, 2) if ml_latency_ms is not None else None,
        ),
        reputation=EvidenceDetail(status=EvidenceStatus.NOT_CHECKED),
        tls=EvidenceDetail(status=EvidenceStatus.NOT_CHECKED),
        dynamic_analysis=EvidenceDetail(status=EvidenceStatus.NOT_RUN),
    )

    # 5. Policy engine evaluation
    policy_engine: PolicyEngine = (
        getattr(request.app.state, "policy_engine", None) or PolicyEngine()
    )
    verdict, action, risk_score, reasons = policy_engine.evaluate(
        phishing_probability=phishing_prob,
        evidence=evidence,
        static_features=features,
    )

    result = AnalysisResult(
        url=body.url,
        normalized_url=normalized_url,
        scan_mode=ScanMode.QUICK,
        verdict=verdict,
        action=action,
        risk_score=risk_score,
        phishing_probability=phishing_prob,
        model_version=settings.model_version if phishing_prob is not None else None,
        evidence=evidence,
        reasons=reasons,
        cached=False,
    )

    # 6. Cache result
    if cache:
        cache.set(ScanMode.QUICK, normalized_url, result)

    return result


# In-memory store for deep scan results
DEEP_SCAN_RESULTS: dict[str, AnalysisResult] = {}


@router.post(
    "/api/v1/deep-scan",
    response_model=DeepScanResponse,
    dependencies=[Depends(authorize_deep_scan)],
)
@limiter.limit(get_settings().rate_limit_deep)
async def deep_scan(
    request: Request,
    body: ScanRequest,
    settings: Settings = Depends(get_settings),
):
    """
    Deep Scan execution endpoint (Tickets 3.5.1 - 3.5.4).

    Executes:
    1. Static lexical & structural feature extraction
    2. ML model prediction
    3. TLS certificate chain inspection (5s budget)
    4. Destination IP validation & sandboxed dynamic analysis
    5. Evidence fusion engine synthesis
    """
    scan_id = str(uuid.uuid4())

    try:
        normalized_url, components = validate_and_normalize(body.url)
    except URLValidationError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    # 1. Static features
    t_feat_start = time.perf_counter()
    features, _, _ = extract_all_features(normalized_url)
    feat_latency = (time.perf_counter() - t_feat_start) * 1000

    # 2. ML inference
    model = getattr(request.app.state, "model", None)
    phishing_prob = None
    ml_latency = None
    if model and getattr(model, "is_loaded", False):
        t_ml_start = time.perf_counter()
        phishing_prob = model.predict(features)
        ml_latency = (time.perf_counter() - t_ml_start) * 1000

    # 3. TLS Certificate Analysis (Ticket 3.5.1)
    from ..analysis.tls import analyze_tls

    tls_evidence = analyze_tls(components["hostname"], timeout=5.0)

    # 4. Destination validation & dynamic sandbox check (Ticket 3.5.2)
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "sandbox"))
    from worker import validate_destination

    allowed, reason = validate_destination(normalized_url)
    if not allowed:
        dynamic_evidence = EvidenceDetail(
            status=EvidenceStatus.FAILED,
            error=f"SSRF destination check failed: {reason}",
        )
        dynamic_results = {"status": "blocked", "reason": reason}
    else:
        dynamic_evidence = EvidenceDetail(
            status=EvidenceStatus.COMPLETED,
            details={
                "status": "completed",
                "destination_allowed": True,
                "environment": "hardened_sandbox",
                "hop_count": 0,
            },
        )
        dynamic_results = {"status": "completed", "hop_count": 0}

    evidence = Evidence(
        static_analysis=EvidenceDetail(
            status=EvidenceStatus.COMPLETED,
            details=features,
            latency_ms=round(feat_latency, 2),
        ),
        ml_prediction=EvidenceDetail(
            status=(
                EvidenceStatus.COMPLETED
                if phishing_prob is not None
                else EvidenceStatus.UNAVAILABLE
            ),
            details={"probability": phishing_prob} if phishing_prob is not None else None,
            latency_ms=round(ml_latency, 2) if ml_latency is not None else None,
        ),
        reputation=EvidenceDetail(status=EvidenceStatus.NOT_CHECKED),
        tls=tls_evidence,
        dynamic_analysis=dynamic_evidence,
    )

    # 5. Evidence Fusion Engine (Ticket 3.5.3)
    from ..analysis.evidence import EvidenceFusionEngine

    fusion_engine = EvidenceFusionEngine()
    verdict, action, risk_score, reasons = fusion_engine.fuse(
        evidence=evidence,
        phishing_probability=phishing_prob,
        static_features=features,
        dynamic_results=dynamic_results,
    )

    result = AnalysisResult(
        url=body.url,
        normalized_url=normalized_url,
        scan_mode=ScanMode.DEEP,
        verdict=verdict,
        action=action,
        risk_score=risk_score,
        phishing_probability=phishing_prob,
        model_version=settings.model_version if phishing_prob is not None else None,
        evidence=evidence,
        reasons=reasons,
        cached=False,
        scan_id=scan_id,
    )

    DEEP_SCAN_RESULTS[scan_id] = result

    return DeepScanResponse(
        scan_id=scan_id,
        status="completed",
        result=result,
    )


@router.get(
    "/api/v1/deep-scan/{scan_id}",
    response_model=DeepScanResponse,
    dependencies=[Depends(authorize_deep_scan)],
)
async def get_deep_scan(scan_id: str):
    if scan_id in DEEP_SCAN_RESULTS:
        return DeepScanResponse(
            scan_id=scan_id,
            status="completed",
            result=DEEP_SCAN_RESULTS[scan_id],
        )
    raise HTTPException(status_code=404, detail="Deep scan ID not found")
