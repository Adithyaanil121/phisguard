"""
End-to-End full stack integration tests (Ticket 3.4).

Spins up the full FastAPI application with lifespan context, loading
the actual trained Random Forest model (models/phishguard_v1.joblib),
and tests realistic end-to-end scanning workflows.
"""
from pathlib import Path

import httpx
import pytest

from backend.app.core.config import get_settings
from backend.app.main import create_app
from backend.app.schemas.analysis import Action, AnalysisResult, ScanMode, Verdict


@pytest.fixture()
def full_app():
    # Load app with real models and components
    app = create_app()
    settings = get_settings()
    model_file = Path(settings.model_path)
    if model_file.exists():
        from backend.app.ml.model_loader import load_model

        app.state.model = load_model(str(model_file))
        app.state.model_loaded = True
    return app


@pytest.fixture()
def auth_headers():
    settings = get_settings()
    return {
        "X-API-Key": str(settings.api_key),
        "Origin": settings.allowed_origins[0],
    }


@pytest.mark.asyncio()
async def test_e2e_benign_url_scan(full_app, auth_headers):
    """End-to-end scan of a benign URL with real ML model inference."""
    model_path = Path("models/phishguard_v1.joblib")
    if not model_path.exists():
        pytest.skip("models/phishguard_v1.joblib not found")

    transport = httpx.ASGITransport(app=full_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Initial health check
        health_resp = await client.get("/health")
        assert health_resp.status_code == 200

        # Scan benign URL
        resp = await client.post(
            "/api/v1/check-url",
            json={"url": "https://example.com/about"},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()

        # Validate against schema
        result = AnalysisResult.model_validate(data)
        assert result.scan_mode == ScanMode.QUICK
        assert result.verdict in (Verdict.NO_KNOWN_THREAT, Verdict.LOW_RISK)
        assert result.action == Action.ALLOW
        assert result.risk_score < 50
        assert result.cached is False

        # Evidence assertions
        assert result.evidence.static_analysis.status == "completed"
        assert result.evidence.ml_prediction.status == "completed"
        assert result.evidence.reputation.status == "not_checked"
        assert result.evidence.tls.status == "not_checked"
        assert result.evidence.dynamic_analysis.status == "not_run"


@pytest.mark.asyncio()
async def test_e2e_phishing_url_scan(full_app, auth_headers):
    """End-to-end scan of a clear phishing attempt with brand mismatch."""
    model_path = Path("models/phishguard_v1.joblib")
    if not model_path.exists():
        pytest.skip("models/phishguard_v1.joblib not found")

    transport = httpx.ASGITransport(app=full_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/check-url",
            json={"url": "https://login.paypal.com.evil.tk/verify?account=locked"},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()

        result = AnalysisResult.model_validate(data)
        assert result.verdict in (Verdict.HIGH_RISK, Verdict.PHISHING)
        assert result.action == Action.BLOCK
        assert result.risk_score >= 80
        assert result.phishing_probability is not None
        assert result.phishing_probability > 0.70
        assert len(result.reasons) > 0


@pytest.mark.asyncio()
async def test_e2e_caching_behavior(full_app, auth_headers):
    """Verify that scanning the same URL twice hits the cache with cached: true."""
    transport = httpx.ASGITransport(app=full_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        url = "https://test-cache-url.org/page?ref=home"

        # 1st call: computed
        resp1 = await client.post(
            "/api/v1/check-url",
            json={"url": url},
            headers=auth_headers,
        )
        assert resp1.status_code == 200
        assert resp1.json()["cached"] is False

        # 2nd call: cached
        resp2 = await client.post(
            "/api/v1/check-url",
            json={"url": url},
            headers=auth_headers,
        )
        assert resp2.status_code == 200
        assert resp2.json()["cached"] is True
        assert resp2.json()["url"] == url


@pytest.mark.asyncio()
async def test_e2e_auth_enforcement(full_app):
    """Verify authentication and origin checks are enforced."""
    transport = httpx.ASGITransport(app=full_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Missing API Key -> 401
        resp = await client.post("/api/v1/check-url", json={"url": "https://example.com"})
        assert resp.status_code == 401

        # Bad Origin -> 403
        settings = get_settings()
        resp2 = await client.post(
            "/api/v1/check-url",
            json={"url": "https://example.com"},
            headers={
                "X-API-Key": str(settings.api_key),
                "Origin": "http://evil-attacker.com",
            },
        )
        assert resp2.status_code == 403
