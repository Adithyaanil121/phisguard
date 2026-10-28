"""
Unit and integration tests for Quick Scan API (Tickets 3.1 & 3.2).

Verifies:
- Full AnalysisResult returned matching defined schema
- Invalid URLs return 400
- Cache hit returns cached: true
- ML model prediction integration
- Degraded mode without ML model
- Health and model-info endpoints
"""
import time
from unittest.mock import MagicMock

import pytest
from httpx import ASGITransport, AsyncClient

from backend.app.core.config import get_settings
from backend.app.main import create_app
from backend.app.schemas.analysis import Action, ScanMode, Verdict


@pytest.fixture()
def app_with_model():
    app = create_app()
    # Mock inference engine on app.state
    mock_model = MagicMock()
    mock_model.is_loaded = True
    mock_model.predict.return_value = 0.05
    mock_model.model_info.return_value = {
        "loaded": True,
        "model_name": "mock_rf",
        "feature_count": 31,
    }
    app.state.model = mock_model
    app.state.model_loaded = True
    return app


@pytest.fixture()
def app_degraded():
    app = create_app()
    app.state.model = None
    app.state.model_loaded = False
    return app


@pytest.fixture()
def auth_headers():
    settings = get_settings()
    return {
        "X-API-Key": str(settings.api_key),
        "Origin": settings.allowed_origins[0],
    }


@pytest.mark.asyncio()
async def test_quick_scan_success(app_with_model, auth_headers):
    transport = ASGITransport(app=app_with_model)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        t0 = time.perf_counter()
        resp = await client.post(
            "/api/v1/check-url",
            json={"url": "https://example.com/login"},
            headers=auth_headers,
        )
        latency_ms = (time.perf_counter() - t0) * 1000

    assert resp.status_code == 200
    data = resp.json()

    assert data["url"] == "https://example.com/login"
    assert data["normalized_url"] == "https://example.com/login"
    assert data["scan_mode"] == ScanMode.QUICK
    assert data["cached"] is False
    assert "verdict" in data
    assert "action" in data
    assert "risk_score" in data
    assert data["evidence"]["static_analysis"]["status"] == "completed"
    assert data["evidence"]["ml_prediction"]["status"] == "completed"
    assert data["evidence"]["reputation"]["status"] == "not_checked"
    assert data["evidence"]["tls"]["status"] == "not_checked"
    assert data["evidence"]["dynamic_analysis"]["status"] == "not_run"
    assert latency_ms < 200.0, f"Quick scan too slow: {latency_ms:.2f}ms"


@pytest.mark.asyncio()
async def test_quick_scan_cache_hit(app_with_model, auth_headers):
    transport = ASGITransport(app=app_with_model)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # First call: populates cache
        resp1 = await client.post(
            "/api/v1/check-url",
            json={"url": "https://example.org/about"},
            headers=auth_headers,
        )
        assert resp1.status_code == 200
        assert resp1.json()["cached"] is False

        # Second call: cache hit
        resp2 = await client.post(
            "/api/v1/check-url",
            json={"url": "https://example.org/about"},
            headers=auth_headers,
        )
        assert resp2.status_code == 200
        assert resp2.json()["cached"] is True
        assert resp2.json()["url"] == resp1.json()["url"]


@pytest.mark.asyncio()
async def test_quick_scan_invalid_url_returns_400(app_with_model, auth_headers):
    transport = ASGITransport(app=app_with_model)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/check-url",
            json={"url": "ftp://bad-scheme.com"},
            headers=auth_headers,
        )
    assert resp.status_code == 400


@pytest.mark.asyncio()
async def test_quick_scan_degraded_mode(app_degraded, auth_headers):
    transport = ASGITransport(app=app_degraded)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/check-url",
            json={"url": "https://example.com/"},
            headers=auth_headers,
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["phishing_probability"] is None
    assert data["evidence"]["ml_prediction"]["status"] == "unavailable"
    assert data["evidence"]["static_analysis"]["status"] == "completed"
    # Degraded mode caps at SUSPICIOUS/WARN, never NO_KNOWN_THREAT
    assert data["verdict"] in (Verdict.SUSPICIOUS, Verdict.HIGH_RISK, Verdict.PHISHING)
    assert data["action"] in (Action.WARN, Action.BLOCK)


@pytest.mark.asyncio()
async def test_health_endpoint(app_with_model):
    transport = ASGITransport(app=app_with_model)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
    assert resp.json()["model_loaded"] is True


@pytest.mark.asyncio()
async def test_model_info_endpoint(app_with_model, auth_headers):
    transport = ASGITransport(app=app_with_model)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/model-info", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "model_version" in data or "version" in data
