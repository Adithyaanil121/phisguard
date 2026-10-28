"""
Tests for False Positive reporting endpoint (Ticket 6.4).
"""
import pytest
from httpx import ASGITransport, AsyncClient

from backend.app.core.config import get_settings
from backend.app.main import create_app


@pytest.fixture()
def app():
    return create_app()


@pytest.fixture()
def auth_headers():
    settings = get_settings()
    return {
        "X-API-Key": str(settings.api_key),
        "Origin": settings.allowed_origins[0],
    }


@pytest.mark.asyncio()
async def test_report_fp_authorized(app, auth_headers, tmp_path, monkeypatch):
    test_file = tmp_path / "fp_reports.json"
    monkeypatch.setattr(
        "backend.app.api.routes.Path",
        lambda p: test_file if "false_positives" in str(p) else tmp_path / p,
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "url": "https://legitimate-bank-portal.example.com/login",
            "scan_id": "test-scan-1234",
            "comments": "Official corporate portal flagged erroneously.",
            "reporter": "analyst@example.com",
        }
        res = await client.post("/api/v1/report-fp", json=payload, headers=auth_headers)
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "recorded"
        assert "report_id" in data


@pytest.mark.asyncio()
async def test_report_fp_unauthorized(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {"url": "https://example.com"}
        res = await client.post("/api/v1/report-fp", json=payload)
        assert res.status_code == 401
