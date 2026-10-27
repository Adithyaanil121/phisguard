import httpx
import pytest
from fastapi import Depends, FastAPI

from backend.app.core.config import Settings, get_settings
from backend.app.core.security import (
    authorize_deep_scan,
    verify_api_key,
    verify_origin,
)

# Test Settings
TEST_SETTINGS = Settings(
    api_key="test-secret-key-9999",
    allowed_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    _env_file=None,
)


def get_test_settings() -> Settings:
    return TEST_SETTINGS


# Test application wiring the dependencies
app = FastAPI()
app.dependency_overrides[get_settings] = get_test_settings


@app.get("/test/quick", dependencies=[Depends(verify_api_key), Depends(verify_origin)])
async def quick_route():
    return {"status": "quick_ok"}


@app.get("/test/deep", dependencies=[Depends(authorize_deep_scan)])
async def deep_route():
    return {"status": "deep_ok"}


@pytest.mark.asyncio
async def test_missing_api_key():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/test/quick")
        assert response.status_code == 401
        assert response.json()["detail"] == "Missing API key"


@pytest.mark.asyncio
async def test_invalid_api_key():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/test/quick", headers={"X-API-Key": "wrong-key"})
        assert response.status_code == 403
        assert response.json()["detail"] == "Invalid API key"


@pytest.mark.asyncio
async def test_correct_api_key_passes():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            "/test/quick",
            headers={"X-API-Key": "test-secret-key-9999"},
        )
        assert response.status_code == 200
        assert response.json() == {"status": "quick_ok"}


@pytest.mark.asyncio
async def test_disallowed_origin():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            "/test/quick",
            headers={
                "X-API-Key": "test-secret-key-9999",
                "Origin": "http://evil-site.com",
            },
        )
        assert response.status_code == 403
        assert response.json()["detail"] == "Origin not allowed"


@pytest.mark.asyncio
async def test_missing_origin_allowed():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            "/test/quick",
            headers={"X-API-Key": "test-secret-key-9999"},
        )
        assert response.status_code == 200
        assert response.json() == {"status": "quick_ok"}


@pytest.mark.asyncio
async def test_allowed_origin():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            "/test/quick",
            headers={
                "X-API-Key": "test-secret-key-9999",
                "Origin": "http://localhost:3000",
            },
        )
        assert response.status_code == 200
        assert response.json() == {"status": "quick_ok"}


@pytest.mark.asyncio
async def test_deep_scan_without_api_key():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/test/deep")
        assert response.status_code == 401
        assert response.json()["detail"] == "Missing API key"


@pytest.mark.asyncio
async def test_deep_scan_with_valid_key_disallowed_origin():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            "/test/deep",
            headers={
                "X-API-Key": "test-secret-key-9999",
                "Origin": "http://malicious.com",
            },
        )
        assert response.status_code == 403
        assert response.json()["detail"] == "Origin not allowed"
