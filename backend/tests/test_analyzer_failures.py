import httpx
import pytest

from backend.app.core.config import Settings, get_settings
from backend.app.main import app

# Dedicated test settings to ensure clean isolation
TEST_API_KEY = "test-analyzer-key-0123456789"
TEST_SETTINGS = Settings(
    api_key=TEST_API_KEY,
    allowed_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    rate_limit_quick="60/minute",
    _env_file=None,
)

app.dependency_overrides[get_settings] = lambda: TEST_SETTINGS

HEADERS = {
    "X-API-Key": TEST_API_KEY,
    "Origin": "http://localhost:3000",
}


@pytest.mark.asyncio
async def test_1_malformed_url():
    """Test 1: Malformed URL -> 400 validation error."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/check-url",
            json={"url": "https://example.com:notaport/test"},
            headers=HEADERS,
        )
        assert response.status_code == 400
        assert "port" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_2_unsupported_scheme():
    """Test 2: URL with unsupported scheme -> 400."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/check-url",
            json={"url": "ftp://evil.example.com/payload"},
            headers=HEADERS,
        )
        assert response.status_code == 400
        assert "unsupported scheme" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_3_missing_ml_model_null_probability():
    """Test 3: Missing ML model -> response includes phishing_probability: null, not a 500."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/check-url",
            json={"url": "https://example.com/login"},
            headers=HEADERS,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["phishing_probability"] is None
        assert data["verdict"] == "suspicious"


@pytest.mark.asyncio
async def test_4_missing_evidence_status_not_checked():
    """Test 4: Missing evidence -> status is 'not_checked', not a crash."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/check-url",
            json={"url": "https://example.com/test"},
            headers=HEADERS,
        )
        assert response.status_code == 200
        evidence = response.json()["evidence"]
        assert evidence["static_analysis"]["status"] == "completed"
        assert evidence["reputation"]["status"] == "not_checked"
        assert evidence["tls"]["status"] == "not_checked"
        assert evidence["dynamic_analysis"]["status"] == "not_run"


@pytest.mark.asyncio
async def test_5_unauthorized_call_no_key():
    """Test 5: Unauthorized call (no key) -> 401."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/check-url",
            json={"url": "https://example.com"},
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "Missing API key"


@pytest.mark.asyncio
async def test_6_unauthorized_call_wrong_key():
    """Test 6: Unauthorized call (wrong key) -> 403."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/check-url",
            json={"url": "https://example.com"},
            headers={"X-API-Key": "wrong-secret-key"},
        )
        assert response.status_code == 403
        assert response.json()["detail"] == "Invalid API key"


@pytest.mark.asyncio
async def test_7_oversized_request_body():
    """Test 7: Oversized request body (>1MB) -> 413."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        oversized_data = "x" * (1024 * 1024 + 10)
        response = await client.post(
            "/api/v1/check-url",
            content=oversized_data,
            headers={
                "X-API-Key": TEST_API_KEY,
                "Content-Type": "application/json",
                "Content-Length": str(len(oversized_data)),
            },
        )
        assert response.status_code == 413
        assert response.json()["detail"] == "Request body too large"


@pytest.mark.asyncio
async def test_8_deep_scan_execution():
    """Test 8: Deep scan execution -> returns completed status with scan_id and result."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/deep-scan",
            json={"url": "https://example.com"},
            headers=HEADERS,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "completed"
        assert "scan_id" in data
        assert data["result"]["scan_mode"] == "deep"
        assert data["result"]["evidence"]["tls"]["status"] in ("completed", "failed", "timeout")


@pytest.mark.asyncio
async def test_9_rate_limit_exceeded():
    """Test 9: Rate limit exceeded -> 429 when sending 61+ rapid requests."""
    rate_limit_key = "rate-limit-test-key-unique"
    temp_settings = Settings(
        api_key=rate_limit_key,
        allowed_origins=["http://localhost:3000"],
        rate_limit_quick="60/minute",
        _env_file=None,
    )
    app.dependency_overrides[get_settings] = lambda: temp_settings

    try:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            got_429 = False
            for _ in range(65):
                res = await client.post(
                    "/api/v1/check-url",
                    json={"url": "https://example.com/test"},
                    headers={
                        "X-API-Key": rate_limit_key,
                        "Origin": "http://localhost:3000",
                    },
                )
                if res.status_code == 429:
                    got_429 = True
                    assert res.json()["detail"] == "Rate limit exceeded"
                    break
            assert got_429, "Expected 429 Rate limit exceeded after 60 requests"
    finally:
        app.dependency_overrides[get_settings] = lambda: TEST_SETTINGS


@pytest.mark.asyncio
async def test_10_valid_request_shape_and_headers():
    """Test 10: Valid request with valid key -> 200 with expected shape & version header."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/check-url",
            json={"url": "https://example.com/path"},
            headers=HEADERS,
        )
        assert response.status_code == 200
        # Check custom version header
        assert response.headers.get("X-PhishGuard-Version") == "1.0.0"
        assert "X-Request-ID" in response.headers

        data = response.json()
        assert data["url"] == "https://example.com/path"
        assert data["normalized_url"] == "https://example.com/path"
        assert data["scan_mode"] == "quick"
        assert "verdict" in data
        assert "action" in data
        assert "risk_score" in data
        assert "scan_id" in data
        assert "timestamp" in data
