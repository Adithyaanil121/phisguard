import uuid

import httpx
import pytest
from fastapi import FastAPI

from backend.app.core.logging_config import (
    RequestLoggingMiddleware,
    configure_logging,
)


@pytest.fixture
def app_with_logging():
    configure_logging(log_level="DEBUG")
    app = FastAPI()
    app.add_middleware(RequestLoggingMiddleware)

    @app.get("/ping")
    async def ping():
        return {"ping": "pong"}

    return app


@pytest.mark.asyncio
async def test_request_logging_middleware_adds_header(app_with_logging):
    transport = httpx.ASGITransport(app=app_with_logging)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/ping")
        assert response.status_code == 200
        assert "X-Request-ID" in response.headers
        req_id = response.headers["X-Request-ID"]
        # Verify it is a valid UUID
        parsed_uuid = uuid.UUID(req_id)
        assert parsed_uuid.version == 4


@pytest.mark.asyncio
async def test_unique_request_ids_per_request(app_with_logging):
    transport = httpx.ASGITransport(app=app_with_logging)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        r1 = await client.get("/ping")
        r2 = await client.get("/ping")
        assert r1.headers["X-Request-ID"] != r2.headers["X-Request-ID"]
