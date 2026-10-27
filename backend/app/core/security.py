"""
Local API security: API key validation, origin checking, scan authorization.

Design decisions:
- verify_api_key: checks X-API-Key header using constant-time comparison.
- verify_origin: validates Origin header against allowed list.
  Called as a SEPARATE dependency on protected routes, not inside verify_api_key.
- authorize_deep_scan: requires both valid API key and origin check.
- Origin check allows missing Origin (non-browser clients like curl).
  CORS is not authentication; this is a defense-in-depth layer.
"""
import secrets

from fastapi import Depends, HTTPException, Request, Security
from fastapi.security import APIKeyHeader

from .config import Settings, get_settings

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(
    api_key: str | None = Security(API_KEY_HEADER),
    settings: Settings = Depends(get_settings),
) -> str:
    """Verify the API key from the request header."""
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing API key")
    if not secrets.compare_digest(api_key, settings.api_key):
        raise HTTPException(status_code=403, detail="Invalid API key")
    return api_key


async def verify_origin(
    request: Request,
    settings: Settings = Depends(get_settings),
) -> None:
    """
    Validate Origin header against allowed origins.
    Allows requests without an Origin header (non-browser clients).
    """
    origin = request.headers.get("origin")
    if origin is not None and origin not in settings.allowed_origins:
        raise HTTPException(status_code=403, detail="Origin not allowed")


async def authorize_deep_scan(
    _key: str = Depends(verify_api_key),
    _origin: None = Depends(verify_origin),
) -> str:
    """Deep Scan requires both valid API key and origin validation."""
    return _key
