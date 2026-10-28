"""Rate limiting instance with key extraction."""
from slowapi import Limiter
from starlette.requests import Request


def get_rate_limit_key(request: Request) -> str:
    """Rate limit by API key, falling back to client IP."""
    api_key = request.headers.get("X-API-Key")
    if api_key:
        return api_key
    return request.client.host if request.client else "unknown"


limiter = Limiter(key_func=get_rate_limit_key)
