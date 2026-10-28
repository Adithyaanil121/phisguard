"""
PhishGuard API server.

- Binds to 127.0.0.1 (local development only)
- Requires PHISHGUARD_API_KEY to start
- Missing ML model → degraded state (model_loaded: false), not a crash
"""
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from .api.routes import router
from .core.config import get_settings
from .core.limiter import limiter
from .core.logging_config import RequestLoggingMiddleware, configure_logging


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: validate config, attempt model load. Shutdown: cleanup."""
    settings = get_settings()
    configure_logging(settings.log_level)
    logger = structlog.get_logger()

    logger.info("startup", host=settings.host, port=settings.port)

    # Initialize in-memory cache and policy engine
    from .core.cache import ScanCache
    from .core.policy import PolicyEngine

    app.state.cache = ScanCache(ttl_seconds=settings.cache_ttl_seconds)
    app.state.policy_engine = PolicyEngine()

    # Attempt model load — degraded state if missing, not crash
    try:
        from .ml.model_loader import load_model

        model = load_model(settings.model_path)
        app.state.model = model
        app.state.model_loaded = getattr(model, "is_loaded", True)
        logger.info("model_loaded", path=settings.model_path)
    except FileNotFoundError:
        app.state.model = None
        app.state.model_loaded = False
        logger.warning(
            "model_not_found",
            path=settings.model_path,
            message="Running in degraded mode: phishing_probability will be null",
        )
    except Exception as e:
        app.state.model = None
        app.state.model_loaded = False
        logger.error("model_load_failed", error=str(e))

    yield

    logger.info("shutdown")


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="PhishGuard",
        version="1.0.0",
        lifespan=lifespan,
    )

    from .core.cache import ScanCache
    from .core.policy import PolicyEngine

    app.state.cache = ScanCache(ttl_seconds=settings.cache_ttl_seconds)
    app.state.policy_engine = PolicyEngine()
    app.state.model = None
    app.state.model_loaded = False

    # CORS — defense in depth, NOT authentication
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["X-API-Key", "Content-Type"],
    )

    # Rate limiting
    app.state.limiter = limiter
    app.add_middleware(SlowAPIMiddleware)

    # Logging
    app.add_middleware(RequestLoggingMiddleware)

    # Request size limit (1MB)
    @app.middleware("http")
    async def limit_request_size(request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > 1_048_576:
            return JSONResponse(
                status_code=413,
                content={"detail": "Request body too large"},
            )
        return await call_next(request)

    # Version header
    @app.middleware("http")
    async def add_version_header(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-PhishGuard-Version"] = "1.0.0"
        return response

    # Rate limit error handler
    @app.exception_handler(RateLimitExceeded)
    async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded"},
        )

    app.include_router(router)
    return app


app = create_app()
