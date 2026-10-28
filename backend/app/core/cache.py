"""In-memory TTL cache for scan results."""
from typing import Any

from cachetools import TTLCache

from .config import get_settings


class ScanCache:
    """In-memory TTL cache keyed by scan_mode and URL."""

    def __init__(
        self,
        maxsize: int | None = None,
        ttl: int | None = None,
        ttl_seconds: int | None = None,
    ):
        settings = get_settings()
        effective_ttl = ttl_seconds if ttl_seconds is not None else ttl
        self._cache = TTLCache(
            maxsize=maxsize or settings.cache_max_size,
            ttl=effective_ttl or settings.cache_ttl_seconds,
        )

    def _make_key(self, arg1: Any, arg2: Any) -> str:
        # Support either (url, scan_mode) or (scan_mode, url)
        # Scan modes are 'quick' or 'deep' (or ScanMode enum)
        arg1_str = str(getattr(arg1, "value", arg1)).lower()
        arg2_str = str(getattr(arg2, "value", arg2)).lower()

        if arg1_str in ("quick", "deep"):
            return f"{arg1_str}:{arg2}"
        if arg2_str in ("quick", "deep"):
            return f"{arg2_str}:{arg1}"
        return f"{arg1_str}:{arg2}"

    def get(self, arg1: Any, arg2: Any) -> Any | None:
        """Retrieve scan result from cache."""
        key = self._make_key(arg1, arg2)
        return self._cache.get(key)

    def set(self, arg1: Any, arg2: Any, result: Any) -> None:
        """Store scan result in cache."""
        key = self._make_key(arg1, arg2)
        self._cache[key] = result

    def clear(self) -> None:
        """Clear all cached entries."""
        self._cache.clear()

    @property
    def size(self) -> int:
        """Number of items currently cached."""
        return len(self._cache)
