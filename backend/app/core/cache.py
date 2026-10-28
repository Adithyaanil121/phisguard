"""In-memory TTL cache for scan results."""
from cachetools import TTLCache

from .config import get_settings


class ScanCache:
    def __init__(self, maxsize: int | None = None, ttl: int | None = None):
        settings = get_settings()
        self._cache = TTLCache(
            maxsize=maxsize or settings.cache_max_size,
            ttl=ttl or settings.cache_ttl_seconds,
        )

    def get(self, url: str, scan_mode: str) -> dict | None:
        key = f"{scan_mode}:{url}"
        return self._cache.get(key)

    def set(self, url: str, scan_mode: str, result: dict) -> None:
        key = f"{scan_mode}:{url}"
        self._cache[key] = result

    def clear(self) -> None:
        self._cache.clear()

    @property
    def size(self) -> int:
        return len(self._cache)
