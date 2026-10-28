import time

from backend.app.core.cache import ScanCache


def test_cached_result_returned_within_ttl():
    cache = ScanCache(maxsize=10, ttl=5)
    cache.set("https://example.com", "quick", {"verdict": "no_known_threat"})
    result = cache.get("https://example.com", "quick")
    assert result is not None
    assert result["verdict"] == "no_known_threat"


def test_result_evicted_after_ttl():
    cache = ScanCache(maxsize=10, ttl=0.1)
    cache.set("https://example.com", "quick", {"verdict": "no_known_threat"})
    time.sleep(0.2)
    result = cache.get("https://example.com", "quick")
    assert result is None


def test_quick_and_deep_results_cached_separately():
    cache = ScanCache(maxsize=10, ttl=5)
    url = "https://example.com"
    cache.set(url, "quick", {"mode": "quick"})
    cache.set(url, "deep", {"mode": "deep"})

    quick_res = cache.get(url, "quick")
    deep_res = cache.get(url, "deep")

    assert quick_res is not None
    assert quick_res["mode"] == "quick"
    assert deep_res is not None
    assert deep_res["mode"] == "deep"


def test_clear_empties_cache():
    cache = ScanCache(maxsize=10, ttl=5)
    cache.set("https://example1.com", "quick", {"v": 1})
    cache.set("https://example2.com", "quick", {"v": 2})
    assert cache.size == 2

    cache.clear()
    assert cache.size == 0
    assert cache.get("https://example1.com", "quick") is None
