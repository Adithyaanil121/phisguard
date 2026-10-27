import pytest
from pydantic import ValidationError


def test_settings_requires_api_key(monkeypatch):
    """App must not start without an API key."""
    monkeypatch.delenv("PHISHGUARD_API_KEY", raising=False)
    # Clear the lru_cache
    from backend.app.core.config import Settings, get_settings
    get_settings.cache_clear()
    with pytest.raises(ValidationError):
        Settings(_env_file=None)  # Don't read .env in tests


def test_settings_loads_with_api_key(monkeypatch):
    """All defaults load correctly when only the API key is provided."""
    monkeypatch.setenv("PHISHGUARD_API_KEY", "test-key-12345")
    from backend.app.core.config import Settings
    s = Settings(_env_file=None)
    assert s.api_key == "test-key-12345"
    assert s.host == "127.0.0.1"
    assert s.port == 8000
    assert s.cache_ttl_seconds == 300


def test_settings_does_not_have_default_api_key():
    """Verify there's no sneaky default that would let it pass without env."""
    from backend.app.core.config import Settings
    # Check that 'api_key' has no default
    field = Settings.model_fields["api_key"]
    assert field.is_required()
