import pytest

from backend.app.features.normalize import URLValidationError, validate_and_normalize


class TestURLValidation:
    def test_empty_url(self):
        with pytest.raises(URLValidationError, match="Empty"):
            validate_and_normalize("")

    def test_whitespace_only(self):
        with pytest.raises(URLValidationError, match="Empty"):
            validate_and_normalize("   ")

    def test_url_too_long(self):
        with pytest.raises(URLValidationError, match="maximum length"):
            validate_and_normalize("https://example.com/" + "a" * 2048)

    def test_unsupported_scheme_ftp(self):
        with pytest.raises(URLValidationError, match="Unsupported scheme"):
            validate_and_normalize("ftp://evil.com")

    def test_javascript_scheme(self):
        with pytest.raises(URLValidationError, match="Unsupported scheme"):
            validate_and_normalize("javascript:alert(1)")

    def test_data_scheme(self):
        with pytest.raises(URLValidationError, match="Unsupported scheme"):
            validate_and_normalize("data:text/html,<h1>phish</h1>")

    def test_no_hostname(self):
        with pytest.raises(URLValidationError):
            validate_and_normalize("https://")

    def test_malformed_port(self):
        with pytest.raises(URLValidationError, match="[Pp]ort"):
            validate_and_normalize("https://example.com:notaport/path")

    # --- Normalization tests ---

    def test_uppercase_scheme(self):
        """Regression: v1 failed on uppercase schemes."""
        url, comp = validate_and_normalize("HTTPS://Example.COM/Path")
        assert url == "https://example.com/Path"
        assert comp["scheme"] == "https"
        assert comp["hostname"] == "example.com"

    def test_mixed_case_scheme(self):
        url, _ = validate_and_normalize("Http://Example.COM/")
        assert url.startswith("http://example.com")

    def test_no_scheme_adds_https(self):
        url, comp = validate_and_normalize("example.com")
        assert url == "https://example.com/"
        assert comp["scheme"] == "https"

    def test_trailing_dot_removed(self):
        url, comp = validate_and_normalize("https://example.com./path")
        assert comp["hostname"] == "example.com"

    def test_fragment_dropped(self):
        url, _ = validate_and_normalize("https://example.com/page#section")
        assert "#" not in url

    def test_path_defaults_to_slash(self):
        url, comp = validate_and_normalize("https://example.com")
        assert comp["path"] == "/"

    # --- Special URL types ---

    def test_ipv4_host(self):
        url, comp = validate_and_normalize("http://192.168.1.1/admin")
        assert comp["is_ipv4"] is True
        assert comp["is_ip_address"] is True

    def test_ipv6_host(self):
        url, comp = validate_and_normalize("http://[::1]/admin")
        assert comp["is_ipv6"] is True
        assert comp["is_ip_address"] is True

    def test_credentials_in_url(self):
        """Credentials are flagged, not silently stripped."""
        url, comp = validate_and_normalize("https://user:pass@evil.example.com/login")
        assert comp["has_credentials"] is True

    def test_punycode_domain(self):
        url, comp = validate_and_normalize("https://xn--pple-43d.com/")
        assert comp["hostname"] == "xn--pple-43d.com"

    # --- tldextract-based parsing ---

    def test_registered_domain_extraction(self):
        _, comp = validate_and_normalize("https://login.mail.example.co.uk/path")
        assert comp["registered_domain"] == "example.co.uk"
        assert comp["subdomain"] == "login.mail"

    def test_multi_part_suffix(self):
        """tldextract handles multi-part TLDs; dot counting would fail."""
        _, comp = validate_and_normalize("https://foo.bar.co.uk")
        assert comp["suffix"] == "co.uk"
        assert comp["registered_domain"] == "bar.co.uk"

    def test_deceptive_hostname(self):
        """paypal.com@evil.example — credentials section, not subdomain."""
        _, comp = validate_and_normalize("https://paypal.com@evil.example.com/login")
        assert comp["has_credentials"] is True
        assert comp["hostname"] == "evil.example.com"
