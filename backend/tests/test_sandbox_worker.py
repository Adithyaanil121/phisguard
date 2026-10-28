"""
Unit tests for sandbox destination validation and SSRF prevention (Ticket 3.5.2).
"""
import sys
from pathlib import Path

# Add sandbox directory to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "sandbox"))

from worker import validate_destination


class TestSandboxSSRFPrevention:
    def test_loopback_ip_blocked(self):
        allowed, reason = validate_destination("http://127.0.0.1/admin")
        assert allowed is False
        assert "ssrf_forbidden_destination" in reason

    def test_private_class_a_blocked(self):
        allowed, reason = validate_destination("http://10.0.1.5:8080/internal")
        assert allowed is False
        assert "ssrf_forbidden_destination" in reason

    def test_private_class_b_blocked(self):
        allowed, reason = validate_destination("http://172.16.50.1/")
        assert allowed is False
        assert "ssrf_forbidden_destination" in reason

    def test_private_class_c_blocked(self):
        allowed, reason = validate_destination("http://192.168.1.1/router")
        assert allowed is False
        assert "ssrf_forbidden_destination" in reason

    def test_cloud_metadata_service_blocked(self):
        allowed, reason = validate_destination("http://169.254.169.254/latest/meta-data")
        assert allowed is False
        assert "ssrf_forbidden_destination" in reason

    def test_localhost_hostname_blocked(self):
        allowed, reason = validate_destination("http://localhost:3000/api")
        assert allowed is False
        assert "ssrf_forbidden_destination" in reason

    def test_missing_hostname_rejected(self):
        allowed, reason = validate_destination("http:///no-host")
        assert allowed is False
        assert "missing_hostname" in reason

    def test_public_domain_allowed(self):
        allowed, reason = validate_destination("https://example.com/test")
        assert allowed is True
        assert reason == "allowed"
