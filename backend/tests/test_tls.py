"""
Unit tests for TLS certificate analyzer (Ticket 3.5.1).
"""
import ssl
from unittest.mock import MagicMock, patch

from backend.app.analysis.tls import analyze_tls
from backend.app.schemas.analysis import EvidenceStatus


class TestTLSAnalyzer:
    def test_mock_valid_tls(self):
        mock_sock = MagicMock()
        mock_sock.__enter__.return_value = mock_sock
        mock_ssock = MagicMock()
        mock_ssock.__enter__.return_value = mock_ssock
        mock_ssock.getpeercert.return_value = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("organizationName", "Example CA"),),),
            "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
            "notBefore": "Jan  1 00:00:00 2026 GMT",
            "notAfter": "Dec 31 23:59:59 2026 GMT",
        }
        mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssock.version.return_value = "TLSv1.3"

        with (
            patch("socket.create_connection", return_value=mock_sock),
            patch("ssl.SSLContext.wrap_socket", return_value=mock_ssock),
        ):
            res = analyze_tls("example.com")

        assert res.status == EvidenceStatus.COMPLETED
        assert res.details["valid"] is True
        assert res.details["issuer"] == "Example CA"
        assert res.details["common_name"] == "example.com"
        assert "example.com" in res.details["subject_alt_names"]

    def test_mock_cert_verification_error(self):
        with (
            patch("socket.create_connection"),
            patch(
                "ssl.SSLContext.wrap_socket",
                side_effect=ssl.SSLCertVerificationError("Certificate verify failed"),
            ),
        ):
            res = analyze_tls("self-signed.badssl.com")

        assert res.status == EvidenceStatus.COMPLETED
        assert res.details["valid"] is False
        assert res.details["error"] == "certificate_verification_failed"

    def test_mock_timeout_error(self):
        with (
            patch("socket.create_connection", side_effect=TimeoutError("timed out")),
        ):
            res = analyze_tls("slow-host.com", timeout=1.0)

        assert res.status == EvidenceStatus.TIMEOUT

    def test_mock_connection_refused(self):
        with (
            patch(
                "socket.create_connection",
                side_effect=ConnectionRefusedError("Connection refused"),
            ),
        ):
            res = analyze_tls("closed-port.com", port=443)

        assert res.status == EvidenceStatus.FAILED
