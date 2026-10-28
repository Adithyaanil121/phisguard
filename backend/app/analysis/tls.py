"""
TLS Certificate analyzer (Ticket 3.5.1).

Inspects TLS certificates for Deep Scan:
- HTTPS availability and negotiation
- Certificate validity period (not_before, not_after)
- Hostname match (SAN / CN)
- Certificate issuer and cipher suite
- Enforces strict 5-second timeout
- Does NOT disable certificate verification
- Note: A valid certificate is supporting evidence, NOT proof of safety.
"""
import socket
import ssl
import time
from datetime import UTC, datetime
from typing import Any

from ..schemas.analysis import EvidenceDetail, EvidenceStatus


def analyze_tls(
    hostname: str,
    port: int = 443,
    timeout: float = 5.0,
) -> EvidenceDetail:
    """
    Connect to hostname:port using TLS and inspect certificate.

    Returns:
        EvidenceDetail with status and extracted TLS metadata.
    """
    start_time = time.perf_counter()

    # Use strict system trust store; DO NOT disable verification
    context = ssl.create_default_context()

    try:
        with (
            socket.create_connection((hostname, port), timeout=timeout) as sock,
            context.wrap_socket(sock, server_hostname=hostname) as ssock,
        ):
            cert: dict[str, Any] = ssock.getpeercert()
            cipher = ssock.cipher()
            version = ssock.version()

            latency_ms = (time.perf_counter() - start_time) * 1000

            # Extract SAN (Subject Alternative Names)
            san = [
                entry[1]
                for entry in cert.get("subjectAltName", ())
                if entry[0] == "DNS"
            ]

            # Extract Subject CN
            subject = dict(x[0] for x in cert.get("subject", ()))
            common_name = subject.get("commonName")

            # Extract Issuer
            issuer = dict(x[0] for x in cert.get("issuer", ()))
            issuer_org = issuer.get("organizationName", issuer.get("commonName", "Unknown"))

            not_before = cert.get("notBefore")
            not_after = cert.get("notAfter")

                # Calculate days until expiration
            days_remaining = None
            if not_after:
                try:
                    exp_dt = datetime.strptime(
                        not_after, "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=UTC)
                    days_remaining = (exp_dt - datetime.now(UTC)).days
                except Exception:
                    pass

            details = {
                "valid": True,
                "version": version,
                "cipher": cipher[0] if cipher else None,
                "issuer": issuer_org,
                "common_name": common_name,
                "subject_alt_names": san[:10],
                "not_before": not_before,
                "not_after": not_after,
                "days_until_expiration": days_remaining,
                "is_expired": days_remaining is not None and days_remaining < 0,
                "hostname_match": True,
            }

            return EvidenceDetail(
                status=EvidenceStatus.COMPLETED,
                details=details,
                latency_ms=round(latency_ms, 2),
            )

    except TimeoutError:
        latency_ms = (time.perf_counter() - start_time) * 1000
        return EvidenceDetail(
            status=EvidenceStatus.TIMEOUT,
            error=f"TLS handshake timed out after {timeout}s",
            latency_ms=round(latency_ms, 2),
        )
    except ssl.SSLCertVerificationError as e:
        latency_ms = (time.perf_counter() - start_time) * 1000
        return EvidenceDetail(
            status=EvidenceStatus.COMPLETED,
            details={
                "valid": False,
                "error": "certificate_verification_failed",
                "message": str(e),
                "hostname_match": False,
            },
            latency_ms=round(latency_ms, 2),
        )
    except ssl.SSLError as e:
        latency_ms = (time.perf_counter() - start_time) * 1000
        return EvidenceDetail(
            status=EvidenceStatus.COMPLETED,
            details={
                "valid": False,
                "error": "ssl_handshake_error",
                "message": str(e),
            },
            latency_ms=round(latency_ms, 2),
        )
    except (socket.gaierror, ConnectionRefusedError, OSError) as e:
        latency_ms = (time.perf_counter() - start_time) * 1000
        return EvidenceDetail(
            status=EvidenceStatus.FAILED,
            error=f"Connection failed: {e}",
            latency_ms=round(latency_ms, 2),
        )
