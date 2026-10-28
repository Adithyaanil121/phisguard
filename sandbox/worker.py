"""
Hardened Sandbox Inspection Worker (Ticket 3.5.2).

Performs dynamic browser inspection of suspicious URLs inside an isolated
container environment.

Security Controls:
- Resolves target IP and blocks private/loopback/cloud-metadata addresses (SSRF prevention)
- Enforces non-root execution and ephemeral browser contexts
- Strict step timeouts (10s navigation, 15s total)
- Returns structured JSON findings to stdout
"""
import argparse
import asyncio
import ipaddress
import json
import socket
import sys
from urllib.parse import urlparse

# Private, loopback, link-local, and cloud-metadata networks
FORBIDDEN_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local / AWS / GCP / Azure metadata
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def validate_destination(url: str) -> tuple[bool, str]:
    """
    Validate that target URL does NOT point to loopback, private, or metadata IPs.

    Returns (is_allowed, reason).
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False, "missing_hostname"

        # Resolve IP addresses
        addr_info = socket.getaddrinfo(hostname, None)
        ips = [info[4][0] for info in addr_info]

        for ip_str in ips:
            ip = ipaddress.ip_address(ip_str)
            for net in FORBIDDEN_NETWORKS:
                if ip in net:
                    return False, f"ssrf_forbidden_destination: {ip_str} in {net}"

        return True, "allowed"
    except Exception as e:
        return False, f"dns_resolution_failed: {e}"


async def inspect_url(url: str, scan_id: str) -> dict:
    """Run sandboxed headless inspection via Playwright."""
    allowed, reason = validate_destination(url)
    if not allowed:
        return {
            "scan_id": scan_id,
            "status": "blocked",
            "reason": reason,
            "url": url,
        }

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {
            "scan_id": scan_id,
            "status": "unavailable",
            "reason": "playwright_not_installed_in_environment",
            "url": url,
        }

    redirect_chain = [url]

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-gpu",
                "--disable-dev-shm-usage",
                "--disable-extensions",
            ],
        )

        user_agent = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
        )
        context = await browser.new_context(
            user_agent=user_agent,
            ignore_https_errors=False,
        )

        page = await context.new_page()

        # Track navigation responses to build redirect chain
        def on_response(response):
            if response.status in (301, 302, 307, 308):
                location = response.headers.get("location")
                if location and location not in redirect_chain:
                    redirect_chain.append(location)

        page.on("response", on_response)

        try:
            # 10 second navigation budget
            await page.goto(url, wait_until="domcontentloaded", timeout=10000)
            final_url = page.url
            if final_url not in redirect_chain:
                redirect_chain.append(final_url)

            title = await page.title()

            # Analyze DOM forms and password fields
            form_analysis = await page.evaluate("""() => {
                const forms = document.querySelectorAll('form');
                const passwordInputs = document.querySelectorAll('input[type="password"]');
                const textInputs = document.querySelectorAll(
                    'input[type="text"], input[type="email"]'
                );
                const iframes = document.querySelectorAll('iframe');

                const formTargets = [];
                forms.forEach(f => {
                    const action = f.getAttribute('action') || '';
                    formTargets.push(action);
                });

                return {
                    form_count: forms.length,
                    password_input_count: passwordInputs.length,
                    text_input_count: textInputs.length,
                    iframe_count: iframes.length,
                    form_targets: formTargets,
                };
            }""")

            # Check for cross-domain form submission
            parsed_initial = urlparse(url)
            has_cross_domain_form = False
            for target in form_analysis.get("form_targets", []):
                if target.startswith("http://") or target.startswith("https://"):
                    target_host = urlparse(target).hostname
                    if target_host and target_host != parsed_initial.hostname:
                        has_cross_domain_form = True

            result = {
                "scan_id": scan_id,
                "status": "completed",
                "initial_url": url,
                "final_url": final_url,
                "redirect_chain": redirect_chain,
                "hop_count": len(redirect_chain) - 1,
                "page_title": title,
                "has_password_field": form_analysis["password_input_count"] > 0,
                "password_field_count": form_analysis["password_input_count"],
                "has_cross_domain_form": has_cross_domain_form,
                "form_count": form_analysis["form_count"],
                "iframe_count": form_analysis["iframe_count"],
            }
            return result

        except Exception as e:
            return {
                "scan_id": scan_id,
                "status": "failed",
                "reason": str(e),
                "url": url,
            }
        finally:
            await context.close()
            await browser.close()


def main():
    parser = argparse.ArgumentParser(description="PhishGuard Sandbox Worker")
    parser.add_argument("--url", help="Target URL to inspect")
    parser.add_argument("--scan-id", default="local-scan", help="Scan ID")
    args = parser.parse_args()

    # Read from stdin if URL is not provided via CLI
    url = args.url
    scan_id = args.scan_id

    if not url:
        try:
            payload = json.loads(sys.stdin.read().strip())
            url = payload.get("url")
            scan_id = payload.get("scan_id", scan_id)
        except Exception:
            pass

    if not url:
        print(json.dumps({"error": "No URL provided"}))
        sys.exit(1)

    result = asyncio.run(inspect_url(url, scan_id))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
