from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from mcpshield.checks.base import BaseCheck
from mcpshield.models import MCPServerConfig, SecurityFinding, Severity, TransportType

# Env-var names that suggest an auth token/key is present
_AUTH_ENV_PATTERNS: re.Pattern[str] = re.compile(
    r"(AUTH|TOKEN|API_KEY|BEARER|SECRET|PASSWORD|CREDENTIAL|APIKEY|X_API)",
    re.IGNORECASE,
)

# Env-var names that are specifically header-forwarding conventions
_AUTH_HEADER_PATTERNS: re.Pattern[str] = re.compile(
    r"(AUTHORIZATION|X_AUTH|HTTP_AUTHORIZATION|HEADER)",
    re.IGNORECASE,
)

# IPv4 addresses that indicate a publicly routable or catch-all binding
_PUBLIC_CATCH_ALL_PATTERN: re.Pattern[str] = re.compile(
    r"^(0\.0\.0\.0|0:0:0:0:0:0:0:0|::)$"
)


def _is_remote_transport(server: MCPServerConfig) -> bool:
    return server.transport in (TransportType.SSE, TransportType.HTTP)


def _has_auth_signal(server: MCPServerConfig) -> bool:
    """Return True if any env var key looks like an auth-related credential."""
    for key in server.env:
        if _AUTH_ENV_PATTERNS.search(key):
            return True
        if _AUTH_HEADER_PATTERNS.search(key):
            return True
    return False


def _parse_hostname(url: str) -> str | None:
    try:
        return urlparse(url).hostname or None
    except Exception:
        return None


def _is_public_ip(hostname: str) -> bool:
    """Return True if the hostname is a public or catch-all IP address."""
    if _PUBLIC_CATCH_ALL_PATTERN.match(hostname):
        return True
    try:
        addr = ipaddress.ip_address(hostname)
        # Not private/loopback/link-local → publicly routable
        return not (addr.is_private or addr.is_loopback or addr.is_link_local)
    except ValueError:
        # hostname is a DNS name — we can't determine routability statically
        return False


class AuthenticationCheck(BaseCheck):
    """Detect authentication weaknesses in remote MCP server configurations."""

    check_id = "AUTH001"
    name = "Authentication Check"
    description = (
        "Checks SSE and streamable-http servers for missing or weak authentication "
        "indicators, insecure transport schemes, and publicly exposed endpoints."
    )

    async def run(self, server: MCPServerConfig) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []

        if not _is_remote_transport(server):
            # stdio servers are out of scope for these checks
            return findings

        url = server.url or ""

        # ------------------------------------------------------------------ #
        # 1. HTTP instead of HTTPS                                             #
        # ------------------------------------------------------------------ #
        parsed = urlparse(url) if url else None
        if parsed and parsed.scheme == "http":
            findings.append(
                SecurityFinding(
                    check_id=self.check_id,
                    severity=Severity.HIGH,
                    title="Server uses plaintext HTTP transport",
                    description=(
                        f"Server '{server.name}' communicates over HTTP ({url}). "
                        "All traffic — including any authentication credentials — "
                        "is transmitted in plaintext and is vulnerable to "
                        "interception and man-in-the-middle attacks."
                    ),
                    remediation=(
                        "Change the server URL to use HTTPS and ensure the server "
                        "is configured with a valid TLS certificate."
                    ),
                )
            )

        # ------------------------------------------------------------------ #
        # 2. Binding to 0.0.0.0 or a public IP                               #
        # ------------------------------------------------------------------ #
        if url:
            hostname = _parse_hostname(url)
            if hostname and _is_public_ip(hostname):
                findings.append(
                    SecurityFinding(
                        check_id=self.check_id,
                        severity=Severity.HIGH,
                        title="Server bound to a publicly accessible address",
                        description=(
                            f"Server '{server.name}' is configured with URL "
                            f"'{url}' which resolves to '{hostname}'. "
                            "Binding to 0.0.0.0 or a public IP exposes the MCP "
                            "server to all network interfaces, including untrusted "
                            "external networks."
                        ),
                        remediation=(
                            "Restrict the server to listen on localhost (127.0.0.1) "
                            "or a specific private interface. Place it behind a "
                            "reverse proxy with authentication if external access "
                            "is required."
                        ),
                    )
                )

        # ------------------------------------------------------------------ #
        # 3. No authentication indicators in env vars                         #
        # ------------------------------------------------------------------ #
        if not _has_auth_signal(server):
            findings.append(
                SecurityFinding(
                    check_id=self.check_id,
                    severity=Severity.MEDIUM,
                    title="No authentication credentials detected in server config",
                    description=(
                        f"Server '{server.name}' uses a remote transport "
                        f"('{server.transport.value}') but no environment variables "
                        "that suggest authentication tokens, API keys, or bearer "
                        "credentials were found. The server may be accessible "
                        "without authentication."
                    ),
                    remediation=(
                        "Add authentication to the MCP server and supply the "
                        "required token or API key via a dedicated environment "
                        "variable (e.g., MCP_AUTH_TOKEN). Verify that the server "
                        "enforces authentication on every endpoint."
                    ),
                )
            )

        return findings
