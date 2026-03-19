"""Tests for AuthenticationCheck (AUTH001)."""
from __future__ import annotations

import pytest

from mcpshield.checks.auth_check import AuthenticationCheck
from mcpshield.models import MCPServerConfig, Severity, TransportType


@pytest.fixture()
def check() -> AuthenticationCheck:
    return AuthenticationCheck()


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


class TestAuthCheckMetadata:
    def test_check_id(self, check: AuthenticationCheck):
        assert check.check_id == "AUTH001"

    def test_name(self, check: AuthenticationCheck):
        assert check.name == "Authentication Check"

    def test_description_not_empty(self, check: AuthenticationCheck):
        assert check.description


# ---------------------------------------------------------------------------
# stdio servers — always clean (out of scope)
# ---------------------------------------------------------------------------


class TestStdioServers:
    async def test_stdio_no_findings(self, check: AuthenticationCheck):
        srv = MCPServerConfig(name="local", transport=TransportType.STDIO, command="python")
        findings = await check.run(srv)
        assert findings == []

    async def test_stdio_with_no_env_still_clean(self, check: AuthenticationCheck):
        srv = MCPServerConfig(name="local", transport=TransportType.STDIO, command="node")
        findings = await check.run(srv)
        assert findings == []


# ---------------------------------------------------------------------------
# Clean remote server (should produce zero findings)
# ---------------------------------------------------------------------------


class TestCleanRemoteServer:
    async def test_https_with_auth_env(self, check: AuthenticationCheck):
        srv = MCPServerConfig(
            name="secure",
            transport=TransportType.HTTP,
            url="https://api.example.com/mcp",
            env={"MCP_AUTH_TOKEN": "some-real-token-value"},
        )
        findings = await check.run(srv)
        assert findings == []

    async def test_sse_with_api_key_env(self, check: AuthenticationCheck):
        srv = MCPServerConfig(
            name="secure-sse",
            transport=TransportType.SSE,
            url="https://events.example.com/sse",
            env={"API_KEY": "abc123"},
        )
        findings = await check.run(srv)
        assert findings == []


# ---------------------------------------------------------------------------
# Finding 1: HTTP instead of HTTPS
# ---------------------------------------------------------------------------


class TestHttpFindings:
    async def test_http_url_triggers_high_finding(self, check: AuthenticationCheck):
        srv = MCPServerConfig(
            name="insecure",
            transport=TransportType.HTTP,
            url="http://api.example.com/mcp",
            env={"API_KEY": "token123"},
        )
        findings = await check.run(srv)
        http_findings = [f for f in findings if "plaintext HTTP" in f.title]
        assert len(http_findings) == 1
        assert http_findings[0].severity == Severity.HIGH
        assert http_findings[0].check_id == "AUTH001"

    async def test_https_url_no_http_finding(self, check: AuthenticationCheck):
        srv = MCPServerConfig(
            name="secure",
            transport=TransportType.HTTP,
            url="https://api.example.com/mcp",
            env={"API_KEY": "token123"},
        )
        findings = await check.run(srv)
        http_findings = [f for f in findings if "plaintext HTTP" in f.title]
        assert http_findings == []


# ---------------------------------------------------------------------------
# Finding 2: Public / catch-all IP binding
# ---------------------------------------------------------------------------


class TestPublicIpFindings:
    async def test_0000_triggers_public_finding(self, check: AuthenticationCheck):
        srv = MCPServerConfig(
            name="catch-all",
            transport=TransportType.HTTP,
            url="http://0.0.0.0:3000/mcp",
            env={"API_KEY": "token"},
        )
        findings = await check.run(srv)
        pub_findings = [f for f in findings if "publicly accessible" in f.title]
        assert len(pub_findings) == 1
        assert pub_findings[0].severity == Severity.HIGH

    async def test_localhost_no_public_finding(self, check: AuthenticationCheck):
        srv = MCPServerConfig(
            name="local-remote",
            transport=TransportType.HTTP,
            url="https://127.0.0.1:8080/mcp",
            env={"API_KEY": "token"},
        )
        findings = await check.run(srv)
        pub_findings = [f for f in findings if "publicly accessible" in f.title]
        assert pub_findings == []

    async def test_private_ip_no_public_finding(self, check: AuthenticationCheck):
        srv = MCPServerConfig(
            name="internal",
            transport=TransportType.HTTP,
            url="https://192.168.1.100:8080/mcp",
            env={"API_KEY": "token"},
        )
        findings = await check.run(srv)
        pub_findings = [f for f in findings if "publicly accessible" in f.title]
        assert pub_findings == []

    async def test_dns_name_no_public_finding(self, check: AuthenticationCheck):
        """A DNS name cannot be statically determined as public/private."""
        srv = MCPServerConfig(
            name="dns",
            transport=TransportType.HTTP,
            url="https://api.mycompany.internal/mcp",
            env={"API_KEY": "token"},
        )
        findings = await check.run(srv)
        pub_findings = [f for f in findings if "publicly accessible" in f.title]
        assert pub_findings == []


# ---------------------------------------------------------------------------
# Finding 3: No auth credentials in env
# ---------------------------------------------------------------------------


class TestNoAuthFindings:
    async def test_no_env_triggers_medium_finding(self, check: AuthenticationCheck):
        srv = MCPServerConfig(
            name="unauth",
            transport=TransportType.HTTP,
            url="https://api.example.com/mcp",
            env={},
        )
        findings = await check.run(srv)
        no_auth = [f for f in findings if "No authentication credentials" in f.title]
        assert len(no_auth) == 1
        assert no_auth[0].severity == Severity.MEDIUM

    async def test_non_auth_env_still_triggers(self, check: AuthenticationCheck):
        srv = MCPServerConfig(
            name="unauth2",
            transport=TransportType.HTTP,
            url="https://api.example.com/mcp",
            env={"NODE_ENV": "production"},
        )
        findings = await check.run(srv)
        no_auth = [f for f in findings if "No authentication credentials" in f.title]
        assert len(no_auth) == 1

    @pytest.mark.parametrize(
        "key",
        [
            "AUTH_TOKEN",
            "API_KEY",
            "BEARER_TOKEN",
            "SECRET",
            "PASSWORD",
            "CREDENTIAL",
            "APIKEY",
            "X_API_KEY",
            "AUTHORIZATION",
            "HTTP_AUTHORIZATION",
        ],
    )
    async def test_various_auth_keys_suppress_finding(
        self, check: AuthenticationCheck, key: str
    ):
        srv = MCPServerConfig(
            name="auth-server",
            transport=TransportType.HTTP,
            url="https://api.example.com/mcp",
            env={key: "some-value"},
        )
        findings = await check.run(srv)
        no_auth = [f for f in findings if "No authentication credentials" in f.title]
        assert no_auth == [], f"Expected no auth finding with env key '{key}'"


# ---------------------------------------------------------------------------
# Multiple findings at once
# ---------------------------------------------------------------------------


class TestMultipleFindings:
    async def test_http_public_ip_no_auth_three_findings(self, check: AuthenticationCheck):
        """The sample fixture's insecure-remote server should get all three findings."""
        srv = MCPServerConfig(
            name="insecure-remote",
            transport=TransportType.HTTP,
            url="http://0.0.0.0:3000/mcp",
            env={},
        )
        findings = await check.run(srv)
        # HTTP + public IP + no auth = 3
        assert len(findings) == 3
        severities = {f.severity for f in findings}
        assert Severity.HIGH in severities
        assert Severity.MEDIUM in severities

    async def test_all_findings_have_check_id(self, check: AuthenticationCheck):
        srv = MCPServerConfig(
            name="bad",
            transport=TransportType.HTTP,
            url="http://0.0.0.0:3000/mcp",
            env={},
        )
        findings = await check.run(srv)
        for f in findings:
            assert f.check_id == "AUTH001"

    async def test_all_findings_have_remediation(self, check: AuthenticationCheck):
        srv = MCPServerConfig(
            name="bad",
            transport=TransportType.HTTP,
            url="http://0.0.0.0:3000/mcp",
            env={},
        )
        findings = await check.run(srv)
        for f in findings:
            assert f.remediation


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    async def test_empty_url_does_not_crash(self, check: AuthenticationCheck):
        """Remote server with empty string url — should not raise."""
        srv = MCPServerConfig(
            name="no-url",
            transport=TransportType.HTTP,
            url="",
            env={"API_KEY": "token"},
        )
        findings = await check.run(srv)
        # No http-scheme finding, no public-ip finding (empty url), but may have no-url finding
        assert isinstance(findings, list)

    async def test_none_url_does_not_crash(self, check: AuthenticationCheck):
        srv = MCPServerConfig(
            name="none-url",
            transport=TransportType.HTTP,
            url=None,
            env={"API_KEY": "token"},
        )
        findings = await check.run(srv)
        assert isinstance(findings, list)

    async def test_sse_transport_scanned(self, check: AuthenticationCheck):
        srv = MCPServerConfig(
            name="sse",
            transport=TransportType.SSE,
            url="http://example.com/sse",
            env={},
        )
        findings = await check.run(srv)
        # SSE is a remote transport — should find HTTP issue and no-auth
        titles = [f.title for f in findings]
        assert any("plaintext" in t for t in titles)
