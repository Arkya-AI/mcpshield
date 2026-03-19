"""Tests for TransportSecurityCheck (TRANS001)."""
from __future__ import annotations

import pytest

from mcpshield.checks.transport_check import TransportSecurityCheck
from mcpshield.models import MCPServerConfig, Severity, TransportType


@pytest.fixture()
def check() -> TransportSecurityCheck:
    return TransportSecurityCheck()


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


class TestMetadata:
    def test_check_id(self, check: TransportSecurityCheck):
        assert check.check_id == "TRANS001"

    def test_name(self, check: TransportSecurityCheck):
        assert check.name == "Transport Security Check"


# ---------------------------------------------------------------------------
# Clean configurations — zero findings
# ---------------------------------------------------------------------------


class TestCleanConfigs:
    async def test_clean_stdio_python(self, check: TransportSecurityCheck):
        srv = MCPServerConfig(name="safe", transport=TransportType.STDIO, command="python")
        findings = await check.run(srv)
        assert findings == []

    async def test_clean_stdio_node(self, check: TransportSecurityCheck):
        srv = MCPServerConfig(name="safe", transport=TransportType.STDIO, command="node")
        findings = await check.run(srv)
        assert findings == []

    async def test_clean_https_http_transport(self, check: TransportSecurityCheck):
        srv = MCPServerConfig(
            name="secure",
            transport=TransportType.HTTP,
            url="https://api.example.com/mcp",
        )
        findings = await check.run(srv)
        assert findings == []

    async def test_full_path_python_clean(self, check: TransportSecurityCheck):
        srv = MCPServerConfig(
            name="safe", transport=TransportType.STDIO, command="/usr/local/bin/python3"
        )
        findings = await check.run(srv)
        assert findings == []


# ---------------------------------------------------------------------------
# Finding 1: Privilege escalation (CRITICAL)
# ---------------------------------------------------------------------------


class TestPrivilegeEscalation:
    @pytest.mark.parametrize("priv_cmd", ["sudo", "doas", "runas", "su", "pkexec"])
    async def test_privilege_command_is_critical(
        self, check: TransportSecurityCheck, priv_cmd: str
    ):
        srv = MCPServerConfig(
            name="dangerous",
            transport=TransportType.STDIO,
            command=priv_cmd,
            args=["python", "-m", "server"],
        )
        findings = await check.run(srv)
        priv_findings = [f for f in findings if "privilege escalation" in f.title.lower()]
        assert len(priv_findings) == 1
        assert priv_findings[0].severity == Severity.CRITICAL

    async def test_sudo_full_path_flagged(self, check: TransportSecurityCheck):
        srv = MCPServerConfig(
            name="dangerous",
            transport=TransportType.STDIO,
            command="/usr/bin/sudo",
            args=["python", "-m", "server"],
        )
        findings = await check.run(srv)
        priv_findings = [f for f in findings if "privilege escalation" in f.title.lower()]
        assert len(priv_findings) == 1
        assert priv_findings[0].severity == Severity.CRITICAL

    async def test_privilege_escalation_not_on_remote_transport(
        self, check: TransportSecurityCheck
    ):
        """Privilege escalation check only applies to stdio."""
        srv = MCPServerConfig(
            name="srv",
            transport=TransportType.HTTP,
            url="https://example.com",
            command="sudo",
        )
        findings = await check.run(srv)
        priv_findings = [f for f in findings if "privilege escalation" in f.title.lower()]
        assert priv_findings == []


# ---------------------------------------------------------------------------
# Finding 2: Shell interpreter as command (HIGH)
# ---------------------------------------------------------------------------


class TestShellInterpreter:
    @pytest.mark.parametrize(
        "shell",
        ["bash", "sh", "zsh", "fish", "dash", "ksh", "csh", "tcsh",
         "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe"],
    )
    async def test_shell_command_is_high(
        self, check: TransportSecurityCheck, shell: str
    ):
        srv = MCPServerConfig(
            name="bad",
            transport=TransportType.STDIO,
            command=shell,
            args=["-c", "some-script.sh"],
        )
        findings = await check.run(srv)
        shell_findings = [f for f in findings if "shell interpreter" in f.title.lower()]
        assert len(shell_findings) == 1
        assert shell_findings[0].severity == Severity.HIGH

    async def test_shell_full_path_flagged(self, check: TransportSecurityCheck):
        srv = MCPServerConfig(
            name="bad",
            transport=TransportType.STDIO,
            command="/bin/bash",
            args=["-c", "server.sh"],
        )
        findings = await check.run(srv)
        shell_findings = [f for f in findings if "shell interpreter" in f.title.lower()]
        assert len(shell_findings) == 1

    async def test_shell_windows_path_flagged(self, check: TransportSecurityCheck):
        srv = MCPServerConfig(
            name="bad",
            transport=TransportType.STDIO,
            command="C:\\Windows\\System32\\cmd.exe",
            args=["/c", "server.bat"],
        )
        findings = await check.run(srv)
        shell_findings = [f for f in findings if "shell interpreter" in f.title.lower()]
        assert len(shell_findings) == 1

    async def test_shell_not_on_remote_transport(self, check: TransportSecurityCheck):
        """Shell check only runs for stdio transport."""
        srv = MCPServerConfig(
            name="srv",
            transport=TransportType.HTTP,
            url="https://example.com",
            command="bash",
        )
        findings = await check.run(srv)
        shell_findings = [f for f in findings if "shell interpreter" in f.title.lower()]
        assert shell_findings == []


# ---------------------------------------------------------------------------
# Finding 3: Non-HTTPS remote URL (HIGH)
# ---------------------------------------------------------------------------


class TestNonHttpsRemote:
    async def test_http_url_flagged(self, check: TransportSecurityCheck):
        srv = MCPServerConfig(
            name="insecure",
            transport=TransportType.HTTP,
            url="http://api.example.com/mcp",
        )
        findings = await check.run(srv)
        https_findings = [f for f in findings if "does not use HTTPS" in f.title]
        assert len(https_findings) == 1
        assert https_findings[0].severity == Severity.HIGH

    async def test_http_sse_flagged(self, check: TransportSecurityCheck):
        srv = MCPServerConfig(
            name="insecure-sse",
            transport=TransportType.SSE,
            url="http://events.example.com/sse",
        )
        findings = await check.run(srv)
        https_findings = [f for f in findings if "does not use HTTPS" in f.title]
        assert len(https_findings) == 1

    async def test_https_url_not_flagged(self, check: TransportSecurityCheck):
        srv = MCPServerConfig(
            name="secure",
            transport=TransportType.HTTP,
            url="https://api.example.com/mcp",
        )
        findings = await check.run(srv)
        https_findings = [f for f in findings if "does not use HTTPS" in f.title]
        assert https_findings == []

    async def test_missing_url_medium_finding(self, check: TransportSecurityCheck):
        srv = MCPServerConfig(name="no-url", transport=TransportType.HTTP, url=None)
        findings = await check.run(srv)
        url_findings = [f for f in findings if "without a URL" in f.title]
        assert len(url_findings) == 1
        assert url_findings[0].severity == Severity.MEDIUM

    async def test_empty_url_medium_finding(self, check: TransportSecurityCheck):
        srv = MCPServerConfig(name="empty-url", transport=TransportType.HTTP, url="")
        findings = await check.run(srv)
        url_findings = [f for f in findings if "without a URL" in f.title]
        assert len(url_findings) == 1


# ---------------------------------------------------------------------------
# Finding 4: Deprecated transport (LOW)
# ---------------------------------------------------------------------------


class TestDeprecatedTransport:
    async def test_sse_transport_deprecated(self, check: TransportSecurityCheck):
        srv = MCPServerConfig(
            name="old",
            transport=TransportType.SSE,
            url="https://events.example.com/sse",
        )
        findings = await check.run(srv)
        dep_findings = [f for f in findings if "Deprecated transport" in f.title]
        assert len(dep_findings) == 1
        assert dep_findings[0].severity == Severity.LOW

    async def test_http_not_deprecated(self, check: TransportSecurityCheck):
        srv = MCPServerConfig(
            name="current",
            transport=TransportType.HTTP,
            url="https://api.example.com/mcp",
        )
        findings = await check.run(srv)
        dep_findings = [f for f in findings if "Deprecated transport" in f.title]
        assert dep_findings == []

    async def test_stdio_not_deprecated(self, check: TransportSecurityCheck):
        srv = MCPServerConfig(name="local", transport=TransportType.STDIO, command="python")
        findings = await check.run(srv)
        dep_findings = [f for f in findings if "Deprecated transport" in f.title]
        assert dep_findings == []


# ---------------------------------------------------------------------------
# Combined scenarios
# ---------------------------------------------------------------------------


class TestCombined:
    async def test_sudo_and_privileged_command_two_findings(
        self, check: TransportSecurityCheck
    ):
        """sudo command = CRITICAL; if command is also a shell, that's another finding."""
        srv = MCPServerConfig(
            name="very-bad",
            transport=TransportType.STDIO,
            command="sudo",
            args=["bash", "-c", "server.sh"],
        )
        findings = await check.run(srv)
        # sudo -> CRITICAL priv escalation
        # sudo is not in _SHELL_EXECUTABLES, so no shell finding
        priv_findings = [f for f in findings if "privilege escalation" in f.title.lower()]
        assert len(priv_findings) == 1

    async def test_sample_dangerous_transport_server(self, check: TransportSecurityCheck):
        """The 'dangerous-transport' server from the fixture."""
        srv = MCPServerConfig(
            name="dangerous-transport",
            transport=TransportType.STDIO,
            command="sudo",
            args=["python", "-m", "admin_server"],
        )
        findings = await check.run(srv)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    async def test_all_findings_have_check_id(self, check: TransportSecurityCheck):
        srv = MCPServerConfig(
            name="srv",
            transport=TransportType.SSE,
            url="http://0.0.0.0:3000/sse",
        )
        findings = await check.run(srv)
        for f in findings:
            assert f.check_id == "TRANS001"
