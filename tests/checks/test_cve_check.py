"""Tests for KnownCVECheck (CVE001)."""
from __future__ import annotations

import pytest

from mcpshield.checks.cve_check import KnownCVECheck
from mcpshield.models import MCPServerConfig, Severity, TransportType


@pytest.fixture()
def check() -> KnownCVECheck:
    return KnownCVECheck()


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


class TestMetadata:
    def test_check_id(self, check: KnownCVECheck):
        assert check.check_id == "CVE001"

    def test_name(self, check: KnownCVECheck):
        assert check.name == "Known CVE Check"


# ---------------------------------------------------------------------------
# Clean configurations — zero findings
# ---------------------------------------------------------------------------


class TestCleanConfig:
    async def test_no_command_no_args_clean(self, check: KnownCVECheck):
        srv = MCPServerConfig(name="safe", command=None)
        findings = await check.run(srv)
        assert findings == []

    async def test_unrelated_command_clean(self, check: KnownCVECheck):
        srv = MCPServerConfig(name="safe", command="python", args=["-m", "my_server"])
        findings = await check.run(srv)
        assert findings == []

    async def test_unrelated_npx_clean(self, check: KnownCVECheck):
        """A package unrelated to any known CVE should produce no findings."""
        srv = MCPServerConfig(
            name="safe", command="npx", args=["-y", "@anthropic-ai/some-other-tool"]
        )
        findings = await check.run(srv)
        assert findings == []


# ---------------------------------------------------------------------------
# CVE-2025-6514: mcp-remote (CRITICAL, CVSS 9.6)
# ---------------------------------------------------------------------------


class TestCVE20256514:
    async def test_mcp_remote_in_args_flagged(self, check: KnownCVECheck):
        srv = MCPServerConfig(
            name="remote-srv",
            command="npx",
            args=["-y", "mcp-remote", "https://example.com/mcp"],
        )
        findings = await check.run(srv)
        cve_findings = [f for f in findings if "CVE-2025-6514" in f.title]
        assert len(cve_findings) == 1
        assert cve_findings[0].severity == Severity.CRITICAL

    async def test_mcp_remote_command_flagged(self, check: KnownCVECheck):
        srv = MCPServerConfig(name="remote", command="mcp-remote", args=["https://example.com"])
        findings = await check.run(srv)
        cve_findings = [f for f in findings if "CVE-2025-6514" in f.title]
        assert len(cve_findings) == 1

    async def test_mcp_remote_cvss_in_title(self, check: KnownCVECheck):
        srv = MCPServerConfig(
            name="remote", command="npx", args=["-y", "mcp-remote", "https://example.com"]
        )
        findings = await check.run(srv)
        assert findings
        assert "9.6" in findings[0].title

    async def test_mcp_remote_not_duplicated(self, check: KnownCVECheck):
        """If mcp-remote appears in both command and args, it should only be reported once."""
        srv = MCPServerConfig(
            name="remote", command="mcp-remote", args=["mcp-remote", "https://example.com"]
        )
        findings = await check.run(srv)
        cve_ids = [f.title for f in findings if "CVE-2025-6514" in f.title]
        assert len(cve_ids) == 1

    async def test_fixture_vulnerable_mcp_remote(self, check: KnownCVECheck):
        """Matches the 'vulnerable-mcp-remote' server from the fixture file."""
        srv = MCPServerConfig(
            name="vulnerable-mcp-remote",
            command="npx",
            args=["-y", "mcp-remote", "https://example.com/mcp"],
        )
        findings = await check.run(srv)
        assert any("CVE-2025-6514" in f.title for f in findings)


# ---------------------------------------------------------------------------
# CVE-2025-49596: mcp (Python package) (HIGH, CVSS 8.8)
# ---------------------------------------------------------------------------


class TestCVE202549596:
    async def test_mcp_package_in_args_flagged(self, check: KnownCVECheck):
        srv = MCPServerConfig(name="py-srv", command="python", args=["-m", "mcp"])
        findings = await check.run(srv)
        cve_findings = [f for f in findings if "CVE-2025-49596" in f.title]
        assert len(cve_findings) == 1
        assert cve_findings[0].severity == Severity.HIGH

    async def test_mcp_command_flagged(self, check: KnownCVECheck):
        srv = MCPServerConfig(name="mcp-srv", command="mcp", args=["serve"])
        findings = await check.run(srv)
        cve_findings = [f for f in findings if "CVE-2025-49596" in f.title]
        assert len(cve_findings) == 1

    async def test_mcp_package_cvss_in_title(self, check: KnownCVECheck):
        srv = MCPServerConfig(name="py-srv", command="mcp")
        findings = await check.run(srv)
        assert findings
        mcp_finding = next((f for f in findings if "CVE-2025-49596" in f.title), None)
        assert mcp_finding is not None
        assert "8.8" in mcp_finding.title


# ---------------------------------------------------------------------------
# CVE-2025-53364: @modelcontextprotocol/sdk (HIGH, CVSS 7.5)
# ---------------------------------------------------------------------------


class TestCVE202553364:
    async def test_sdk_in_args_flagged(self, check: KnownCVECheck):
        srv = MCPServerConfig(
            name="node-srv",
            command="npx",
            args=["-y", "@modelcontextprotocol/sdk"],
        )
        findings = await check.run(srv)
        cve_findings = [f for f in findings if "CVE-2025-53364" in f.title]
        assert len(cve_findings) == 1
        assert cve_findings[0].severity == Severity.HIGH

    async def test_modelcontextprotocol_alias_flagged(self, check: KnownCVECheck):
        srv = MCPServerConfig(
            name="node-srv",
            command="node",
            args=["node_modules/@modelcontextprotocol/sdk/dist/index.js"],
        )
        findings = await check.run(srv)
        cve_findings = [f for f in findings if "CVE-2025-53364" in f.title]
        assert len(cve_findings) >= 1

    async def test_sdk_cvss_in_title(self, check: KnownCVECheck):
        srv = MCPServerConfig(
            name="node-srv", command="npx", args=["-y", "@modelcontextprotocol/sdk"]
        )
        findings = await check.run(srv)
        sdk_finding = next((f for f in findings if "CVE-2025-53364" in f.title), None)
        assert sdk_finding is not None
        assert "7.5" in sdk_finding.title


# ---------------------------------------------------------------------------
# Deduplication across tokens
# ---------------------------------------------------------------------------


class TestDeduplication:
    async def test_same_cve_not_reported_twice(self, check: KnownCVECheck):
        """mcp-remote in both command and joined cmdline must not duplicate."""
        srv = MCPServerConfig(
            name="srv",
            command="npx",
            args=["-y", "mcp-remote", "https://example.com"],
        )
        findings = await check.run(srv)
        cve_ids = [f.title for f in findings]
        cve_6514_count = sum(1 for t in cve_ids if "CVE-2025-6514" in t)
        assert cve_6514_count == 1


# ---------------------------------------------------------------------------
# Finding fields
# ---------------------------------------------------------------------------


class TestFindingFields:
    async def test_findings_have_check_id(self, check: KnownCVECheck):
        srv = MCPServerConfig(
            name="srv", command="npx", args=["-y", "mcp-remote", "https://example.com"]
        )
        findings = await check.run(srv)
        for f in findings:
            assert f.check_id == "CVE001"

    async def test_findings_have_remediation(self, check: KnownCVECheck):
        srv = MCPServerConfig(
            name="srv", command="npx", args=["-y", "mcp-remote", "https://example.com"]
        )
        findings = await check.run(srv)
        for f in findings:
            assert f.remediation

    async def test_findings_mention_server_name(self, check: KnownCVECheck):
        srv = MCPServerConfig(
            name="my-mcp-remote-server",
            command="npx",
            args=["-y", "mcp-remote", "https://example.com"],
        )
        findings = await check.run(srv)
        for f in findings:
            assert "my-mcp-remote-server" in f.description
