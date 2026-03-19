"""Tests for mcpshield.models — data model creation, validation, and defaults."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from mcpshield.models import (
    MCPConfigFile,
    MCPServerConfig,
    ScanResult,
    SecurityFinding,
    SecurityGrade,
    Severity,
    TransportType,
)


# ---------------------------------------------------------------------------
# TransportType
# ---------------------------------------------------------------------------


class TestTransportType:
    def test_values(self):
        assert TransportType.STDIO == "stdio"
        assert TransportType.SSE == "sse"
        assert TransportType.HTTP == "http"

    def test_from_string(self):
        assert TransportType("stdio") is TransportType.STDIO
        assert TransportType("sse") is TransportType.SSE
        assert TransportType("http") is TransportType.HTTP

    def test_invalid_value(self):
        with pytest.raises(ValueError):
            TransportType("grpc")


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------


class TestSeverity:
    def test_all_values_present(self):
        expected = {"critical", "high", "medium", "low", "info"}
        actual = {s.value for s in Severity}
        assert actual == expected

    def test_ordering_by_value_string(self):
        # Just ensure all members are reachable
        for member in Severity:
            assert isinstance(member.value, str)


# ---------------------------------------------------------------------------
# SecurityGrade
# ---------------------------------------------------------------------------


class TestSecurityGrade:
    def test_all_grades(self):
        for grade in ("A", "B", "C", "D", "F"):
            assert SecurityGrade(grade).value == grade


# ---------------------------------------------------------------------------
# MCPServerConfig
# ---------------------------------------------------------------------------


class TestMCPServerConfig:
    def test_minimal_stdio(self):
        srv = MCPServerConfig(name="my-server")
        assert srv.name == "my-server"
        assert srv.transport == TransportType.STDIO
        assert srv.command is None
        assert srv.url is None
        assert srv.args == []
        assert srv.env == {}

    def test_full_stdio(self):
        srv = MCPServerConfig(
            name="fs",
            transport=TransportType.STDIO,
            command="npx",
            args=["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
            env={"NODE_ENV": "production"},
        )
        assert srv.command == "npx"
        assert srv.args == ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
        assert srv.env["NODE_ENV"] == "production"

    def test_http_server(self):
        srv = MCPServerConfig(
            name="remote",
            transport=TransportType.HTTP,
            url="https://api.example.com/mcp",
        )
        assert srv.url == "https://api.example.com/mcp"
        assert srv.transport == TransportType.HTTP

    def test_sse_server(self):
        srv = MCPServerConfig(
            name="events",
            transport=TransportType.SSE,
            url="https://api.example.com/events",
        )
        assert srv.transport == TransportType.SSE

    def test_transport_accepts_enum_and_string(self):
        srv_enum = MCPServerConfig(name="s", transport=TransportType.HTTP)
        srv_str = MCPServerConfig(name="s", transport="http")  # type: ignore[arg-type]
        assert srv_enum.transport == srv_str.transport

    def test_name_required(self):
        with pytest.raises(ValidationError):
            MCPServerConfig()  # type: ignore[call-arg]

    def test_defaults_are_independent_instances(self):
        """Default list/dict fields must not be shared between instances."""
        a = MCPServerConfig(name="a")
        b = MCPServerConfig(name="b")
        a.args.append("x")
        assert b.args == []
        a.env["K"] = "V"
        assert b.env == {}


# ---------------------------------------------------------------------------
# SecurityFinding
# ---------------------------------------------------------------------------


class TestSecurityFinding:
    def test_create(self):
        finding = SecurityFinding(
            check_id="AUTH001",
            severity=Severity.HIGH,
            title="Test finding",
            description="A description",
            remediation="Fix it",
        )
        assert finding.check_id == "AUTH001"
        assert finding.severity == Severity.HIGH
        assert finding.title == "Test finding"

    def test_severity_accepts_string(self):
        finding = SecurityFinding(
            check_id="X",
            severity="medium",  # type: ignore[arg-type]
            title="t",
            description="d",
            remediation="r",
        )
        assert finding.severity == Severity.MEDIUM

    def test_all_required_fields(self):
        with pytest.raises(ValidationError):
            SecurityFinding(check_id="X", severity=Severity.LOW)  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# ScanResult
# ---------------------------------------------------------------------------


class TestScanResult:
    def test_defaults(self):
        result = ScanResult(server_name="srv")
        assert result.findings == []
        assert result.grade == SecurityGrade.A
        assert result.score == 100
        assert isinstance(result.scan_timestamp, datetime)
        assert result.metadata == {}

    def test_score_bounds(self):
        with pytest.raises(ValidationError):
            ScanResult(server_name="s", score=101)
        with pytest.raises(ValidationError):
            ScanResult(server_name="s", score=-1)

    def test_score_zero_allowed(self):
        result = ScanResult(server_name="s", score=0)
        assert result.score == 0

    def test_scan_timestamp_is_utc_aware(self):
        result = ScanResult(server_name="s")
        assert result.scan_timestamp.tzinfo is not None

    def test_with_findings(self):
        finding = SecurityFinding(
            check_id="CVE001",
            severity=Severity.CRITICAL,
            title="Vuln",
            description="desc",
            remediation="patch",
        )
        result = ScanResult(
            server_name="srv",
            findings=[finding],
            grade=SecurityGrade.F,
            score=40,
        )
        assert len(result.findings) == 1
        assert result.grade == SecurityGrade.F

    def test_metadata_arbitrary_dict(self):
        result = ScanResult(server_name="s", metadata={"key": "value", "num": 42})
        assert result.metadata["num"] == 42


# ---------------------------------------------------------------------------
# MCPConfigFile
# ---------------------------------------------------------------------------


class TestMCPConfigFile:
    def test_empty_config(self):
        cfg = MCPConfigFile()
        assert cfg.servers == {}
        assert cfg.source is None

    def test_with_source(self):
        cfg = MCPConfigFile(source="/path/to/config.json")
        assert cfg.source == "/path/to/config.json"

    def test_with_servers(self):
        srv = MCPServerConfig(name="a", command="python")
        cfg = MCPConfigFile(servers={"a": srv})
        assert "a" in cfg.servers
        assert cfg.servers["a"].command == "python"

    def test_servers_defaults_empty(self):
        cfg1 = MCPConfigFile()
        cfg2 = MCPConfigFile()
        cfg1.servers["x"] = MCPServerConfig(name="x")
        assert "x" not in cfg2.servers
