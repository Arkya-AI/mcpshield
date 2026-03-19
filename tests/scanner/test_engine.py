"""Tests for mcpshield.scanner.engine — Scanner, grade calculation, concurrency."""
from __future__ import annotations

import asyncio

import pytest

from mcpshield.checks.base import BaseCheck
from mcpshield.models import (
    MCPConfigFile,
    MCPServerConfig,
    SecurityFinding,
    SecurityGrade,
    Severity,
    TransportType,
)
from mcpshield.scanner.engine import Scanner, _score_to_grade


# ---------------------------------------------------------------------------
# Helpers / stubs
# ---------------------------------------------------------------------------


def _make_finding(severity: Severity, check_id: str = "TEST001") -> SecurityFinding:
    return SecurityFinding(
        check_id=check_id,
        severity=severity,
        title="Test finding",
        description="desc",
        remediation="fix",
    )


class _NullCheck(BaseCheck):
    """Always returns no findings."""

    check_id = "NULL001"
    name = "Null Check"
    description = "Returns nothing."

    async def run(self, server: MCPServerConfig) -> list[SecurityFinding]:
        return []


class _FixedCheck(BaseCheck):
    """Returns a predetermined list of findings."""

    check_id = "FIXED001"
    name = "Fixed Check"
    description = "Returns fixed findings."

    def __init__(self, findings: list[SecurityFinding]) -> None:
        self._findings = findings

    async def run(self, server: MCPServerConfig) -> list[SecurityFinding]:
        return list(self._findings)


class _RaisingCheck(BaseCheck):
    """Simulates a check that throws an exception."""

    check_id = "ERR001"
    name = "Error Check"
    description = "Always raises."

    async def run(self, server: MCPServerConfig) -> list[SecurityFinding]:
        raise RuntimeError("simulated check failure")


# ---------------------------------------------------------------------------
# _score_to_grade
# ---------------------------------------------------------------------------


class TestScoreToGrade:
    @pytest.mark.parametrize(
        "score,expected",
        [
            (100, SecurityGrade.A),
            (90, SecurityGrade.A),
            (89, SecurityGrade.B),
            (80, SecurityGrade.B),
            (79, SecurityGrade.C),
            (70, SecurityGrade.C),
            (69, SecurityGrade.D),
            (60, SecurityGrade.D),
            (59, SecurityGrade.F),
            (0, SecurityGrade.F),
        ],
    )
    def test_boundaries(self, score: int, expected: SecurityGrade):
        assert _score_to_grade(score) == expected


# ---------------------------------------------------------------------------
# Scanner.register
# ---------------------------------------------------------------------------


class TestScannerRegister:
    def test_no_checks_by_default(self):
        scanner = Scanner()
        assert scanner._checks == []

    def test_register_appends(self):
        scanner = Scanner()
        check = _NullCheck()
        scanner.register(check)
        assert check in scanner._checks

    def test_init_with_checks(self):
        check = _NullCheck()
        scanner = Scanner(checks=[check])
        assert check in scanner._checks

    def test_multiple_registrations(self):
        scanner = Scanner()
        for i in range(3):
            check = _NullCheck()
            check.check_id = f"NULL{i:03d}"  # type: ignore[assignment]
            scanner.register(check)
        assert len(scanner._checks) == 3


# ---------------------------------------------------------------------------
# Scanner.scan_server
# ---------------------------------------------------------------------------


class TestScanServer:
    async def test_no_findings_gives_perfect_score(self):
        scanner = Scanner(checks=[_NullCheck()])
        srv = MCPServerConfig(name="clean", command="python")
        result = await scanner.scan_server(srv)
        assert result.score == 100
        assert result.grade == SecurityGrade.A
        assert result.findings == []
        assert result.server_name == "clean"

    async def test_critical_penalty(self):
        # One CRITICAL = -30 → score 70 → grade C
        scanner = Scanner(checks=[_FixedCheck([_make_finding(Severity.CRITICAL)])])
        srv = MCPServerConfig(name="srv", command="python")
        result = await scanner.scan_server(srv)
        assert result.score == 70
        assert result.grade == SecurityGrade.C

    async def test_high_penalty(self):
        # One HIGH = -15 → score 85 → grade B
        scanner = Scanner(checks=[_FixedCheck([_make_finding(Severity.HIGH)])])
        srv = MCPServerConfig(name="srv", command="python")
        result = await scanner.scan_server(srv)
        assert result.score == 85
        assert result.grade == SecurityGrade.B

    async def test_medium_penalty(self):
        # One MEDIUM = -8 → score 92 → grade A
        scanner = Scanner(checks=[_FixedCheck([_make_finding(Severity.MEDIUM)])])
        srv = MCPServerConfig(name="srv", command="python")
        result = await scanner.scan_server(srv)
        assert result.score == 92
        assert result.grade == SecurityGrade.A

    async def test_low_penalty(self):
        # One LOW = -3 → score 97 → grade A
        scanner = Scanner(checks=[_FixedCheck([_make_finding(Severity.LOW)])])
        srv = MCPServerConfig(name="srv", command="python")
        result = await scanner.scan_server(srv)
        assert result.score == 97
        assert result.grade == SecurityGrade.A

    async def test_info_no_penalty(self):
        # INFO = 0 penalty → score stays 100
        scanner = Scanner(checks=[_FixedCheck([_make_finding(Severity.INFO)])])
        srv = MCPServerConfig(name="srv", command="python")
        result = await scanner.scan_server(srv)
        assert result.score == 100
        assert result.grade == SecurityGrade.A

    async def test_score_floor_at_zero(self):
        # Multiple criticals should not produce a negative score
        findings = [_make_finding(Severity.CRITICAL) for _ in range(10)]
        scanner = Scanner(checks=[_FixedCheck(findings)])
        srv = MCPServerConfig(name="srv", command="python")
        result = await scanner.scan_server(srv)
        assert result.score == 0
        assert result.grade == SecurityGrade.F

    async def test_multiple_checks_findings_combined(self):
        check_a = _FixedCheck([_make_finding(Severity.HIGH, "A001")])
        check_b = _FixedCheck([_make_finding(Severity.MEDIUM, "B001")])
        scanner = Scanner(checks=[check_a, check_b])
        srv = MCPServerConfig(name="srv", command="python")
        result = await scanner.scan_server(srv)
        # HIGH (-15) + MEDIUM (-8) = -23 → 77 → grade C
        assert result.score == 77
        assert result.grade == SecurityGrade.C
        assert len(result.findings) == 2

    async def test_raising_check_is_skipped(self):
        """A check that raises must not propagate — other checks still run."""
        good = _FixedCheck([_make_finding(Severity.LOW)])
        bad = _RaisingCheck()
        scanner = Scanner(checks=[bad, good])
        srv = MCPServerConfig(name="srv", command="python")
        result = await scanner.scan_server(srv)
        # Only the good check's finding counts
        assert len(result.findings) == 1
        assert result.score == 97

    async def test_no_checks_perfect_score(self):
        scanner = Scanner(checks=[])
        srv = MCPServerConfig(name="srv", command="python")
        result = await scanner.scan_server(srv)
        assert result.score == 100
        assert result.grade == SecurityGrade.A

    async def test_result_server_name_matches(self):
        scanner = Scanner(checks=[_NullCheck()])
        srv = MCPServerConfig(name="my-special-server", command="python")
        result = await scanner.scan_server(srv)
        assert result.server_name == "my-special-server"


# ---------------------------------------------------------------------------
# Scanner.scan_config
# ---------------------------------------------------------------------------


class TestScanConfig:
    async def test_empty_config_returns_empty_list(self):
        scanner = Scanner(checks=[_NullCheck()])
        cfg = MCPConfigFile(servers={})
        results = await scanner.scan_config(cfg)
        assert results == []

    async def test_one_server(self):
        scanner = Scanner(checks=[_NullCheck()])
        srv = MCPServerConfig(name="srv", command="python")
        cfg = MCPConfigFile(servers={"srv": srv})
        results = await scanner.scan_config(cfg)
        assert len(results) == 1
        assert results[0].server_name == "srv"

    async def test_multiple_servers(self):
        scanner = Scanner(checks=[_NullCheck()])
        cfg = MCPConfigFile(
            servers={
                "a": MCPServerConfig(name="a", command="python"),
                "b": MCPServerConfig(name="b", command="node"),
                "c": MCPServerConfig(name="c", command="ruby"),
            }
        )
        results = await scanner.scan_config(cfg)
        assert len(results) == 3
        names = {r.server_name for r in results}
        assert names == {"a", "b", "c"}

    async def test_concurrent_execution(self):
        """Verify scan_config runs server scans concurrently (asyncio.gather)."""
        call_order: list[str] = []

        class _TrackingCheck(BaseCheck):
            check_id = "TRACK001"
            name = "Tracking Check"
            description = ""

            async def run(self, server: MCPServerConfig) -> list[SecurityFinding]:
                call_order.append(server.name)
                await asyncio.sleep(0)  # yield to event loop
                return []

        scanner = Scanner(checks=[_TrackingCheck()])
        cfg = MCPConfigFile(
            servers={
                "x": MCPServerConfig(name="x", command="a"),
                "y": MCPServerConfig(name="y", command="b"),
            }
        )
        results = await scanner.scan_config(cfg)
        assert len(results) == 2
        # Both servers were scanned
        assert set(call_order) == {"x", "y"}

    async def test_scan_config_propagates_findings(self):
        check = _FixedCheck([_make_finding(Severity.CRITICAL)])
        scanner = Scanner(checks=[check])
        cfg = MCPConfigFile(
            servers={
                "bad": MCPServerConfig(name="bad", command="python"),
            }
        )
        results = await scanner.scan_config(cfg)
        assert results[0].score == 70
        assert len(results[0].findings) == 1
