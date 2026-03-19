"""Tests for mcpshield.reporter.json_report."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from mcpshield import __version__
from mcpshield.models import (
    ScanResult,
    SecurityFinding,
    SecurityGrade,
    Severity,
)
from mcpshield.reporter.json_report import generate_json_report, _serialize_result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding(
    severity: Severity,
    check_id: str = "TEST001",
    title: str = "Test finding",
) -> SecurityFinding:
    return SecurityFinding(
        check_id=check_id,
        severity=severity,
        title=title,
        description="A description of the finding.",
        remediation="How to fix it.",
    )


def _result(
    name: str = "server",
    findings: list[SecurityFinding] | None = None,
    grade: SecurityGrade = SecurityGrade.A,
    score: int = 100,
) -> ScanResult:
    return ScanResult(
        server_name=name,
        findings=findings or [],
        grade=grade,
        score=score,
    )


# ---------------------------------------------------------------------------
# generate_json_report — return type and basic structure
# ---------------------------------------------------------------------------


class TestGenerateJsonReport:
    def test_returns_valid_json_string(self):
        report = generate_json_report([_result()])
        # Must not raise
        parsed = json.loads(report)
        assert isinstance(parsed, dict)

    def test_top_level_keys(self):
        parsed = json.loads(generate_json_report([_result()]))
        assert "metadata" in parsed
        assert "results" in parsed

    def test_metadata_keys(self):
        parsed = json.loads(generate_json_report([_result()]))
        meta = parsed["metadata"]
        assert "scan_timestamp" in meta
        assert "mcpshield_version" in meta
        assert "total_findings" in meta
        assert "severity_totals" in meta
        assert "server_count" in meta

    def test_mcpshield_version_matches_package(self):
        parsed = json.loads(generate_json_report([_result()]))
        assert parsed["metadata"]["mcpshield_version"] == __version__

    def test_scan_timestamp_is_iso_format(self):
        parsed = json.loads(generate_json_report([_result()]))
        ts = parsed["metadata"]["scan_timestamp"]
        # Should parse without raising
        dt = datetime.fromisoformat(ts)
        assert dt.tzinfo is not None

    def test_server_count_correct(self):
        results = [_result("a"), _result("b"), _result("c")]
        parsed = json.loads(generate_json_report(results))
        assert parsed["metadata"]["server_count"] == 3

    def test_empty_results_list(self):
        parsed = json.loads(generate_json_report([]))
        assert parsed["metadata"]["server_count"] == 0
        assert parsed["metadata"]["total_findings"] == 0
        assert parsed["results"] == []

    def test_results_list_length_matches(self):
        results = [_result("a"), _result("b")]
        parsed = json.loads(generate_json_report(results))
        assert len(parsed["results"]) == 2


# ---------------------------------------------------------------------------
# generate_json_report — total_findings and severity_totals
# ---------------------------------------------------------------------------


class TestFindingCounts:
    def test_total_findings_zero_when_clean(self):
        parsed = json.loads(generate_json_report([_result()]))
        assert parsed["metadata"]["total_findings"] == 0

    def test_total_findings_counts_across_servers(self):
        r1 = _result("a", findings=[_finding(Severity.HIGH), _finding(Severity.LOW)])
        r2 = _result("b", findings=[_finding(Severity.CRITICAL)])
        parsed = json.loads(generate_json_report([r1, r2]))
        assert parsed["metadata"]["total_findings"] == 3

    def test_severity_totals_empty_when_no_findings(self):
        parsed = json.loads(generate_json_report([_result()]))
        assert parsed["metadata"]["severity_totals"] == {}

    def test_severity_totals_single_critical(self):
        r = _result(findings=[_finding(Severity.CRITICAL)])
        parsed = json.loads(generate_json_report([r]))
        assert parsed["metadata"]["severity_totals"]["critical"] == 1

    def test_severity_totals_mixed(self):
        findings = [
            _finding(Severity.CRITICAL),
            _finding(Severity.HIGH),
            _finding(Severity.HIGH),
            _finding(Severity.MEDIUM),
            _finding(Severity.LOW),
            _finding(Severity.INFO),
        ]
        r = _result(findings=findings)
        parsed = json.loads(generate_json_report([r]))
        totals = parsed["metadata"]["severity_totals"]
        assert totals["critical"] == 1
        assert totals["high"] == 2
        assert totals["medium"] == 1
        assert totals["low"] == 1
        assert totals["info"] == 1

    def test_severity_totals_accumulated_across_servers(self):
        r1 = _result("a", findings=[_finding(Severity.HIGH)])
        r2 = _result("b", findings=[_finding(Severity.HIGH)])
        parsed = json.loads(generate_json_report([r1, r2]))
        assert parsed["metadata"]["severity_totals"]["high"] == 2


# ---------------------------------------------------------------------------
# _serialize_result — result-level structure
# ---------------------------------------------------------------------------


class TestSerializeResult:
    def test_result_keys(self):
        result = _serialize_result(_result())
        assert "server_name" in result
        assert "grade" in result
        assert "score" in result
        assert "scan_timestamp" in result
        assert "metadata" in result
        assert "findings" in result
        assert "finding_counts" in result

    def test_server_name_preserved(self):
        result = _serialize_result(_result(name="my-server"))
        assert result["server_name"] == "my-server"

    def test_grade_is_string_value(self):
        result = _serialize_result(_result(grade=SecurityGrade.B, score=85))
        assert result["grade"] == "B"

    def test_score_preserved(self):
        result = _serialize_result(_result(score=72))
        assert result["score"] == 72

    def test_scan_timestamp_is_string(self):
        result = _serialize_result(_result())
        assert isinstance(result["scan_timestamp"], str)

    def test_metadata_preserved(self):
        scan = ScanResult(server_name="s", metadata={"custom": "value"})
        result = _serialize_result(scan)
        assert result["metadata"]["custom"] == "value"

    def test_empty_findings_list(self):
        result = _serialize_result(_result(findings=[]))
        assert result["findings"] == []

    def test_findings_serialized(self):
        findings = [_finding(Severity.HIGH, "AUTH001", "HTTP transport")]
        result = _serialize_result(_result(findings=findings))
        assert len(result["findings"]) == 1
        f = result["findings"][0]
        assert f["check_id"] == "AUTH001"
        assert f["severity"] == "high"
        assert f["title"] == "HTTP transport"
        assert "description" in f
        assert "remediation" in f

    def test_finding_counts_all_severities_present(self):
        result = _serialize_result(_result(findings=[]))
        counts = result["finding_counts"]
        for sev in ("critical", "high", "medium", "low", "info"):
            assert sev in counts
            assert counts[sev] == 0

    def test_finding_counts_correct(self):
        findings = [
            _finding(Severity.CRITICAL),
            _finding(Severity.CRITICAL),
            _finding(Severity.HIGH),
        ]
        result = _serialize_result(_result(findings=findings))
        counts = result["finding_counts"]
        assert counts["critical"] == 2
        assert counts["high"] == 1
        assert counts["medium"] == 0
        assert counts["low"] == 0
        assert counts["info"] == 0


# ---------------------------------------------------------------------------
# Round-trip: generate → parse → verify individual finding fields
# ---------------------------------------------------------------------------


class TestRoundTrip:
    def test_round_trip_single_server(self):
        findings = [
            _finding(Severity.CRITICAL, "AUTH001", "Server uses HTTP"),
            _finding(Severity.MEDIUM, "CRED001", "Placeholder value detected"),
        ]
        scan = ScanResult(
            server_name="test-server",
            findings=findings,
            grade=SecurityGrade.C,
            score=62,
        )
        parsed = json.loads(generate_json_report([scan]))
        server_result = parsed["results"][0]

        assert server_result["server_name"] == "test-server"
        assert server_result["grade"] == "C"
        assert server_result["score"] == 62
        assert len(server_result["findings"]) == 2
        assert server_result["finding_counts"]["critical"] == 1
        assert server_result["finding_counts"]["medium"] == 1

    def test_round_trip_preserves_remediation(self):
        f = SecurityFinding(
            check_id="X",
            severity=Severity.HIGH,
            title="T",
            description="D",
            remediation="Upgrade to latest version.",
        )
        parsed = json.loads(generate_json_report([_result(findings=[f])]))
        assert parsed["results"][0]["findings"][0]["remediation"] == "Upgrade to latest version."

    def test_multiple_servers_all_in_results(self):
        results = [
            _result("server-a", [_finding(Severity.HIGH)]),
            _result("server-b", []),
            _result("server-c", [_finding(Severity.CRITICAL), _finding(Severity.LOW)]),
        ]
        parsed = json.loads(generate_json_report(results))
        names = {r["server_name"] for r in parsed["results"]}
        assert names == {"server-a", "server-b", "server-c"}

    def test_json_is_indented(self):
        """The output should be human-readable (indented), not minified."""
        report = generate_json_report([_result()])
        assert "\n" in report
        assert "  " in report  # 2-space indent from json.dumps(indent=2)
