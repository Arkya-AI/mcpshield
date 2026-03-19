from __future__ import annotations

import json
from datetime import datetime, timezone

from mcpshield import __version__
from mcpshield.models import ScanResult


def generate_json_report(results: list[ScanResult]) -> str:
    total_findings = sum(len(r.findings) for r in results)

    severity_totals: dict[str, int] = {}
    for result in results:
        for finding in result.findings:
            severity_totals[finding.severity.value] = (
                severity_totals.get(finding.severity.value, 0) + 1
            )

    report = {
        "metadata": {
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "mcpshield_version": __version__,
            "total_findings": total_findings,
            "severity_totals": severity_totals,
            "server_count": len(results),
        },
        "results": [_serialize_result(r) for r in results],
    }

    return json.dumps(report, indent=2, default=str)


def _serialize_result(result: ScanResult) -> dict:
    return {
        "server_name": result.server_name,
        "grade": result.grade.value,
        "score": result.score,
        "scan_timestamp": result.scan_timestamp.isoformat(),
        "metadata": result.metadata,
        "findings": [
            {
                "check_id": f.check_id,
                "severity": f.severity.value,
                "title": f.title,
                "description": f.description,
                "remediation": f.remediation,
            }
            for f in result.findings
        ],
        "finding_counts": {
            sev: sum(1 for f in result.findings if f.severity.value == sev)
            for sev in ("critical", "high", "medium", "low", "info")
        },
    }
