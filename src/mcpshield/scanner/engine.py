from __future__ import annotations

import asyncio

from ..checks.base import BaseCheck
from ..models import (
    MCPConfigFile,
    MCPServerConfig,
    ScanResult,
    SecurityGrade,
    Severity,
)

_SEVERITY_PENALTY: dict[Severity, int] = {
    Severity.CRITICAL: 30,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 0,
}


def _score_to_grade(score: int) -> SecurityGrade:
    if score >= 90:
        return SecurityGrade.A
    if score >= 80:
        return SecurityGrade.B
    if score >= 70:
        return SecurityGrade.C
    if score >= 60:
        return SecurityGrade.D
    return SecurityGrade.F


class Scanner:
    def __init__(self, checks: list[BaseCheck] | None = None) -> None:
        self._checks: list[BaseCheck] = checks or []

    def register(self, check: BaseCheck) -> None:
        self._checks.append(check)

    async def scan_config(self, config: MCPConfigFile) -> list[ScanResult]:
        return await asyncio.gather(
            *(self.scan_server(server) for server in config.servers.values())
        )

    async def scan_server(self, server: MCPServerConfig) -> ScanResult:
        results = await asyncio.gather(
            *(check.run(server) for check in self._checks),
            return_exceptions=True,
        )

        findings = []
        for result in results:
            if isinstance(result, BaseException):
                continue
            findings.extend(result)

        score = max(
            0,
            100 - sum(_SEVERITY_PENALTY[f.severity] for f in findings),
        )
        grade = _score_to_grade(score)

        return ScanResult(
            server_name=server.name,
            findings=findings,
            grade=grade,
            score=score,
        )
