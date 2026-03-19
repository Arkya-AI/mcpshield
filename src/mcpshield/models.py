from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class TransportType(str, Enum):
    STDIO = "stdio"
    SSE = "sse"
    HTTP = "http"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SecurityGrade(str, Enum):
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"


class MCPServerConfig(BaseModel):
    name: str
    transport: TransportType = TransportType.STDIO
    command: str | None = None
    url: str | None = None
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)


class SecurityFinding(BaseModel):
    check_id: str
    severity: Severity
    title: str
    description: str
    remediation: str


class ScanResult(BaseModel):
    server_name: str
    findings: list[SecurityFinding] = Field(default_factory=list)
    grade: SecurityGrade = SecurityGrade.A
    score: int = Field(default=100, ge=0, le=100)
    scan_timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    metadata: dict[str, Any] = Field(default_factory=dict)


class MCPConfigFile(BaseModel):
    source: str | None = None
    servers: dict[str, MCPServerConfig] = Field(default_factory=dict)
