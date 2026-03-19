from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, HttpUrl, field_validator


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    """Raw MCP config to scan.

    Accepts both Claude Desktop format (``mcpServers`` key) and the generic
    MCPShield format (``servers`` key).  Additional top-level keys are passed
    through as-is so callers do not need to strip them first.
    """

    config: dict[str, Any] = Field(
        ...,
        description=(
            "MCP config JSON.  Accepts Claude Desktop format "
            "({'mcpServers': {...}}) or generic format ({'servers': {...}})."
        ),
    )
    source: str | None = Field(
        default=None,
        description="Optional human-readable label for the config source (e.g. a filename).",
    )

    model_config = {"json_schema_extra": {
        "example": {
            "config": {
                "mcpServers": {
                    "my-server": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem"],
                        "env": {"API_KEY": "sk-live-abc123"},
                    }
                }
            },
            "source": "claude_desktop_config.json",
        }
    }}


class ScanUrlRequest(BaseModel):
    """URL of a remote MCP server to scan."""

    url: str = Field(..., description="URL of the remote MCP server to scan.")
    name: str | None = Field(
        default=None,
        description="Optional display name for the server.  Defaults to the hostname.",
    )

    @field_validator("url")
    @classmethod
    def _validate_url(cls, v: str) -> str:
        if not v.startswith(("http://", "https://", "sse://", "ws://", "wss://")):
            raise ValueError(
                "url must start with http://, https://, sse://, ws://, or wss://"
            )
        return v

    model_config = {"json_schema_extra": {
        "example": {
            "url": "https://mcp.example.com/sse",
            "name": "example-remote-server",
        }
    }}


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------


class FindingSchema(BaseModel):
    check_id: str
    severity: str
    title: str
    description: str
    remediation: str


class FindingCountsSchema(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ServerResultSchema(BaseModel):
    server_name: str
    grade: str
    score: int = Field(ge=0, le=100)
    scan_timestamp: datetime
    findings: list[FindingSchema]
    finding_counts: FindingCountsSchema
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScanMetadataSchema(BaseModel):
    scan_timestamp: datetime
    mcpshield_version: str
    total_findings: int
    severity_totals: dict[str, int]
    server_count: int
    duration_ms: float = Field(description="Wall-clock time for the full scan in milliseconds.")


class ScanResponse(BaseModel):
    metadata: ScanMetadataSchema
    results: list[ServerResultSchema]

    model_config = {"json_schema_extra": {
        "example": {
            "metadata": {
                "scan_timestamp": "2026-03-19T12:00:00Z",
                "mcpshield_version": "0.1.0",
                "total_findings": 2,
                "severity_totals": {"high": 1, "medium": 1},
                "server_count": 1,
                "duration_ms": 42.5,
            },
            "results": [
                {
                    "server_name": "my-server",
                    "grade": "C",
                    "score": 77,
                    "scan_timestamp": "2026-03-19T12:00:00Z",
                    "findings": [
                        {
                            "check_id": "CRED-001",
                            "severity": "high",
                            "title": "Credential in env",
                            "description": "API key found in env.",
                            "remediation": "Use a secrets manager.",
                        }
                    ],
                    "finding_counts": {"critical": 0, "high": 1, "medium": 1, "low": 0, "info": 0},
                    "metadata": {},
                }
            ],
        }
    }}


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str
