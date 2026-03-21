from __future__ import annotations

import time
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from mcpshield import __version__
from mcpshield.checks import get_all_checks
from mcpshield.models import MCPConfigFile, MCPServerConfig, TransportType
from mcpshield.scanner.engine import Scanner

from .schemas import (
    HealthResponse,
    ScanMetadataSchema,
    ScanRequest,
    ScanResponse,
    ScanUrlRequest,
    ServerResultSchema,
    FindingSchema,
    FindingCountsSchema,
)


# ---------------------------------------------------------------------------
# Lifespan — initialise database on startup
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    from mcpshield.db.engine import init_db
    await init_db()
    yield


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

app = FastAPI(
    title="MCP Shield API",
    description=(
        "Security scanner for Model Context Protocol (MCP) server configurations. "
        "Submit your MCP config to detect credential exposure, insecure transports, "
        "over-permissioned servers, and known CVEs."
    ),
    version=__version__,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# CORS — allow all origins so a web frontend can call this freely.
# Tighten origins in production by replacing "*" with your domain list.
# ---------------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Include routers — auth, billing
# ---------------------------------------------------------------------------

from mcpshield.auth.router import router as auth_router
from mcpshield.billing.router import router as billing_router

app.include_router(auth_router)
app.include_router(billing_router)

# ---------------------------------------------------------------------------
# Simple in-memory rate limiter
# Tracks per-IP scan count in 60-second rolling windows.
# ---------------------------------------------------------------------------

_RATE_LIMIT_MAX = 30          # max scans per window (generous for open use)
_RATE_LIMIT_WINDOW_SECS = 60  # window size in seconds

# {ip: [(timestamp, count), ...]}  — each entry is a 1-second bucket
_rate_buckets: dict[str, list[float]] = defaultdict(list)


def _check_rate_limit(ip: str) -> None:
    """Raise HTTP 429 if *ip* has exceeded the scan rate limit."""
    now = time.monotonic()
    window_start = now - _RATE_LIMIT_WINDOW_SECS

    # Prune timestamps outside the current window
    timestamps = _rate_buckets[ip]
    timestamps[:] = [t for t in timestamps if t >= window_start]

    if len(timestamps) >= _RATE_LIMIT_MAX:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Rate limit exceeded: maximum {_RATE_LIMIT_MAX} scans "
                f"per {_RATE_LIMIT_WINDOW_SECS} seconds per IP."
            ),
            headers={"Retry-After": str(_RATE_LIMIT_WINDOW_SECS)},
        )

    timestamps.append(now)


def _client_ip(request: Request) -> str:
    """Return the best-effort client IP, honouring X-Forwarded-For."""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


# ---------------------------------------------------------------------------
# Shared scanner instance (checks are stateless; reuse is safe)
# ---------------------------------------------------------------------------

_scanner = Scanner(checks=get_all_checks())

# ---------------------------------------------------------------------------
# Usage tracking — simple in-memory counters for monitoring
# ---------------------------------------------------------------------------

_scan_counts: dict[str, int] = defaultdict(int)  # {YYYY-MM-DD: count}
_total_scans: int = 0


def _track_scan() -> None:
    global _total_scans
    _total_scans += 1
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    _scan_counts[today] = _scan_counts.get(today, 0) + 1


# ---------------------------------------------------------------------------
# Config normalisation helpers
# ---------------------------------------------------------------------------

def _normalise_config(raw: dict[str, Any], source: str | None) -> MCPConfigFile:
    """Convert Claude Desktop or generic config dict to MCPConfigFile.

    Supported input shapes
    ----------------------
    Claude Desktop::

        {"mcpServers": {"name": {"command": "...", "args": [...], "env": {...}}}}

    Generic (MCPShield native)::

        {"servers": {"name": {"command": "...", "transport": "stdio", ...}}}
    """
    servers_raw: dict[str, Any]

    if "mcpServers" in raw:
        servers_raw = raw["mcpServers"]
    elif "servers" in raw:
        servers_raw = raw["servers"]
    else:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "Config must contain either a 'mcpServers' key (Claude Desktop format) "
                "or a 'servers' key (generic format)."
            ),
        )

    if not isinstance(servers_raw, dict):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="'mcpServers' / 'servers' must be a JSON object.",
        )

    if not servers_raw:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Config contains no servers to scan.",
        )

    servers: dict[str, MCPServerConfig] = {}
    for name, cfg in servers_raw.items():
        if not isinstance(cfg, dict):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Server entry '{name}' must be a JSON object.",
            )
        try:
            # Inject the name field if missing (Claude Desktop omits it)
            servers[name] = MCPServerConfig(name=name, **cfg)
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid config for server '{name}': {exc}",
            ) from exc

    return MCPConfigFile(source=source, servers=servers)


def _build_response(results_raw: list[Any], duration_ms: float) -> ScanResponse:
    """Convert a list of ScanResult to the API ScanResponse schema."""
    total_findings = sum(len(r.findings) for r in results_raw)

    severity_totals: dict[str, int] = {}
    for result in results_raw:
        for finding in result.findings:
            key = finding.severity.value
            severity_totals[key] = severity_totals.get(key, 0) + 1

    server_results = []
    for r in results_raw:
        finding_counts = FindingCountsSchema(
            critical=sum(1 for f in r.findings if f.severity.value == "critical"),
            high=sum(1 for f in r.findings if f.severity.value == "high"),
            medium=sum(1 for f in r.findings if f.severity.value == "medium"),
            low=sum(1 for f in r.findings if f.severity.value == "low"),
            info=sum(1 for f in r.findings if f.severity.value == "info"),
        )
        server_results.append(
            ServerResultSchema(
                server_name=r.server_name,
                grade=r.grade.value,
                score=r.score,
                scan_timestamp=r.scan_timestamp,
                findings=[
                    FindingSchema(
                        check_id=f.check_id,
                        severity=f.severity.value,
                        title=f.title,
                        description=f.description,
                        remediation=f.remediation,
                    )
                    for f in r.findings
                ],
                finding_counts=finding_counts,
                metadata=r.metadata,
            )
        )

    return ScanResponse(
        metadata=ScanMetadataSchema(
            scan_timestamp=datetime.now(timezone.utc),
            mcpshield_version=__version__,
            total_findings=total_findings,
            severity_totals=severity_totals,
            server_count=len(results_raw),
            duration_ms=round(duration_ms, 2),
        ),
        results=server_results,
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


# Try project root first (dev), then /app/web (Docker container)
_WEB_DIR_CANDIDATES = [
    Path(__file__).resolve().parent.parent.parent.parent / "web",
    Path("/app/web"),
]
_WEB_DIR = next((p for p in _WEB_DIR_CANDIDATES if p.is_dir()), _WEB_DIR_CANDIDATES[0])

@app.get("/", include_in_schema=False)
async def root():
    """Serve the landing page if available, otherwise redirect to API docs."""
    index = _WEB_DIR / "index.html"
    if index.exists():
        return FileResponse(index, media_type="text/html")
    return RedirectResponse(url="/docs", status_code=status.HTTP_302_FOUND)


@app.get("/login", include_in_schema=False)
async def login_page():
    page = _WEB_DIR / "login.html"
    if page.exists():
        return FileResponse(page, media_type="text/html")
    return RedirectResponse(url="/docs")


@app.get("/dashboard", include_in_schema=False)
async def dashboard_page():
    page = _WEB_DIR / "dashboard.html"
    if page.exists():
        return FileResponse(page, media_type="text/html")
    return RedirectResponse(url="/login")


@app.get(
    "/api/v1/health",
    response_model=HealthResponse,
    summary="Health check",
    tags=["System"],
)
async def health() -> HealthResponse:
    """Returns ``{"status": "ok"}`` when the service is running."""
    return HealthResponse(status="ok", version=__version__)


@app.get(
    "/api/v1/stats",
    summary="Usage statistics",
    tags=["System"],
)
async def stats() -> dict:
    """Return scan usage statistics for monitoring."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return {
        "total_scans": _total_scans,
        "today": _scan_counts.get(today, 0),
        "daily_counts": dict(_scan_counts),
    }


@app.post(
    "/api/v1/scan",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Scan an MCP config",
    tags=["Scanning"],
)
async def scan_config(body: ScanRequest, request: Request) -> ScanResponse:
    """Scan a full MCP configuration for security issues.

    Accepts both **Claude Desktop** format (``mcpServers`` key) and the
    generic MCPShield format (``servers`` key).  Returns per-server findings,
    security grades, and an aggregated summary.
    """
    _check_rate_limit(_client_ip(request))

    config = _normalise_config(body.config, body.source)

    t0 = time.perf_counter()
    try:
        results = await _scanner.scan_config(config)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scan failed unexpectedly: {exc}",
        ) from exc
    duration_ms = (time.perf_counter() - t0) * 1000
    _track_scan()

    return _build_response(results, duration_ms)


@app.post(
    "/api/v1/scan-url",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Scan a remote MCP server URL",
    tags=["Scanning"],
)
async def scan_url(body: ScanUrlRequest, request: Request) -> ScanResponse:
    """Scan a remote MCP server by URL.

    The URL is treated as a single SSE/HTTP server entry and run through the
    same security checks as a full config scan.  The ``name`` field defaults
    to the URL hostname when omitted.
    """
    _check_rate_limit(_client_ip(request))

    # Derive a display name from the URL when the caller did not provide one
    name = body.name
    if not name:
        try:
            from urllib.parse import urlparse
            name = urlparse(body.url).hostname or body.url
        except Exception:
            name = body.url

    # Determine transport type from scheme
    url_lower = body.url.lower()
    if url_lower.startswith(("sse://", "http://", "https://")):
        transport = TransportType.SSE
    else:
        transport = TransportType.HTTP

    server = MCPServerConfig(
        name=name,
        url=body.url,
        transport=transport,
    )
    config = MCPConfigFile(
        source=body.url,
        servers={name: server},
    )

    t0 = time.perf_counter()
    try:
        results = await _scanner.scan_config(config)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scan failed unexpectedly: {exc}",
        ) from exc
    duration_ms = (time.perf_counter() - t0) * 1000
    _track_scan()

    return _build_response(results, duration_ms)
