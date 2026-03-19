from __future__ import annotations

import json
from pathlib import Path

from mcpshield.models import MCPConfigFile, MCPServerConfig, TransportType


class ConfigParseError(Exception):
    pass


def _infer_transport(entry: dict) -> TransportType:
    if entry.get("url"):
        url: str = entry["url"]
        if "sse" in url or url.endswith("/events"):
            return TransportType.SSE
        return TransportType.HTTP
    return TransportType.STDIO


def _parse_claude_or_cursor(data: dict, source_path: str | None = None) -> MCPConfigFile:
    raw_servers: dict = data.get("mcpServers", {})
    servers: dict[str, MCPServerConfig] = {}
    for name, cfg in raw_servers.items():
        servers[name] = MCPServerConfig(
            name=name,
            command=cfg.get("command"),
            url=cfg.get("url"),
            args=cfg.get("args", []),
            env=cfg.get("env", {}),
            transport=_infer_transport(cfg),
        )
    return MCPConfigFile(servers=servers, source=source_path)


def _parse_generic(data: dict, source_path: str | None = None) -> MCPConfigFile:
    raw_servers: list = data.get("servers", [])
    servers: dict[str, MCPServerConfig] = {}
    for entry in raw_servers:
        name: str = entry.get("name", "")
        if not name:
            raise ConfigParseError("Generic format server entry missing 'name' field.")
        servers[name] = MCPServerConfig(
            name=name,
            command=entry.get("command"),
            url=entry.get("url"),
            args=entry.get("args", []),
            env=entry.get("env", {}),
            transport=_infer_transport(entry),
        )
    return MCPConfigFile(servers=servers, source=source_path)


def _detect_format(data: dict) -> str:
    if "mcpServers" in data:
        return "claude_desktop"
    if "servers" in data and isinstance(data["servers"], list):
        return "generic"
    raise ConfigParseError(
        "Unrecognised MCP config format. "
        "Expected 'mcpServers' (Claude Desktop / Cursor) or 'servers' (generic list)."
    )


def parse_config_file(path: Path) -> MCPConfigFile:
    if not path.exists():
        raise ConfigParseError(f"Config file not found: {path}")

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigParseError(f"Invalid JSON in config file: {exc}") from exc

    fmt = _detect_format(data)
    source = str(path.resolve())

    if fmt in ("claude_desktop", "cursor"):
        return _parse_claude_or_cursor(data, source_path=source)
    return _parse_generic(data, source_path=source)


def make_single_server_config(url: str, name: str = "remote") -> MCPConfigFile:
    transport = _infer_transport({"url": url})
    server = MCPServerConfig(name=name, url=url, transport=transport)
    return MCPConfigFile(servers={name: server}, source=None)
