"""Tests for mcpshield.cli.config_parser."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from mcpshield.cli.config_parser import (
    ConfigParseError,
    make_single_server_config,
    parse_config_file,
)
from mcpshield.models import MCPConfigFile, TransportType


# ---------------------------------------------------------------------------
# Fixtures — write temp JSON files for parse_config_file
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_path_json(tmp_path: Path):
    """Helper: write a dict as JSON to a temp file and return the Path."""

    def _write(data: dict, filename: str = "config.json") -> Path:
        p = tmp_path / filename
        p.write_text(json.dumps(data), encoding="utf-8")
        return p

    return _write


# ---------------------------------------------------------------------------
# parse_config_file — file-not-found
# ---------------------------------------------------------------------------


class TestFileNotFound:
    def test_missing_file_raises(self):
        with pytest.raises(ConfigParseError, match="not found"):
            parse_config_file(Path("/nonexistent/path/config.json"))


# ---------------------------------------------------------------------------
# parse_config_file — invalid JSON
# ---------------------------------------------------------------------------


class TestInvalidJson:
    def test_bad_json_raises(self, tmp_path: Path):
        bad = tmp_path / "bad.json"
        bad.write_text("{invalid json}", encoding="utf-8")
        with pytest.raises(ConfigParseError, match="Invalid JSON"):
            parse_config_file(bad)


# ---------------------------------------------------------------------------
# parse_config_file — unrecognised format
# ---------------------------------------------------------------------------


class TestUnrecognisedFormat:
    def test_empty_object_raises(self, tmp_path_json):
        p = tmp_path_json({})
        with pytest.raises(ConfigParseError, match="Unrecognised"):
            parse_config_file(p)

    def test_unknown_keys_raises(self, tmp_path_json):
        p = tmp_path_json({"foo": "bar"})
        with pytest.raises(ConfigParseError, match="Unrecognised"):
            parse_config_file(p)

    def test_servers_as_dict_raises(self, tmp_path_json):
        """'servers' must be a list for generic format; a dict is unrecognised."""
        p = tmp_path_json({"servers": {}})
        with pytest.raises(ConfigParseError, match="Unrecognised"):
            parse_config_file(p)


# ---------------------------------------------------------------------------
# parse_config_file — Claude Desktop / Cursor format
# ---------------------------------------------------------------------------


class TestClaudeDesktopFormat:
    def _claude_data(self) -> dict:
        return {
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                    "env": {"NODE_ENV": "production"},
                },
                "remote-api": {
                    "url": "https://api.example.com/mcp",
                    "env": {"API_KEY": "token123"},
                },
            }
        }

    def test_returns_mcp_config_file(self, tmp_path_json):
        p = tmp_path_json(self._claude_data())
        result = parse_config_file(p)
        assert isinstance(result, MCPConfigFile)

    def test_source_is_set_to_resolved_path(self, tmp_path_json):
        p = tmp_path_json(self._claude_data())
        result = parse_config_file(p)
        assert result.source == str(p.resolve())

    def test_server_count(self, tmp_path_json):
        p = tmp_path_json(self._claude_data())
        result = parse_config_file(p)
        assert len(result.servers) == 2

    def test_stdio_server_parsed_correctly(self, tmp_path_json):
        p = tmp_path_json(self._claude_data())
        result = parse_config_file(p)
        fs = result.servers["filesystem"]
        assert fs.name == "filesystem"
        assert fs.command == "npx"
        assert fs.args == ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
        assert fs.env == {"NODE_ENV": "production"}
        assert fs.transport == TransportType.STDIO

    def test_remote_server_transport_inferred_http(self, tmp_path_json):
        p = tmp_path_json(self._claude_data())
        result = parse_config_file(p)
        remote = result.servers["remote-api"]
        assert remote.transport == TransportType.HTTP
        assert remote.url == "https://api.example.com/mcp"

    def test_empty_mcpservers_returns_empty_config(self, tmp_path_json):
        p = tmp_path_json({"mcpServers": {}})
        result = parse_config_file(p)
        assert result.servers == {}

    def test_server_name_is_dict_key(self, tmp_path_json):
        data = {"mcpServers": {"my-tool": {"command": "python"}}}
        p = tmp_path_json(data)
        result = parse_config_file(p)
        assert "my-tool" in result.servers
        assert result.servers["my-tool"].name == "my-tool"

    def test_args_default_to_empty_list(self, tmp_path_json):
        data = {"mcpServers": {"srv": {"command": "python"}}}
        p = tmp_path_json(data)
        result = parse_config_file(p)
        assert result.servers["srv"].args == []

    def test_env_defaults_to_empty_dict(self, tmp_path_json):
        data = {"mcpServers": {"srv": {"command": "python"}}}
        p = tmp_path_json(data)
        result = parse_config_file(p)
        assert result.servers["srv"].env == {}


# ---------------------------------------------------------------------------
# Transport inference — _infer_transport via parse_config_file
# ---------------------------------------------------------------------------


class TestTransportInference:
    def test_no_url_infers_stdio(self, tmp_path_json):
        data = {"mcpServers": {"srv": {"command": "python"}}}
        p = tmp_path_json(data)
        result = parse_config_file(p)
        assert result.servers["srv"].transport == TransportType.STDIO

    def test_url_infers_http(self, tmp_path_json):
        data = {"mcpServers": {"srv": {"url": "https://api.example.com/mcp"}}}
        p = tmp_path_json(data)
        result = parse_config_file(p)
        assert result.servers["srv"].transport == TransportType.HTTP

    def test_sse_in_url_infers_sse(self, tmp_path_json):
        data = {"mcpServers": {"srv": {"url": "https://api.example.com/sse/stream"}}}
        p = tmp_path_json(data)
        result = parse_config_file(p)
        assert result.servers["srv"].transport == TransportType.SSE

    def test_url_ending_with_events_infers_sse(self, tmp_path_json):
        data = {"mcpServers": {"srv": {"url": "https://api.example.com/events"}}}
        p = tmp_path_json(data)
        result = parse_config_file(p)
        assert result.servers["srv"].transport == TransportType.SSE


# ---------------------------------------------------------------------------
# parse_config_file — generic format
# ---------------------------------------------------------------------------


class TestGenericFormat:
    def _generic_data(self) -> dict:
        return {
            "servers": [
                {
                    "name": "fs-server",
                    "command": "python",
                    "args": ["-m", "mcp_server"],
                    "env": {"DEBUG": "false"},
                },
                {
                    "name": "remote-server",
                    "url": "https://api.example.com/mcp",
                },
            ]
        }

    def test_returns_mcp_config_file(self, tmp_path_json):
        p = tmp_path_json(self._generic_data())
        result = parse_config_file(p)
        assert isinstance(result, MCPConfigFile)

    def test_server_count(self, tmp_path_json):
        p = tmp_path_json(self._generic_data())
        result = parse_config_file(p)
        assert len(result.servers) == 2

    def test_stdio_server_parsed(self, tmp_path_json):
        p = tmp_path_json(self._generic_data())
        result = parse_config_file(p)
        fs = result.servers["fs-server"]
        assert fs.name == "fs-server"
        assert fs.command == "python"
        assert fs.args == ["-m", "mcp_server"]
        assert fs.transport == TransportType.STDIO

    def test_remote_server_parsed(self, tmp_path_json):
        p = tmp_path_json(self._generic_data())
        result = parse_config_file(p)
        remote = result.servers["remote-server"]
        assert remote.url == "https://api.example.com/mcp"
        assert remote.transport == TransportType.HTTP

    def test_missing_name_raises(self, tmp_path_json):
        data = {"servers": [{"command": "python"}]}
        p = tmp_path_json(data)
        with pytest.raises(ConfigParseError, match="missing 'name'"):
            parse_config_file(p)

    def test_empty_servers_list_empty_config(self, tmp_path_json):
        data = {"servers": []}
        p = tmp_path_json(data)
        result = parse_config_file(p)
        assert result.servers == {}

    def test_source_is_set(self, tmp_path_json):
        p = tmp_path_json(self._generic_data())
        result = parse_config_file(p)
        assert result.source == str(p.resolve())


# ---------------------------------------------------------------------------
# parse_config_file — sample fixture file
# ---------------------------------------------------------------------------


class TestSampleFixture:
    def test_sample_config_parses_successfully(self):
        fixture = Path(__file__).parent / "fixtures" / "sample_config.json"
        result = parse_config_file(fixture)
        assert isinstance(result, MCPConfigFile)
        assert len(result.servers) == 5

    def test_sample_config_server_names(self):
        fixture = Path(__file__).parent / "fixtures" / "sample_config.json"
        result = parse_config_file(fixture)
        assert "secure-server" in result.servers
        assert "insecure-remote" in result.servers
        assert "leaky-creds" in result.servers
        assert "dangerous-transport" in result.servers
        assert "vulnerable-mcp-remote" in result.servers

    def test_sample_secure_server_is_stdio(self):
        fixture = Path(__file__).parent / "fixtures" / "sample_config.json"
        result = parse_config_file(fixture)
        srv = result.servers["secure-server"]
        assert srv.transport == TransportType.STDIO
        assert srv.command == "npx"

    def test_sample_insecure_remote_is_http(self):
        fixture = Path(__file__).parent / "fixtures" / "sample_config.json"
        result = parse_config_file(fixture)
        srv = result.servers["insecure-remote"]
        assert srv.transport == TransportType.HTTP
        assert srv.url == "http://0.0.0.0:3000/mcp"


# ---------------------------------------------------------------------------
# make_single_server_config
# ---------------------------------------------------------------------------


class TestMakeSingleServerConfig:
    def test_returns_mcp_config_file(self):
        result = make_single_server_config("https://api.example.com/mcp")
        assert isinstance(result, MCPConfigFile)

    def test_default_name_is_remote(self):
        result = make_single_server_config("https://api.example.com/mcp")
        assert "remote" in result.servers

    def test_custom_name(self):
        result = make_single_server_config("https://api.example.com/mcp", name="my-srv")
        assert "my-srv" in result.servers

    def test_http_transport_inferred(self):
        result = make_single_server_config("https://api.example.com/mcp")
        srv = list(result.servers.values())[0]
        assert srv.transport == TransportType.HTTP

    def test_sse_transport_inferred(self):
        result = make_single_server_config("https://api.example.com/sse")
        srv = list(result.servers.values())[0]
        assert srv.transport == TransportType.SSE

    def test_source_is_none(self):
        result = make_single_server_config("https://api.example.com/mcp")
        assert result.source is None

    def test_url_stored_on_server(self):
        url = "https://api.example.com/mcp"
        result = make_single_server_config(url)
        srv = list(result.servers.values())[0]
        assert srv.url == url
