"""Tests for ConfigHygieneCheck (HYGN001)."""
from __future__ import annotations

import pytest

from mcpshield.checks.config_hygiene_check import ConfigHygieneCheck
from mcpshield.models import MCPConfigFile, MCPServerConfig, Severity, TransportType


@pytest.fixture()
def check() -> ConfigHygieneCheck:
    return ConfigHygieneCheck()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _stdio_server(name: str, command: str | None = "python") -> MCPServerConfig:
    return MCPServerConfig(name=name, transport=TransportType.STDIO, command=command)


def _http_server(name: str, url: str | None = "https://api.example.com/mcp") -> MCPServerConfig:
    return MCPServerConfig(name=name, transport=TransportType.HTTP, url=url)


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


class TestMetadata:
    def test_check_id(self, check: ConfigHygieneCheck):
        assert check.check_id == "HYGN001"

    def test_name(self, check: ConfigHygieneCheck):
        assert check.name == "Config Hygiene Check"


# ---------------------------------------------------------------------------
# run() — per-server checks
# ---------------------------------------------------------------------------


class TestRunPerServer:
    async def test_clean_stdio_no_findings(self, check: ConfigHygieneCheck):
        srv = _stdio_server("my-server", command="python")
        findings = await check.run(srv)
        assert findings == []

    async def test_clean_http_no_findings(self, check: ConfigHygieneCheck):
        srv = _http_server("my-remote")
        findings = await check.run(srv)
        assert findings == []

    async def test_clean_server_with_env_no_findings(self, check: ConfigHygieneCheck):
        srv = MCPServerConfig(
            name="srv",
            transport=TransportType.STDIO,
            command="python",
            env={"NODE_ENV": "production"},
        )
        findings = await check.run(srv)
        assert findings == []


# ---------------------------------------------------------------------------
# Incomplete server: no command (stdio) — HIGH
# ---------------------------------------------------------------------------


class TestIncompleteServer:
    async def test_stdio_no_command_flagged(self, check: ConfigHygieneCheck):
        srv = _stdio_server("no-cmd", command=None)
        findings = await check.run(srv)
        incomplete = [f for f in findings if "has no command" in f.title]
        assert len(incomplete) == 1
        assert incomplete[0].severity == Severity.HIGH

    async def test_stdio_empty_command_flagged(self, check: ConfigHygieneCheck):
        srv = _stdio_server("no-cmd", command="   ")
        findings = await check.run(srv)
        incomplete = [f for f in findings if "has no command" in f.title]
        assert len(incomplete) == 1

    async def test_stdio_with_command_clean(self, check: ConfigHygieneCheck):
        srv = _stdio_server("has-cmd", command="python")
        findings = await check.run(srv)
        incomplete = [f for f in findings if "has no command" in f.title]
        assert incomplete == []

    async def test_http_no_url_flagged(self, check: ConfigHygieneCheck):
        srv = _http_server("no-url", url=None)
        findings = await check.run(srv)
        incomplete = [f for f in findings if "has no URL" in f.title]
        assert len(incomplete) == 1
        assert incomplete[0].severity == Severity.HIGH

    async def test_http_empty_url_flagged(self, check: ConfigHygieneCheck):
        srv = _http_server("empty-url", url="   ")
        findings = await check.run(srv)
        incomplete = [f for f in findings if "has no URL" in f.title]
        assert len(incomplete) == 1

    async def test_http_with_url_clean(self, check: ConfigHygieneCheck):
        srv = _http_server("ok-remote", url="https://api.example.com")
        findings = await check.run(srv)
        incomplete = [f for f in findings if "has no URL" in f.title]
        assert incomplete == []

    async def test_sse_no_url_flagged(self, check: ConfigHygieneCheck):
        srv = MCPServerConfig(name="sse-no-url", transport=TransportType.SSE, url=None)
        findings = await check.run(srv)
        incomplete = [f for f in findings if "has no URL" in f.title]
        assert len(incomplete) == 1


# ---------------------------------------------------------------------------
# Placeholder env values — MEDIUM
# ---------------------------------------------------------------------------


class TestPlaceholderEnvValues:
    @pytest.mark.parametrize(
        "value",
        [
            "your_api_key",
            "your_api_key_here",
            "YOUR_API_KEY",
            "your-token-here",
            "your_secret_here",
            "your_password_here",
            "insert_key_here",
            "replace-me",
            "change_me",
            "<API_KEY>",
            "<PLACEHOLDER>",
            "{REPLACE_WITH_REAL}",
            "placeholder",
            "example_key",
            "dummy_token",
            "dummy_secret",
            "test_key",
            "test_token",
            "todo",
            "fixme",
            "xxx",
            "xxxxx",
        ],
    )
    async def test_placeholder_value_flagged(
        self, check: ConfigHygieneCheck, value: str
    ):
        srv = MCPServerConfig(
            name="srv",
            command="python",
            env={"API_KEY": value},
        )
        findings = await check.run(srv)
        placeholder_findings = [f for f in findings if "Placeholder value" in f.title]
        assert len(placeholder_findings) >= 1, f"'{value}' should be flagged as placeholder"
        assert placeholder_findings[0].severity == Severity.MEDIUM

    async def test_real_value_not_flagged(self, check: ConfigHygieneCheck):
        srv = MCPServerConfig(
            name="srv",
            command="python",
            env={"API_KEY": "sk-actual-real-key-12345"},
        )
        findings = await check.run(srv)
        placeholder_findings = [f for f in findings if "Placeholder value" in f.title]
        assert placeholder_findings == []

    async def test_multiple_placeholders_multiple_findings(
        self, check: ConfigHygieneCheck
    ):
        srv = MCPServerConfig(
            name="srv",
            command="python",
            env={"API_KEY": "your_api_key", "SECRET": "replace-me"},
        )
        findings = await check.run(srv)
        placeholder_findings = [f for f in findings if "Placeholder value" in f.title]
        assert len(placeholder_findings) == 2


# ---------------------------------------------------------------------------
# run_config() — whole-config checks
# ---------------------------------------------------------------------------


class TestRunConfig:
    async def test_empty_config_info_finding(self, check: ConfigHygieneCheck):
        cfg = MCPConfigFile(servers={}, source="/path/to/config.json")
        findings = await check.run_config(cfg)
        empty_findings = [f for f in findings if "no servers" in f.title]
        assert len(empty_findings) == 1
        assert empty_findings[0].severity == Severity.INFO

    async def test_empty_config_unknown_source(self, check: ConfigHygieneCheck):
        cfg = MCPConfigFile(servers={}, source=None)
        findings = await check.run_config(cfg)
        empty_findings = [f for f in findings if "no servers" in f.title]
        assert len(empty_findings) == 1
        assert "unknown" in empty_findings[0].description

    async def test_non_empty_config_no_empty_finding(self, check: ConfigHygieneCheck):
        cfg = MCPConfigFile(
            servers={"a": _stdio_server("a", command="python")},
        )
        findings = await check.run_config(cfg)
        empty_findings = [f for f in findings if "no servers" in f.title]
        assert empty_findings == []

    async def test_name_mismatch_flagged(self, check: ConfigHygieneCheck):
        """Key 'server-a' but inner name is 'server-b' — should be flagged."""
        srv = MCPServerConfig(name="server-b", command="python")
        cfg = MCPConfigFile(servers={"server-a": srv})
        findings = await check.run_config(cfg)
        mismatch = [f for f in findings if "name mismatch" in f.title]
        assert len(mismatch) == 1
        assert mismatch[0].severity == Severity.LOW

    async def test_matching_key_and_name_no_mismatch(self, check: ConfigHygieneCheck):
        srv = MCPServerConfig(name="server-a", command="python")
        cfg = MCPConfigFile(servers={"server-a": srv})
        findings = await check.run_config(cfg)
        mismatch = [f for f in findings if "name mismatch" in f.title]
        assert mismatch == []

    async def test_case_insensitive_duplicate_name_flagged(
        self, check: ConfigHygieneCheck
    ):
        """Keys 'Server' and 'server' are case-insensitive duplicates."""
        cfg = MCPConfigFile(
            servers={
                "Server": MCPServerConfig(name="Server", command="python"),
                "server": MCPServerConfig(name="server", command="node"),
            }
        )
        findings = await check.run_config(cfg)
        dup_findings = [f for f in findings if "Duplicate server name" in f.title]
        assert len(dup_findings) >= 1
        assert dup_findings[0].severity == Severity.MEDIUM

    async def test_server_count_below_limit_no_finding(
        self, check: ConfigHygieneCheck
    ):
        servers = {f"s{i}": _stdio_server(f"s{i}") for i in range(20)}
        cfg = MCPConfigFile(servers=servers)
        findings = await check.run_config(cfg)
        count_findings = [f for f in findings if "Excessive number" in f.title]
        assert count_findings == []

    async def test_server_count_exceeds_limit_low_finding(
        self, check: ConfigHygieneCheck
    ):
        servers = {f"s{i}": _stdio_server(f"s{i}") for i in range(21)}
        cfg = MCPConfigFile(servers=servers)
        findings = await check.run_config(cfg)
        count_findings = [f for f in findings if "Excessive number" in f.title]
        assert len(count_findings) == 1
        assert count_findings[0].severity == Severity.LOW

    async def test_run_config_also_runs_per_server(self, check: ConfigHygieneCheck):
        """run_config must also run per-server checks (incomplete command check)."""
        bad_srv = _stdio_server("bad", command=None)
        cfg = MCPConfigFile(servers={"bad": bad_srv})
        findings = await check.run_config(cfg)
        incomplete = [f for f in findings if "has no command" in f.title]
        assert len(incomplete) == 1

    async def test_clean_config_no_findings(self, check: ConfigHygieneCheck):
        cfg = MCPConfigFile(
            servers={
                "fs": MCPServerConfig(name="fs", command="npx", env={"NODE_ENV": "production"}),
                "remote": MCPServerConfig(
                    name="remote",
                    transport=TransportType.HTTP,
                    url="https://api.example.com/mcp",
                ),
            }
        )
        findings = await check.run_config(cfg)
        assert findings == []


# ---------------------------------------------------------------------------
# All findings have required fields
# ---------------------------------------------------------------------------


class TestFindingFields:
    async def test_all_per_server_findings_have_check_id(
        self, check: ConfigHygieneCheck
    ):
        srv = _stdio_server("empty", command=None)
        findings = await check.run(srv)
        for f in findings:
            assert f.check_id == "HYGN001"

    async def test_all_config_findings_have_check_id(self, check: ConfigHygieneCheck):
        cfg = MCPConfigFile(servers={})
        findings = await check.run_config(cfg)
        for f in findings:
            assert f.check_id == "HYGN001"
