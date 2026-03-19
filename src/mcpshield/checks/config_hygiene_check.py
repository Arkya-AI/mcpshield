from __future__ import annotations

import re
from collections import Counter

from mcpshield.checks.base import BaseCheck
from mcpshield.models import MCPConfigFile, MCPServerConfig, SecurityFinding, Severity, TransportType

# Maximum number of servers before we flag complexity risk
_MAX_SERVERS = 20

# Placeholder values that indicate an unconfigured entry
_PLACEHOLDER_PATTERN: re.Pattern[str] = re.compile(
    r"(?i)^("
    r"your[_\-]?api[_\-]?key([_\-]?here)?"
    r"|your[_\-]?token([_\-]?here)?"
    r"|your[_\-]?secret([_\-]?here)?"
    r"|your[_\-]?password([_\-]?here)?"
    r"|insert[_\-]?key[_\-]?here"
    r"|replace[_\-]?me"
    r"|change[_\-]?me"
    r"|<[^>]+>"           # <PLACEHOLDER> style
    r"|\{[^}]+\}"         # {PLACEHOLDER} style
    r"|placeholder"
    r"|example[_\-]?key"
    r"|dummy[_\-]?(key|token|secret|password)"
    r"|test[_\-]?(key|token|secret)"
    r"|todo"
    r"|fixme"
    r"|xxx+"
    r")$"
)


class ConfigHygieneCheck(BaseCheck):
    """Detect structural and hygiene issues in the overall MCP configuration."""

    check_id = "HYGN001"
    name = "Config Hygiene Check"
    description = (
        "Validates overall MCP configuration quality: detects empty configs, "
        "duplicate server names, incomplete server entries, unconfigured "
        "placeholder values, and excessive server counts."
    )

    # ---------------------------------------------------------------------- #
    # Public entry point — accepts either a single server or a full config   #
    # ---------------------------------------------------------------------- #

    async def run(self, server: MCPServerConfig) -> list[SecurityFinding]:
        """Per-server hygiene checks (placeholder values, empty command/url)."""
        findings: list[SecurityFinding] = []
        findings.extend(self._check_incomplete_server(server))
        findings.extend(self._check_placeholder_env_values(server))
        return findings

    async def run_config(self, config: MCPConfigFile) -> list[SecurityFinding]:
        """Whole-config hygiene checks (empty config, duplicates, server count).

        Call this method from the scanner when a full MCPConfigFile is available.
        """
        findings: list[SecurityFinding] = []
        findings.extend(self._check_empty_config(config))
        findings.extend(self._check_duplicate_names(config))
        findings.extend(self._check_server_count(config))
        for srv in config.servers.values():
            findings.extend(await self.run(srv))
        return findings

    # ---------------------------------------------------------------------- #
    # Individual sub-checks                                                   #
    # ---------------------------------------------------------------------- #

    def _check_empty_config(self, config: MCPConfigFile) -> list[SecurityFinding]:
        if not config.servers:
            source = config.source or "unknown"
            return [
                SecurityFinding(
                    check_id=self.check_id,
                    severity=Severity.INFO,
                    title="MCP configuration contains no servers",
                    description=(
                        f"The configuration file '{source}' defines no MCP "
                        "servers. This may indicate an incomplete setup or an "
                        "accidentally empty file."
                    ),
                    remediation=(
                        "Add at least one server entry, or remove the "
                        "configuration file if it is no longer needed."
                    ),
                )
            ]
        return []

    def _check_duplicate_names(self, config: MCPConfigFile) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        # The dict keys are the canonical names; duplicates can arise from
        # case-insensitive collisions or copy-paste errors where the 'name'
        # field inside the object differs from its dict key.
        name_counts: Counter[str] = Counter()
        for key, srv in config.servers.items():
            name_counts[key.lower()] += 1
            if srv.name.lower() != key.lower():
                # Inner name disagrees with the dict key — flag it
                findings.append(
                    SecurityFinding(
                        check_id=self.check_id,
                        severity=Severity.LOW,
                        title="Server name mismatch between key and config object",
                        description=(
                            f"The configuration key '{key}' contains a server "
                            f"whose 'name' field is '{srv.name}'. This mismatch "
                            "can cause confusion and may indicate a copy-paste "
                            "error."
                        ),
                        remediation=(
                            "Ensure the dict key matches the 'name' field for "
                            f"every server entry. Update either the key or the "
                            f"name field for '{key}'."
                        ),
                    )
                )

        for name, count in name_counts.items():
            if count > 1:
                findings.append(
                    SecurityFinding(
                        check_id=self.check_id,
                        severity=Severity.MEDIUM,
                        title=f"Duplicate server name '{name}'",
                        description=(
                            f"The server name '{name}' appears {count} times in "
                            "the configuration (case-insensitive). Duplicate names "
                            "can cause clients to load the wrong server or silently "
                            "overwrite entries."
                        ),
                        remediation=(
                            "Ensure every server entry has a unique name. "
                            f"Rename or remove the duplicate entries for '{name}'."
                        ),
                    )
                )
        return findings

    def _check_server_count(self, config: MCPConfigFile) -> list[SecurityFinding]:
        count = len(config.servers)
        if count > _MAX_SERVERS:
            return [
                SecurityFinding(
                    check_id=self.check_id,
                    severity=Severity.LOW,
                    title=f"Excessive number of configured servers ({count})",
                    description=(
                        f"The configuration defines {count} MCP servers, which "
                        f"exceeds the recommended maximum of {_MAX_SERVERS}. "
                        "Large numbers of servers increase the attack surface, "
                        "make auditing difficult, and can slow MCP client startup."
                    ),
                    remediation=(
                        "Review whether all configured servers are actively used. "
                        "Remove stale or unused entries and consider grouping "
                        "related functionality into fewer, well-scoped servers."
                    ),
                )
            ]
        return []

    def _check_incomplete_server(
        self, server: MCPServerConfig
    ) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []

        if server.transport == TransportType.STDIO:
            if not server.command or not server.command.strip():
                findings.append(
                    SecurityFinding(
                        check_id=self.check_id,
                        severity=Severity.HIGH,
                        title=f"stdio server '{server.name}' has no command",
                        description=(
                            f"Server '{server.name}' is configured as a stdio "
                            "server but the 'command' field is empty or absent. "
                            "The server cannot start without a command."
                        ),
                        remediation=(
                            "Set the 'command' field to the executable that "
                            "should be launched for this server."
                        ),
                    )
                )
        else:
            if not server.url or not server.url.strip():
                findings.append(
                    SecurityFinding(
                        check_id=self.check_id,
                        severity=Severity.HIGH,
                        title=(
                            f"Remote server '{server.name}' has no URL "
                            f"(transport: {server.transport.value})"
                        ),
                        description=(
                            f"Server '{server.name}' uses transport "
                            f"'{server.transport.value}' but the 'url' field is "
                            "empty or absent. The server cannot connect without "
                            "a URL."
                        ),
                        remediation=(
                            "Set the 'url' field to the endpoint where this "
                            "server is reachable."
                        ),
                    )
                )
        return findings

    def _check_placeholder_env_values(
        self, server: MCPServerConfig
    ) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        for key, value in server.env.items():
            if _PLACEHOLDER_PATTERN.match(value.strip()):
                findings.append(
                    SecurityFinding(
                        check_id=self.check_id,
                        severity=Severity.MEDIUM,
                        title=f"Placeholder value in env var '{key}'",
                        description=(
                            f"Server '{server.name}' sets environment variable "
                            f"'{key}' to a placeholder value ('{value}'). The "
                            "server will likely fail to authenticate or function "
                            "correctly until a real value is provided."
                        ),
                        remediation=(
                            f"Replace the placeholder value in '{key}' with the "
                            "real credential or configuration value, sourced from "
                            "a secrets manager or a .env file excluded from "
                            "version control."
                        ),
                    )
                )
        return findings
