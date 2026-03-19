from __future__ import annotations

import os
import re
from urllib.parse import urlparse

from mcpshield.checks.base import BaseCheck
from mcpshield.models import MCPServerConfig, SecurityFinding, Severity, TransportType

# ---------------------------------------------------------------------------
# Shell executables — running a shell directly as an MCP server suggests
# the "command" is a shell invocation, which is a command-injection risk.
# ---------------------------------------------------------------------------
_SHELL_EXECUTABLES: frozenset[str] = frozenset(
    {
        "bash",
        "sh",
        "zsh",
        "fish",
        "dash",
        "ksh",
        "csh",
        "tcsh",
        "cmd",
        "cmd.exe",
        "powershell",
        "powershell.exe",
        "pwsh",
        "pwsh.exe",
    }
)

# ---------------------------------------------------------------------------
# Privilege-escalation prefixes — commands launched with these run the MCP
# server as root/administrator, which is never appropriate.
# ---------------------------------------------------------------------------
_PRIVILEGE_ESCALATION_COMMANDS: re.Pattern[str] = re.compile(
    r"^(sudo|doas|runas|su|pkexec)\b",
    re.IGNORECASE,
)

# Deprecated / experimental transport identifiers that should no longer be used
_DEPRECATED_TRANSPORTS: frozenset[str] = frozenset({"sse"})


def _command_basename(command: str) -> str:
    """Return the basename of a command path (handles both / and \\ separators)."""
    return os.path.basename(command.replace("\\", "/")).lower()


class TransportSecurityCheck(BaseCheck):
    """Detect transport-layer security issues in MCP server configurations."""

    check_id = "TRANS001"
    name = "Transport Security Check"
    description = (
        "Checks for insecure or misconfigured transport settings including "
        "privilege-escalating stdio commands, direct shell invocations, "
        "non-HTTPS remote URLs, and deprecated transport types."
    )

    async def run(self, server: MCPServerConfig) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        command = server.command or ""

        # ------------------------------------------------------------------ #
        # 1. stdio server launched with a privilege-escalation prefix         #
        # ------------------------------------------------------------------ #
        if server.transport == TransportType.STDIO and command:
            cmd_basename = _command_basename(command)
            if _PRIVILEGE_ESCALATION_COMMANDS.match(cmd_basename):
                findings.append(
                    SecurityFinding(
                        check_id=self.check_id,
                        severity=Severity.CRITICAL,
                        title="MCP server launched with privilege escalation",
                        description=(
                            f"Server '{server.name}' is configured to run via "
                            f"'{cmd_basename}' (full command: '{command}'). "
                            "Running an MCP server with sudo/runas/su grants it "
                            "root or administrator-level access to the host, "
                            "which dramatically increases the impact of any "
                            "tool-poisoning or prompt-injection attack."
                        ),
                        remediation=(
                            "Remove the privilege-escalation wrapper. If elevated "
                            "permissions are genuinely needed for a specific "
                            "operation, implement a narrow, audited helper process "
                            "rather than running the entire MCP server as root."
                        ),
                    )
                )

            # ---------------------------------------------------------------- #
            # 2. Command is a shell — suggests command injection risk           #
            # ---------------------------------------------------------------- #
            if cmd_basename in _SHELL_EXECUTABLES:
                findings.append(
                    SecurityFinding(
                        check_id=self.check_id,
                        severity=Severity.HIGH,
                        title="MCP server command is a shell interpreter",
                        description=(
                            f"Server '{server.name}' uses '{cmd_basename}' as its "
                            "command. Pointing an MCP server entry directly at a "
                            "shell (bash, sh, cmd, powershell, etc.) is a strong "
                            "indicator of a command-injection vulnerability or a "
                            "misconfigured entry that could allow arbitrary code "
                            "execution on the host."
                        ),
                        remediation=(
                            "Replace the shell command with the actual server "
                            "binary or a purpose-built launcher script. If a "
                            "shell wrapper is unavoidable, audit it thoroughly "
                            "and ensure all inputs are sanitized."
                        ),
                    )
                )

        # ------------------------------------------------------------------ #
        # 3. Remote server URL is not HTTPS                                   #
        # ------------------------------------------------------------------ #
        if server.transport in (TransportType.SSE, TransportType.HTTP):
            url = server.url or ""
            if url:
                scheme = urlparse(url).scheme.lower()
                if scheme and scheme != "https":
                    findings.append(
                        SecurityFinding(
                            check_id=self.check_id,
                            severity=Severity.HIGH,
                            title="Remote MCP server does not use HTTPS",
                            description=(
                                f"Server '{server.name}' uses URL '{url}' with "
                                f"scheme '{scheme}'. Without TLS, all MCP protocol "
                                "messages — including tool calls and their results "
                                "— travel in plaintext and can be intercepted or "
                                "tampered with in transit."
                            ),
                            remediation=(
                                "Update the server URL to use the 'https://' "
                                "scheme and configure the server with a valid TLS "
                                "certificate (e.g., from Let's Encrypt)."
                            ),
                        )
                    )
            else:
                # Remote transport with no URL at all
                findings.append(
                    SecurityFinding(
                        check_id=self.check_id,
                        severity=Severity.MEDIUM,
                        title="Remote transport configured without a URL",
                        description=(
                            f"Server '{server.name}' specifies transport "
                            f"'{server.transport.value}' but has no URL set. "
                            "The server cannot function and the configuration is "
                            "incomplete."
                        ),
                        remediation=(
                            "Supply a valid 'url' field for this server, or "
                            "change the transport to 'stdio' if the server runs "
                            "as a local process."
                        ),
                    )
                )

        # ------------------------------------------------------------------ #
        # 4. Deprecated transport type                                        #
        # ------------------------------------------------------------------ #
        if server.transport.value in _DEPRECATED_TRANSPORTS:
            findings.append(
                SecurityFinding(
                    check_id=self.check_id,
                    severity=Severity.LOW,
                    title=f"Deprecated transport type '{server.transport.value}'",
                    description=(
                        f"Server '{server.name}' uses the '{server.transport.value}' "
                        "transport, which is deprecated in the MCP specification. "
                        "Deprecated transports may receive fewer security patches "
                        "and could be removed in future versions of MCP clients."
                    ),
                    remediation=(
                        "Migrate the server to the 'streamable-http' transport, "
                        "which is the current recommended replacement for SSE."
                    ),
                )
            )

        return findings
