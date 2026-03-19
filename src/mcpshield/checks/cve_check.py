from __future__ import annotations

import re
from dataclasses import dataclass, field

from mcpshield.checks.base import BaseCheck
from mcpshield.models import MCPServerConfig, SecurityFinding, Severity


@dataclass(frozen=True)
class CVEEntry:
    """Describes a known MCP-related CVE."""

    cve_id: str
    cvss: float
    severity: Severity
    summary: str
    # Package/binary names that indicate exposure (matched against command + args)
    affected_packages: tuple[str, ...]
    remediation: str


# ---------------------------------------------------------------------------
# Known MCP CVE database
# ---------------------------------------------------------------------------
# Keep entries sorted by CVSS descending so the first match is always the
# highest-severity one for a given package.
_KNOWN_CVES: tuple[CVEEntry, ...] = (
    CVEEntry(
        cve_id="CVE-2025-6514",
        cvss=9.6,
        severity=Severity.CRITICAL,
        summary=(
            "mcp-remote is vulnerable to server-side request forgery (SSRF) and "
            "remote code execution via a malicious MCP server that supplies a "
            "crafted redirect URL during the OAuth handshake. An attacker-controlled "
            "server can redirect the client to an arbitrary endpoint, potentially "
            "exfiltrating OAuth tokens or executing arbitrary code in the client "
            "process context."
        ),
        affected_packages=("mcp-remote",),
        remediation=(
            "Upgrade mcp-remote to version 0.1.18 or later, which validates "
            "redirect URIs against the registered client URI. As a short-term "
            "workaround, only connect to trusted MCP servers when using mcp-remote."
        ),
    ),
    CVEEntry(
        cve_id="CVE-2025-49596",
        cvss=8.8,
        severity=Severity.HIGH,
        summary=(
            "The mcp package (Python) before 1.8.0 does not sanitize tool names "
            "before rendering them in certain UI contexts, enabling stored "
            "cross-site scripting (XSS) via a malicious tool name returned by a "
            "connected server."
        ),
        affected_packages=("mcp",),
        remediation=(
            "Upgrade the 'mcp' Python package to version 1.8.0 or later. "
            "Avoid connecting to untrusted MCP servers."
        ),
    ),
    CVEEntry(
        cve_id="CVE-2025-53364",
        cvss=7.5,
        severity=Severity.HIGH,
        summary=(
            "@modelcontextprotocol/sdk (npm) before 1.12.0 does not enforce "
            "origin validation on WebSocket upgrade requests, allowing a "
            "cross-origin WebSocket hijacking attack from a malicious web page "
            "when the server is bound to localhost."
        ),
        affected_packages=("@modelcontextprotocol/sdk", "modelcontextprotocol"),
        remediation=(
            "Upgrade @modelcontextprotocol/sdk to version 1.12.0 or later. "
            "Ensure the server enforces strict Origin header validation."
        ),
    ),
)

# ---------------------------------------------------------------------------
# Package name → CVE lookup, built once at import time
# ---------------------------------------------------------------------------
_PACKAGE_TO_CVES: dict[str, list[CVEEntry]] = {}
for _entry in _KNOWN_CVES:
    for _pkg in _entry.affected_packages:
        _PACKAGE_TO_CVES.setdefault(_pkg.lower(), []).append(_entry)


def _build_pkg_pattern(package_name: str) -> re.Pattern[str]:
    """Return a regex that matches the package name as a word/path component."""
    escaped = re.escape(package_name)
    # Match as a whole token (word boundary or path separator before/after)
    return re.compile(
        r"(?:^|[\s/\\@])" + escaped + r"(?:$|[\s/\\@])",
        re.IGNORECASE,
    )


# Pre-compile one pattern per unique package name
_PKG_PATTERNS: dict[str, re.Pattern[str]] = {
    pkg: _build_pkg_pattern(pkg) for pkg in _PACKAGE_TO_CVES
}


def _scan_token(token: str) -> list[CVEEntry]:
    """Return all CVEs whose affected packages appear in *token*."""
    matches: list[CVEEntry] = []
    seen_cves: set[str] = set()
    for pkg, pattern in _PKG_PATTERNS.items():
        if pattern.search(token):
            for cve in _PACKAGE_TO_CVES[pkg]:
                if cve.cve_id not in seen_cves:
                    matches.append(cve)
                    seen_cves.add(cve.cve_id)
    return matches


class KnownCVECheck(BaseCheck):
    """Check for use of packages with known MCP-related CVEs."""

    check_id = "CVE001"
    name = "Known CVE Check"
    description = (
        "Matches the server command and arguments against a database of known "
        "MCP-related CVEs to detect use of vulnerable packages."
    )

    async def run(self, server: MCPServerConfig) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []

        # Build the full command line as a single string for scanning, plus
        # check each token individually so multi-word names are matched correctly.
        tokens_to_scan: list[str] = []
        if server.command:
            tokens_to_scan.append(server.command)
        tokens_to_scan.extend(server.args)
        # Also scan the joined command line for patterns like "npx mcp-remote"
        full_cmdline = " ".join(filter(None, [server.command] + list(server.args)))
        tokens_to_scan.append(full_cmdline)

        seen_cves: set[str] = set()
        for token in tokens_to_scan:
            for cve in _scan_token(token):
                if cve.cve_id in seen_cves:
                    continue
                seen_cves.add(cve.cve_id)
                findings.append(
                    SecurityFinding(
                        check_id=self.check_id,
                        severity=cve.severity,
                        title=(
                            f"{cve.cve_id} (CVSS {cve.cvss:.1f}) — "
                            "vulnerable package detected"
                        ),
                        description=(
                            f"Server '{server.name}' references a package affected "
                            f"by {cve.cve_id} (CVSS {cve.cvss:.1f}). "
                            f"{cve.summary}"
                        ),
                        remediation=cve.remediation,
                    )
                )

        return findings
