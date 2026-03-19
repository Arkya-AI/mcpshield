from __future__ import annotations

import re

from mcpshield.checks.base import BaseCheck
from mcpshield.models import MCPServerConfig, SecurityFinding, Severity

# Server name patterns that suggest elevated privilege expectations
_ADMIN_NAME_PATTERN: re.Pattern[str] = re.compile(
    r"\b(admin|administrator|root|superuser|super_user|sysadmin|sys_admin|"
    r"privileged|god.?mode|master|owner)\b",
    re.IGNORECASE,
)

# Env-var *key* patterns that suggest elevated privileges are being granted
_PRIVILEGE_ENV_KEY_PATTERN: re.Pattern[str] = re.compile(
    r"^(ADMIN|ROOT|SUPERUSER|SUDO|PRIVILEGED|ELEVATED|"
    r"ROOT_ACCESS|ADMIN_ACCESS|FULL_ACCESS|UNRESTRICTED|"
    r"BYPASS_AUTH|SKIP_AUTH|DISABLE_AUTH|NO_AUTH|"
    r"ALLOW_ALL|PERMIT_ALL|GLOBAL_ACCESS|MASTER_KEY|"
    r"OVERRIDE_PERMISSIONS?|FORCE_ADMIN)",
    re.IGNORECASE,
)

# Env-var *value* patterns that explicitly enable elevated modes
_PRIVILEGE_ENV_VALUE_PATTERN: re.Pattern[str] = re.compile(
    r"^(true|1|yes|on|enabled|allow|grant|full|unrestricted)$",
    re.IGNORECASE,
)

# Tool-scope/permission env-var patterns that suggest overly broad access
_BROAD_SCOPE_PATTERN: re.Pattern[str] = re.compile(
    r"(SCOPE|PERMISSION|ROLE|ACCESS_LEVEL|GRANT|CAPABILITY|CAPABILITY_SET)",
    re.IGNORECASE,
)

_BROAD_SCOPE_VALUE_PATTERN: re.Pattern[str] = re.compile(
    r"\b(all|full|unlimited|everything|\*|admin|root|superuser|god)\b",
    re.IGNORECASE,
)


class OverPermissionCheck(BaseCheck):
    """Detect configurations that suggest overly broad or elevated permissions."""

    check_id = "PERM001"
    name = "Over-Permission Check"
    description = (
        "Identifies MCP server configurations that indicate admin/root-level "
        "access, elevated privilege environment variables, or overly broad "
        "permission scopes."
    )

    async def run(self, server: MCPServerConfig) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []

        # ------------------------------------------------------------------ #
        # 1. Server name suggests administrative or root-level access         #
        # ------------------------------------------------------------------ #
        if _ADMIN_NAME_PATTERN.search(server.name):
            findings.append(
                SecurityFinding(
                    check_id=self.check_id,
                    severity=Severity.MEDIUM,
                    title="Server name suggests elevated privilege",
                    description=(
                        f"Server '{server.name}' has a name that contains "
                        "admin/root/superuser terminology. This may indicate that "
                        "the server is configured with or expected to use elevated "
                        "system privileges, which violates the principle of least "
                        "privilege."
                    ),
                    remediation=(
                        "Review whether this server genuinely requires elevated "
                        "privileges. If so, scope its permissions to the minimum "
                        "required and consider renaming it to reflect its actual "
                        "function rather than its privilege level."
                    ),
                )
            )

        # ------------------------------------------------------------------ #
        # 2. Env vars that explicitly grant or assert elevated privileges      #
        # ------------------------------------------------------------------ #
        for key, value in server.env.items():
            if _PRIVILEGE_ENV_KEY_PATTERN.match(key) and _PRIVILEGE_ENV_VALUE_PATTERN.match(
                value
            ):
                findings.append(
                    SecurityFinding(
                        check_id=self.check_id,
                        severity=Severity.HIGH,
                        title=f"Environment variable '{key}' grants elevated access",
                        description=(
                            f"Server '{server.name}' sets '{key}={value}', which "
                            "explicitly enables an elevated or unrestricted access "
                            "mode. This may bypass normal permission checks and "
                            "expose the host system to over-privileged tool "
                            "execution."
                        ),
                        remediation=(
                            "Remove or restrict this environment variable. Audit "
                            "the server's source to understand what access "
                            f"'{key}={value}' actually enables and apply the "
                            "principle of least privilege."
                        ),
                    )
                )

        # ------------------------------------------------------------------ #
        # 3. Scope/permission env vars set to overly broad values             #
        # ------------------------------------------------------------------ #
        for key, value in server.env.items():
            if _BROAD_SCOPE_PATTERN.search(key) and _BROAD_SCOPE_VALUE_PATTERN.search(
                value
            ):
                # Avoid double-reporting keys already caught above
                if not _PRIVILEGE_ENV_KEY_PATTERN.match(key):
                    findings.append(
                        SecurityFinding(
                            check_id=self.check_id,
                            severity=Severity.MEDIUM,
                            title=f"Overly broad permission scope in '{key}'",
                            description=(
                                f"Server '{server.name}' sets '{key}={value}', "
                                "which suggests an unrestricted or all-encompassing "
                                "permission scope. Granting wide-open scopes "
                                "increases the blast radius of any security "
                                "incident involving this server."
                            ),
                            remediation=(
                                "Replace the broad scope with the minimum set of "
                                "specific permissions the server actually requires."
                            ),
                        )
                    )

        return findings
