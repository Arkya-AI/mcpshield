from __future__ import annotations

import re

from mcpshield.checks.base import BaseCheck
from mcpshield.models import MCPServerConfig, SecurityFinding, Severity

# ---------------------------------------------------------------------------
# Patterns for suspicious env-var *key* names
# ---------------------------------------------------------------------------
_SENSITIVE_KEY_PATTERN: re.Pattern[str] = re.compile(
    r"(SECRET|API_KEY|APIKEY|TOKEN|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_KEY|"
    r"ACCESS_KEY|AUTH_KEY|CLIENT_SECRET|APP_SECRET|DB_PASS|DATABASE_PASS|"
    r"OAUTH_SECRET|JWT_SECRET|ENCRYPTION_KEY|SIGNING_KEY|WEBHOOK_SECRET)",
    re.IGNORECASE,
)

# Values that look like placeholders — these are *not* real credentials
_PLACEHOLDER_PATTERN: re.Pattern[str] = re.compile(
    r"^(YOUR_.*|CHANGE.?ME|REPLACE.?ME|<.*>|\{.*\}|EXAMPLE|PLACEHOLDER|"
    r"TODO|FIXME|REDACTED|N/A|NONE|NULL|EMPTY|\.\.\.)$",
    re.IGNORECASE,
)

# Values that are clearly non-secrets (empty, boolean-like, numeric-only)
_BENIGN_VALUE_PATTERN: re.Pattern[str] = re.compile(
    r"^(true|false|yes|no|0|1|enabled|disabled|on|off)$",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Patterns for token-like values inside *args*
# ---------------------------------------------------------------------------
# Matches common token shapes: long hex strings, base64 blobs, JWT-like strings
_TOKEN_LIKE_VALUE: re.Pattern[str] = re.compile(
    r"(?:"
    # JWT  (header.payload.signature, each ≥8 chars base64url)
    r"ey[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
    r"|"
    # Long hex string (32+ hex chars — MD5/SHA1/SHA256 sized)
    r"[0-9a-fA-F]{32,}"
    r"|"
    # Generic long base64 blob (≥40 chars, may include +/=)
    r"[A-Za-z0-9+/]{40,}={0,2}"
    r")"
)

# Flag args that follow --password / --token / --secret / --key style flags
_SECRET_ARG_FLAG: re.Pattern[str] = re.compile(
    r"^-{1,2}(password|passwd|secret|token|api.?key|auth|credential|private.?key)$",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Sensitive filesystem path fragments in the command itself
# ---------------------------------------------------------------------------
_SENSITIVE_PATH_PATTERN: re.Pattern[str] = re.compile(
    r"(/etc/shadow|/etc/passwd|/etc/sudoers|/root/|/home/\w+/\.ssh|"
    r"\.pem$|\.key$|\.p12$|\.pfx$|\.jks$|id_rsa|id_ed25519|"
    r"credentials\.json|service.?account\.json|\.aws/credentials|"
    r"\.netrc)",
    re.IGNORECASE,
)


def _value_looks_like_real_secret(value: str) -> bool:
    """Return True when a value is non-empty, non-placeholder, and non-benign."""
    if not value or not value.strip():
        return False
    if _PLACEHOLDER_PATTERN.match(value.strip()):
        return False
    if _BENIGN_VALUE_PATTERN.match(value.strip()):
        return False
    # Must be at least 4 characters to be meaningful
    return len(value.strip()) >= 4


class CredentialExposureCheck(BaseCheck):
    """Detect hardcoded secrets and credential exposure in MCP server configs."""

    check_id = "CRED001"
    name = "Credential Exposure Check"
    description = (
        "Scans environment variables, command arguments, and command paths for "
        "hardcoded secrets, API keys, tokens, and passwords."
    )

    async def run(self, server: MCPServerConfig) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []

        # ------------------------------------------------------------------ #
        # 1. Env vars with sensitive key names and real-looking values        #
        # ------------------------------------------------------------------ #
        for key, value in server.env.items():
            if _SENSITIVE_KEY_PATTERN.search(key) and _value_looks_like_real_secret(
                value
            ):
                # Redact the value in the description — we never want to log it
                redacted = value[:4] + "***" if len(value) > 4 else "***"
                findings.append(
                    SecurityFinding(
                        check_id=self.check_id,
                        severity=Severity.HIGH,
                        title=f"Hardcoded secret in environment variable '{key}'",
                        description=(
                            f"Server '{server.name}' sets environment variable "
                            f"'{key}' to a value that appears to be a real secret "
                            f"(value starts with '{redacted}'). Storing credentials "
                            "directly in config files risks accidental exposure "
                            "through version control, logs, or process listings."
                        ),
                        remediation=(
                            "Remove the hardcoded value and reference it from a "
                            "secrets manager, a dedicated .env file excluded from "
                            "version control, or an OS-level secret store "
                            "(e.g., macOS Keychain, AWS Secrets Manager)."
                        ),
                    )
                )

        # ------------------------------------------------------------------ #
        # 2. Args that look like tokens or follow --secret=<value> patterns   #
        # ------------------------------------------------------------------ #
        args = server.args
        for idx, arg in enumerate(args):
            # Check for --secret <next_arg> style
            if _SECRET_ARG_FLAG.match(arg):
                next_val = args[idx + 1] if idx + 1 < len(args) else None
                if next_val and _value_looks_like_real_secret(next_val):
                    findings.append(
                        SecurityFinding(
                            check_id=self.check_id,
                            severity=Severity.HIGH,
                            title="Credential passed as command-line argument",
                            description=(
                                f"Server '{server.name}' passes a credential via "
                                f"the command-line flag '{arg}'. Command-line "
                                "arguments are visible to all users on the host "
                                "through process listings (e.g., 'ps aux')."
                            ),
                            remediation=(
                                "Pass credentials via environment variables or "
                                "a secrets file rather than command-line arguments."
                            ),
                        )
                    )

            # Check for --secret=value inline style
            if "=" in arg:
                flag, _, value = arg.partition("=")
                if _SECRET_ARG_FLAG.match(flag) and _value_looks_like_real_secret(
                    value
                ):
                    findings.append(
                        SecurityFinding(
                            check_id=self.check_id,
                            severity=Severity.HIGH,
                            title="Credential embedded in command-line argument",
                            description=(
                                f"Server '{server.name}' embeds a credential "
                                f"directly in the argument '{flag}=...'. "
                                "Command-line arguments are visible to all users "
                                "on the host through process listings."
                            ),
                            remediation=(
                                "Pass credentials via environment variables or a "
                                "secrets file rather than command-line arguments."
                            ),
                        )
                    )

            # Check for standalone token-shaped values in args
            if _TOKEN_LIKE_VALUE.fullmatch(arg):
                findings.append(
                    SecurityFinding(
                        check_id=self.check_id,
                        severity=Severity.MEDIUM,
                        title="Token-like value found in command arguments",
                        description=(
                            f"Server '{server.name}' includes an argument that "
                            "matches the pattern of a JWT, long hex string, or "
                            "base64 encoded token. If this is a real credential "
                            "it should not appear in the argument list."
                        ),
                        remediation=(
                            "Confirm whether this argument is a credential. If so, "
                            "move it to an environment variable or a secrets file."
                        ),
                    )
                )

        # ------------------------------------------------------------------ #
        # 3. Sensitive filesystem paths in the command                        #
        # ------------------------------------------------------------------ #
        command = server.command or ""
        match = _SENSITIVE_PATH_PATTERN.search(command)
        if match:
            findings.append(
                SecurityFinding(
                    check_id=self.check_id,
                    severity=Severity.HIGH,
                    title="Command references a sensitive filesystem path",
                    description=(
                        f"Server '{server.name}' has a command path that "
                        f"references '{match.group()}', which is associated with "
                        "private keys, certificates, or credential stores. "
                        "Running MCP servers directly against such files is "
                        "a significant credential-exposure risk."
                    ),
                    remediation=(
                        "Ensure the server does not directly expose private key "
                        "or credential files. Review whether the command is "
                        "appropriate for an MCP server entry."
                    ),
                )
            )

        return findings
