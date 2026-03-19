"""Tests for CredentialExposureCheck (CRED001)."""
from __future__ import annotations

import pytest

from mcpshield.checks.credential_check import CredentialExposureCheck
from mcpshield.models import MCPServerConfig, Severity, TransportType


@pytest.fixture()
def check() -> CredentialExposureCheck:
    return CredentialExposureCheck()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _server(
    name: str = "srv",
    command: str | None = "python",
    args: list[str] | None = None,
    env: dict[str, str] | None = None,
) -> MCPServerConfig:
    return MCPServerConfig(
        name=name,
        command=command,
        args=args or [],
        env=env or {},
    )


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


class TestMetadata:
    def test_check_id(self, check: CredentialExposureCheck):
        assert check.check_id == "CRED001"

    def test_name(self, check: CredentialExposureCheck):
        assert check.name == "Credential Exposure Check"


# ---------------------------------------------------------------------------
# Clean configuration — zero findings
# ---------------------------------------------------------------------------


class TestCleanConfig:
    async def test_no_env_no_args_clean(self, check: CredentialExposureCheck):
        srv = _server()
        findings = await check.run(srv)
        assert findings == []

    async def test_benign_env_values_clean(self, check: CredentialExposureCheck):
        srv = _server(env={"NODE_ENV": "production", "DEBUG": "false"})
        findings = await check.run(srv)
        assert findings == []

    async def test_placeholder_value_not_flagged(self, check: CredentialExposureCheck):
        """Placeholder values should NOT be flagged as real secrets."""
        srv = _server(env={"API_KEY": "YOUR_API_KEY"})
        findings = await check.run(srv)
        assert findings == []

    async def test_placeholder_angle_brackets_not_flagged(self, check: CredentialExposureCheck):
        srv = _server(env={"SECRET": "<YOUR_SECRET>"})
        findings = await check.run(srv)
        assert findings == []

    async def test_placeholder_curly_braces_not_flagged(self, check: CredentialExposureCheck):
        srv = _server(env={"TOKEN": "{REPLACE_ME}"})
        findings = await check.run(srv)
        assert findings == []

    async def test_benign_true_false_not_flagged(self, check: CredentialExposureCheck):
        srv = _server(env={"API_KEY": "true"})
        findings = await check.run(srv)
        assert findings == []

    async def test_short_value_not_flagged(self, check: CredentialExposureCheck):
        """Values under 4 characters are not real secrets."""
        srv = _server(env={"SECRET": "abc"})
        findings = await check.run(srv)
        assert findings == []


# ---------------------------------------------------------------------------
# Finding 1: Hardcoded secret in env var
# ---------------------------------------------------------------------------


class TestHardcodedEnvSecret:
    @pytest.mark.parametrize(
        "key,value",
        [
            ("API_KEY", "sk-1234567890abcdef"),
            ("SECRET", "my-very-secret-value"),
            ("TOKEN", "ghp_abcdefghijklmnop"),
            ("PASSWORD", "correct-horse-battery-staple"),
            ("DATABASE_PASSWORD", "super_secret_123"),
            ("CLIENT_SECRET", "oauth-client-secret-xyz"),
            ("JWT_SECRET", "jwt-signing-key-abc"),
            ("PRIVATE_KEY", "-----BEGIN RSA PRIVATE KEY-----"),
            ("ENCRYPTION_KEY", "aes256-key-value-here"),
        ],
    )
    async def test_sensitive_key_with_real_value_flagged(
        self, check: CredentialExposureCheck, key: str, value: str
    ):
        srv = _server(env={key: value})
        findings = await check.run(srv)
        env_findings = [f for f in findings if key in f.title]
        assert len(env_findings) >= 1
        assert env_findings[0].severity == Severity.HIGH
        assert env_findings[0].check_id == "CRED001"

    async def test_multiple_secrets_multiple_findings(self, check: CredentialExposureCheck):
        srv = _server(
            env={
                "DATABASE_PASSWORD": "super_secret_123",
                "API_KEY": "sk-1234567890abcdef",
            }
        )
        findings = await check.run(srv)
        env_findings = [f for f in findings if "Hardcoded secret in environment variable" in f.title]
        assert len(env_findings) == 2

    async def test_secret_value_is_redacted_in_description(
        self, check: CredentialExposureCheck
    ):
        """The full secret value must not appear in the finding description."""
        secret = "super_secret_password_12345"
        srv = _server(env={"PASSWORD": secret})
        findings = await check.run(srv)
        assert findings
        description = findings[0].description
        assert secret not in description
        # Redacted prefix (first 4 chars + ***)
        assert "supe***" in description

    async def test_non_sensitive_key_name_not_flagged(self, check: CredentialExposureCheck):
        srv = _server(env={"SOME_RANDOM_VAR": "some-value-that-looks-real"})
        findings = await check.run(srv)
        env_findings = [f for f in findings if "Hardcoded secret" in f.title]
        assert env_findings == []


# ---------------------------------------------------------------------------
# Finding 2a: --flag value style credential in args
# ---------------------------------------------------------------------------


class TestArgFlagCredential:
    async def test_password_flag_with_value(self, check: CredentialExposureCheck):
        srv = _server(args=["--password", "my-real-password"])
        findings = await check.run(srv)
        flag_findings = [f for f in findings if "command-line argument" in f.title]
        assert len(flag_findings) >= 1
        assert flag_findings[0].severity == Severity.HIGH

    async def test_token_flag_with_value(self, check: CredentialExposureCheck):
        srv = _server(args=["--token", "ghp_somerealtokenhere123"])
        findings = await check.run(srv)
        flag_findings = [f for f in findings if "command-line argument" in f.title]
        assert len(flag_findings) >= 1

    async def test_secret_flag_with_placeholder_not_flagged(self, check: CredentialExposureCheck):
        srv = _server(args=["--secret", "YOUR_SECRET"])
        findings = await check.run(srv)
        flag_findings = [f for f in findings if "command-line argument" in f.title]
        assert flag_findings == []

    async def test_password_flag_last_arg_no_crash(self, check: CredentialExposureCheck):
        """--password as the last argument (no following value) must not crash."""
        srv = _server(args=["--password"])
        findings = await check.run(srv)
        assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# Finding 2b: --flag=value inline credential in args
# ---------------------------------------------------------------------------


class TestArgInlineCredential:
    async def test_inline_password_flagged(self, check: CredentialExposureCheck):
        srv = _server(args=["--password=my-real-password"])
        findings = await check.run(srv)
        inline_findings = [f for f in findings if "embedded in command-line argument" in f.title]
        assert len(inline_findings) >= 1
        assert inline_findings[0].severity == Severity.HIGH

    async def test_inline_api_key_flagged(self, check: CredentialExposureCheck):
        srv = _server(args=["--api-key=sk-1234567890abcdef"])
        findings = await check.run(srv)
        inline_findings = [f for f in findings if "embedded in command-line argument" in f.title]
        assert len(inline_findings) >= 1

    async def test_inline_non_secret_flag_not_flagged(self, check: CredentialExposureCheck):
        srv = _server(args=["--output=json"])
        findings = await check.run(srv)
        inline_findings = [f for f in findings if "embedded in command-line argument" in f.title]
        assert inline_findings == []


# ---------------------------------------------------------------------------
# Finding 2c: token-like standalone value in args
# ---------------------------------------------------------------------------


class TestTokenLikeArg:
    async def test_jwt_in_args_flagged(self, check: CredentialExposureCheck):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        srv = _server(args=[jwt])
        findings = await check.run(srv)
        token_findings = [f for f in findings if "Token-like value" in f.title]
        assert len(token_findings) >= 1
        assert token_findings[0].severity == Severity.MEDIUM

    async def test_long_hex_string_flagged(self, check: CredentialExposureCheck):
        hex_val = "a" * 32  # 32 hex chars
        srv = _server(args=[hex_val])
        findings = await check.run(srv)
        token_findings = [f for f in findings if "Token-like value" in f.title]
        assert len(token_findings) >= 1

    async def test_short_arg_not_flagged(self, check: CredentialExposureCheck):
        srv = _server(args=["--verbose", "json"])
        findings = await check.run(srv)
        token_findings = [f for f in findings if "Token-like value" in f.title]
        assert token_findings == []


# ---------------------------------------------------------------------------
# Finding 3: Sensitive filesystem path in command
# ---------------------------------------------------------------------------


class TestSensitivePath:
    @pytest.mark.parametrize(
        "command",
        [
            "/home/user/.ssh/id_rsa",
            "/etc/shadow",
            "/etc/passwd",
            "/root/credentials.json",
            "/path/to/service_account.json",
            "/path/to/cert.pem",
            "/path/to/key.key",
        ],
    )
    async def test_sensitive_command_path_flagged(
        self, check: CredentialExposureCheck, command: str
    ):
        srv = _server(command=command)
        findings = await check.run(srv)
        path_findings = [f for f in findings if "sensitive filesystem path" in f.title]
        assert len(path_findings) >= 1
        assert path_findings[0].severity == Severity.HIGH

    async def test_normal_command_not_flagged(self, check: CredentialExposureCheck):
        srv = _server(command="/usr/local/bin/python3")
        findings = await check.run(srv)
        path_findings = [f for f in findings if "sensitive filesystem path" in f.title]
        assert path_findings == []

    async def test_none_command_not_flagged(self, check: CredentialExposureCheck):
        srv = _server(command=None)
        findings = await check.run(srv)
        path_findings = [f for f in findings if "sensitive filesystem path" in f.title]
        assert path_findings == []


# ---------------------------------------------------------------------------
# All findings have required fields
# ---------------------------------------------------------------------------


class TestFindingFields:
    async def test_all_findings_have_check_id(self, check: CredentialExposureCheck):
        srv = _server(
            command="/home/user/.ssh/id_rsa",
            env={"PASSWORD": "super_secret_pass"},
            args=["--token", "ghp_somerealtokenvalue"],
        )
        findings = await check.run(srv)
        for f in findings:
            assert f.check_id == "CRED001"
            assert f.remediation
            assert f.description
