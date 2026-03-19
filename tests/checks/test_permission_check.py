"""Tests for OverPermissionCheck (PERM001)."""
from __future__ import annotations

import pytest

from mcpshield.checks.permission_check import OverPermissionCheck
from mcpshield.models import MCPServerConfig, Severity, TransportType


@pytest.fixture()
def check() -> OverPermissionCheck:
    return OverPermissionCheck()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _server(
    name: str = "srv",
    env: dict[str, str] | None = None,
    command: str | None = "python",
) -> MCPServerConfig:
    return MCPServerConfig(name=name, command=command, env=env or {})


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


class TestMetadata:
    def test_check_id(self, check: OverPermissionCheck):
        assert check.check_id == "PERM001"

    def test_name(self, check: OverPermissionCheck):
        assert check.name == "Over-Permission Check"


# ---------------------------------------------------------------------------
# Clean configurations — zero findings
# ---------------------------------------------------------------------------


class TestCleanConfig:
    async def test_plain_name_no_findings(self, check: OverPermissionCheck):
        srv = _server(name="filesystem-server")
        findings = await check.run(srv)
        assert findings == []

    async def test_safe_env_no_findings(self, check: OverPermissionCheck):
        srv = _server(env={"NODE_ENV": "production", "LOG_LEVEL": "info"})
        findings = await check.run(srv)
        assert findings == []

    async def test_scope_with_narrow_value_no_findings(self, check: OverPermissionCheck):
        srv = _server(env={"SCOPE": "read:users"})
        findings = await check.run(srv)
        broad_findings = [f for f in findings if "Overly broad permission scope" in f.title]
        assert broad_findings == []


# ---------------------------------------------------------------------------
# Finding 1: Admin name (MEDIUM)
# ---------------------------------------------------------------------------


class TestAdminName:
    @pytest.mark.parametrize(
        "name",
        [
            "admin",
            "administrator",
            "root",
            "superuser",
            "super_user",
            "sysadmin",
            "sys_admin",
            "privileged",
            "master",
            "owner",
            "my-admin-server",
            "root-access-tool",
        ],
    )
    async def test_admin_name_flagged(self, check: OverPermissionCheck, name: str):
        srv = _server(name=name)
        findings = await check.run(srv)
        name_findings = [f for f in findings if "Server name suggests elevated privilege" in f.title]
        assert len(name_findings) == 1
        assert name_findings[0].severity == Severity.MEDIUM

    async def test_non_admin_name_not_flagged(self, check: OverPermissionCheck):
        for name in ["filesystem", "github-tools", "slack-integration", "database-reader"]:
            srv = _server(name=name)
            findings = await check.run(srv)
            name_findings = [f for f in findings if "Server name suggests elevated privilege" in f.title]
            assert name_findings == [], f"'{name}' should not trigger a finding"

    async def test_god_mode_name_flagged(self, check: OverPermissionCheck):
        srv = _server(name="godmode-server")
        findings = await check.run(srv)
        name_findings = [f for f in findings if "Server name suggests elevated privilege" in f.title]
        assert len(name_findings) == 1


# ---------------------------------------------------------------------------
# Finding 2: Privilege env var (HIGH)
# ---------------------------------------------------------------------------


class TestPrivilegeEnvVar:
    @pytest.mark.parametrize(
        "key,value",
        [
            ("ADMIN", "true"),
            ("ROOT", "1"),
            ("SUPERUSER", "yes"),
            ("SUDO", "enabled"),
            ("PRIVILEGED", "on"),
            ("ELEVATED", "allow"),
            ("ROOT_ACCESS", "enabled"),
            ("ADMIN_ACCESS", "true"),
            ("FULL_ACCESS", "grant"),
            ("UNRESTRICTED", "full"),
            ("BYPASS_AUTH", "true"),
            ("SKIP_AUTH", "yes"),
            ("DISABLE_AUTH", "on"),
            ("NO_AUTH", "true"),
            ("ALLOW_ALL", "1"),
            ("PERMIT_ALL", "true"),
            ("GLOBAL_ACCESS", "full"),
            ("MASTER_KEY", "allow"),
            ("OVERRIDE_PERMISSIONS", "true"),
            ("FORCE_ADMIN", "1"),
        ],
    )
    async def test_privilege_env_key_value_flagged(
        self, check: OverPermissionCheck, key: str, value: str
    ):
        srv = _server(env={key: value})
        findings = await check.run(srv)
        priv_findings = [f for f in findings if f"'{key}' grants elevated access" in f.title]
        assert len(priv_findings) == 1, f"Expected finding for {key}={value}"
        assert priv_findings[0].severity == Severity.HIGH

    async def test_privilege_key_with_false_value_not_flagged(
        self, check: OverPermissionCheck
    ):
        srv = _server(env={"ADMIN": "false"})
        findings = await check.run(srv)
        priv_findings = [f for f in findings if "grants elevated access" in f.title]
        assert priv_findings == []

    async def test_privilege_key_with_empty_value_not_flagged(
        self, check: OverPermissionCheck
    ):
        srv = _server(env={"ROOT_ACCESS": ""})
        findings = await check.run(srv)
        priv_findings = [f for f in findings if "grants elevated access" in f.title]
        assert priv_findings == []

    async def test_sample_dangerous_server_env_flagged(self, check: OverPermissionCheck):
        """Matches the 'dangerous-transport' server from the fixture."""
        srv = _server(
            name="dangerous-transport",
            env={"ADMIN": "true", "ROOT_ACCESS": "enabled"},
        )
        findings = await check.run(srv)
        priv_findings = [f for f in findings if "grants elevated access" in f.title]
        assert len(priv_findings) == 2


# ---------------------------------------------------------------------------
# Finding 3: Broad scope (MEDIUM)
# ---------------------------------------------------------------------------


class TestBroadScope:
    @pytest.mark.parametrize(
        "key,value",
        [
            ("SCOPE", "all"),
            ("PERMISSION", "full"),
            ("ROLE", "admin"),
            ("ACCESS_LEVEL", "unlimited"),
            ("GRANT", "everything"),
            ("CAPABILITY_SET", "all"),
        ],
    )
    async def test_broad_scope_flagged(
        self, check: OverPermissionCheck, key: str, value: str
    ):
        srv = _server(env={key: value})
        findings = await check.run(srv)
        scope_findings = [f for f in findings if "Overly broad permission scope" in f.title]
        assert len(scope_findings) == 1, f"Expected finding for {key}={value}"
        assert scope_findings[0].severity == Severity.MEDIUM

    async def test_scope_with_root_value_flagged(self, check: OverPermissionCheck):
        srv = _server(env={"SCOPE": "root"})
        findings = await check.run(srv)
        scope_findings = [f for f in findings if "Overly broad permission scope" in f.title]
        assert len(scope_findings) == 1

    async def test_narrow_scope_not_flagged(self, check: OverPermissionCheck):
        srv = _server(env={"SCOPE": "read:files"})
        findings = await check.run(srv)
        scope_findings = [f for f in findings if "Overly broad permission scope" in f.title]
        assert scope_findings == []

    async def test_privilege_key_not_double_reported_as_broad_scope(
        self, check: OverPermissionCheck
    ):
        """A key matched by both patterns should only appear in privilege findings."""
        # ADMIN is in _PRIVILEGE_ENV_KEY_PATTERN — broad-scope check must skip it
        srv = _server(env={"ADMIN": "all"})
        findings = await check.run(srv)
        scope_findings = [f for f in findings if "Overly broad permission scope" in f.title]
        assert scope_findings == []


# ---------------------------------------------------------------------------
# Combined findings
# ---------------------------------------------------------------------------


class TestCombined:
    async def test_admin_name_plus_env_multiple_findings(self, check: OverPermissionCheck):
        srv = _server(
            name="admin-server",
            env={"ROOT_ACCESS": "enabled", "SCOPE": "all"},
        )
        findings = await check.run(srv)
        assert len(findings) >= 3  # name + ROOT_ACCESS + SCOPE

    async def test_all_findings_have_check_id(self, check: OverPermissionCheck):
        srv = _server(
            name="admin",
            env={"ADMIN": "true", "SCOPE": "all"},
        )
        findings = await check.run(srv)
        for f in findings:
            assert f.check_id == "PERM001"

    async def test_all_findings_have_remediation(self, check: OverPermissionCheck):
        srv = _server(
            name="root-server",
            env={"BYPASS_AUTH": "true", "CAPABILITY": "*"},
        )
        findings = await check.run(srv)
        for f in findings:
            assert f.remediation
