"""Tests for CheckRegistry."""
from __future__ import annotations

import pytest

from mcpshield.checks.auth_check import AuthenticationCheck
from mcpshield.checks.base import BaseCheck
from mcpshield.checks.config_hygiene_check import ConfigHygieneCheck
from mcpshield.checks.credential_check import CredentialExposureCheck
from mcpshield.checks.cve_check import KnownCVECheck
from mcpshield.checks.permission_check import OverPermissionCheck
from mcpshield.checks.registry import CheckRegistry
from mcpshield.checks.transport_check import TransportSecurityCheck
from mcpshield.models import MCPServerConfig, SecurityFinding


# ---------------------------------------------------------------------------
# Stub custom check
# ---------------------------------------------------------------------------


class _CustomCheck(BaseCheck):
    check_id = "CUSTOM001"
    name = "Custom Check"
    description = "A test-only custom check."

    async def run(self, server: MCPServerConfig) -> list[SecurityFinding]:
        return []


class _AnotherCustomCheck(BaseCheck):
    check_id = "CUSTOM002"
    name = "Another Custom Check"
    description = "Second test-only custom check."

    async def run(self, server: MCPServerConfig) -> list[SecurityFinding]:
        return []


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


class TestRegistryInit:
    def test_default_registry_has_six_checks(self):
        registry = CheckRegistry()
        assert len(registry) == 6

    def test_default_checks_include_all_builtin(self):
        registry = CheckRegistry()
        check_ids = {c.check_id for c in registry.get_all_checks()}
        assert "AUTH001" in check_ids
        assert "CRED001" in check_ids
        assert "PERM001" in check_ids
        assert "TRANS001" in check_ids
        assert "CVE001" in check_ids
        assert "HYGN001" in check_ids

    def test_checks_are_correct_types(self):
        registry = CheckRegistry()
        checks = registry.get_all_checks()
        types = {type(c) for c in checks}
        assert AuthenticationCheck in types
        assert CredentialExposureCheck in types
        assert OverPermissionCheck in types
        assert TransportSecurityCheck in types
        assert KnownCVECheck in types
        assert ConfigHygieneCheck in types

    def test_repr_contains_check_ids(self):
        registry = CheckRegistry()
        r = repr(registry)
        assert "AUTH001" in r
        assert "CheckRegistry" in r


# ---------------------------------------------------------------------------
# get_all_checks
# ---------------------------------------------------------------------------


class TestGetAllChecks:
    def test_returns_list(self):
        registry = CheckRegistry()
        result = registry.get_all_checks()
        assert isinstance(result, list)

    def test_returns_copy(self):
        """Mutating the returned list must not affect the registry."""
        registry = CheckRegistry()
        original_len = len(registry)
        result = registry.get_all_checks()
        result.clear()
        assert len(registry) == original_len

    def test_all_instances_are_base_check(self):
        registry = CheckRegistry()
        for check in registry.get_all_checks():
            assert isinstance(check, BaseCheck)


# ---------------------------------------------------------------------------
# get_check_by_id
# ---------------------------------------------------------------------------


class TestGetCheckById:
    def test_returns_correct_check(self):
        registry = CheckRegistry()
        check = registry.get_check_by_id("AUTH001")
        assert check is not None
        assert isinstance(check, AuthenticationCheck)

    def test_returns_none_for_unknown_id(self):
        registry = CheckRegistry()
        result = registry.get_check_by_id("NONEXISTENT")
        assert result is None

    def test_returns_none_for_empty_string(self):
        registry = CheckRegistry()
        result = registry.get_check_by_id("")
        assert result is None

    @pytest.mark.parametrize(
        "check_id",
        ["AUTH001", "CRED001", "PERM001", "TRANS001", "CVE001", "HYGN001"],
    )
    def test_all_builtin_ids_found(self, check_id: str):
        registry = CheckRegistry()
        check = registry.get_check_by_id(check_id)
        assert check is not None
        assert check.check_id == check_id


# ---------------------------------------------------------------------------
# get_checks_by_ids
# ---------------------------------------------------------------------------


class TestGetChecksByIds:
    def test_returns_subset(self):
        registry = CheckRegistry()
        result = registry.get_checks_by_ids(["AUTH001", "CVE001"])
        assert len(result) == 2
        ids = {c.check_id for c in result}
        assert ids == {"AUTH001", "CVE001"}

    def test_unknown_id_skipped(self):
        registry = CheckRegistry()
        result = registry.get_checks_by_ids(["AUTH001", "DOES_NOT_EXIST"])
        assert len(result) == 1
        assert result[0].check_id == "AUTH001"

    def test_empty_list_returns_empty(self):
        registry = CheckRegistry()
        result = registry.get_checks_by_ids([])
        assert result == []

    def test_all_ids_returns_all_checks(self):
        registry = CheckRegistry()
        all_ids = [c.check_id for c in registry.get_all_checks()]
        result = registry.get_checks_by_ids(all_ids)
        assert len(result) == len(all_ids)


# ---------------------------------------------------------------------------
# register
# ---------------------------------------------------------------------------


class TestRegister:
    def test_register_adds_check(self):
        registry = CheckRegistry()
        original_len = len(registry)
        registry.register(_CustomCheck())
        assert len(registry) == original_len + 1

    def test_registered_check_retrievable_by_id(self):
        registry = CheckRegistry()
        registry.register(_CustomCheck())
        check = registry.get_check_by_id("CUSTOM001")
        assert check is not None
        assert isinstance(check, _CustomCheck)

    def test_duplicate_id_raises_value_error(self):
        registry = CheckRegistry()
        registry.register(_CustomCheck())
        with pytest.raises(ValueError, match="CUSTOM001"):
            registry.register(_CustomCheck())

    def test_register_multiple_custom_checks(self):
        registry = CheckRegistry()
        registry.register(_CustomCheck())
        registry.register(_AnotherCustomCheck())
        assert len(registry) == 8  # 6 built-in + 2 custom

    def test_duplicate_builtin_id_raises(self):
        registry = CheckRegistry()
        with pytest.raises(ValueError, match="AUTH001"):
            registry.register(AuthenticationCheck())


# ---------------------------------------------------------------------------
# unregister
# ---------------------------------------------------------------------------


class TestUnregister:
    def test_unregister_removes_check(self):
        registry = CheckRegistry()
        original_len = len(registry)
        removed = registry.unregister("AUTH001")
        assert removed is True
        assert len(registry) == original_len - 1

    def test_unregister_check_no_longer_retrievable(self):
        registry = CheckRegistry()
        registry.unregister("AUTH001")
        assert registry.get_check_by_id("AUTH001") is None

    def test_unregister_unknown_id_returns_false(self):
        registry = CheckRegistry()
        result = registry.unregister("DOES_NOT_EXIST")
        assert result is False
        # Registry unchanged
        assert len(registry) == 6

    def test_register_then_unregister(self):
        registry = CheckRegistry()
        registry.register(_CustomCheck())
        assert registry.get_check_by_id("CUSTOM001") is not None
        registry.unregister("CUSTOM001")
        assert registry.get_check_by_id("CUSTOM001") is None

    def test_unregister_all_builtin_checks(self):
        registry = CheckRegistry()
        for cid in ["AUTH001", "CRED001", "PERM001", "TRANS001", "CVE001", "HYGN001"]:
            registry.unregister(cid)
        assert len(registry) == 0


# ---------------------------------------------------------------------------
# __len__
# ---------------------------------------------------------------------------


class TestLen:
    def test_default_length(self):
        registry = CheckRegistry()
        assert len(registry) == 6

    def test_length_after_register(self):
        registry = CheckRegistry()
        registry.register(_CustomCheck())
        assert len(registry) == 7

    def test_length_after_unregister(self):
        registry = CheckRegistry()
        registry.unregister("CVE001")
        assert len(registry) == 5
