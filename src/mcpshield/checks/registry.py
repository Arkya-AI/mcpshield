from __future__ import annotations

from mcpshield.checks.auth_check import AuthenticationCheck
from mcpshield.checks.base import BaseCheck
from mcpshield.checks.config_hygiene_check import ConfigHygieneCheck
from mcpshield.checks.credential_check import CredentialExposureCheck
from mcpshield.checks.cve_check import KnownCVECheck
from mcpshield.checks.permission_check import OverPermissionCheck
from mcpshield.checks.transport_check import TransportSecurityCheck


class CheckRegistry:
    """Central registry of all available MCP security checks.

    Usage::

        registry = CheckRegistry()
        checks = registry.get_all_checks()
        for check in checks:
            findings = await check.run(server)
    """

    def __init__(self) -> None:
        # Instantiate all checks once; callers receive the same instances.
        self._checks: list[BaseCheck] = [
            AuthenticationCheck(),
            CredentialExposureCheck(),
            OverPermissionCheck(),
            TransportSecurityCheck(),
            KnownCVECheck(),
            ConfigHygieneCheck(),
        ]

    # ---------------------------------------------------------------------- #
    # Public API                                                               #
    # ---------------------------------------------------------------------- #

    def get_all_checks(self) -> list[BaseCheck]:
        """Return all registered check instances."""
        return list(self._checks)

    def get_check_by_id(self, check_id: str) -> BaseCheck | None:
        """Return the check with the given check_id, or None if not found."""
        for check in self._checks:
            if check.check_id == check_id:
                return check
        return None

    def get_checks_by_ids(self, check_ids: list[str]) -> list[BaseCheck]:
        """Return only the checks whose IDs are in the provided list."""
        id_set = set(check_ids)
        return [c for c in self._checks if c.check_id in id_set]

    def register(self, check: BaseCheck) -> None:
        """Add a custom check instance to the registry.

        Raises ValueError if a check with the same check_id is already registered.
        """
        for existing in self._checks:
            if existing.check_id == check.check_id:
                raise ValueError(
                    f"A check with id '{check.check_id}' is already registered "
                    f"(existing: {existing.__class__.__name__}, "
                    f"new: {check.__class__.__name__})."
                )
        self._checks.append(check)

    def unregister(self, check_id: str) -> bool:
        """Remove the check with the given id. Returns True if removed, False if not found."""
        for i, check in enumerate(self._checks):
            if check.check_id == check_id:
                self._checks.pop(i)
                return True
        return False

    def __len__(self) -> int:
        return len(self._checks)

    def __repr__(self) -> str:
        ids = ", ".join(c.check_id for c in self._checks)
        return f"CheckRegistry([{ids}])"
