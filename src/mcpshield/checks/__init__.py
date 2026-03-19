from __future__ import annotations

from mcpshield.checks.base import BaseCheck
from mcpshield.checks.registry import CheckRegistry

__all__ = ["BaseCheck", "CheckRegistry", "get_all_checks"]


def get_all_checks() -> list[BaseCheck]:
    return CheckRegistry().get_all_checks()
