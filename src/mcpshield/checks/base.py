from __future__ import annotations

from abc import ABC, abstractmethod

from mcpshield.models import MCPServerConfig, SecurityFinding


class BaseCheck(ABC):
    """Abstract base class for all MCP security checks."""

    check_id: str
    name: str
    description: str

    @abstractmethod
    async def run(self, server: MCPServerConfig) -> list[SecurityFinding]:
        """Run the check against the given server configuration.

        Args:
            server: The MCP server configuration to analyse.

        Returns:
            A (possibly empty) list of SecurityFinding objects describing any
            issues discovered.
        """
