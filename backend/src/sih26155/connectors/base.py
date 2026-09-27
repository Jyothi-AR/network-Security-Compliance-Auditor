"""
DeviceConnector Abstract Base and Read-Only Safety Interface.

Strict Security Guarantees:
- Hardcoded command allowlists per vendor.
- Immediate blocking of any state-changing, write, or destructive CLI token.
- Bounded connection timeouts to avoid hanging daemon threads.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
import re
from typing import Any

from sih26155.core.schema.normalized_device import NormalizedDeviceConfig


# Destructive or state-changing command patterns that MUST NEVER execute
FORBIDDEN_MUTATING_PATTERNS = [
    r"\bconfig\s+t\b",
    r"\bconfigure\s+terminal\b",
    r"\bset\b",
    r"\breload\b",
    r"\breboot\b",
    r"\bshutdown\b",
    r"\bdelete\b",
    r"\berase\b",
    r"\bformat\b",
    r"\bwrite\s+memory\b",
    r"\bcopy\s+run\b",
    r"\brm\b",
    r"\bdrop\b",
    r"\btruncate\b",
    r"\bkill\b",
    r"\buserdel\b",
    r"\bpasswd\b",
]


class DeviceConnectorError(Exception):
    """Base exception for connector failures."""
    pass


class ConnectorSecurityViolation(DeviceConnectorError):
    """Raised when a non-whitelisted or mutating command is attempted."""
    pass


class DeviceConnector(ABC):
    """
    Abstract interface for safe, read-only live device communication.
    """

    def __init__(
        self,
        host: str,
        username: str = "",
        password: str = "",
        port: int = 22,
        timeout: int = 15,
    ) -> None:
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.timeout = timeout

    @property
    @abstractmethod
    def vendor_name(self) -> str:
        """Name of vendor (e.g. Cisco, Fortinet, Palo Alto, MikroTik, Linux)."""
        pass

    @property
    @abstractmethod
    def allowed_commands(self) -> set[str]:
        """Hardcoded allowlist of permitted read-only CLI commands."""
        pass

    def validate_command(self, command: str) -> None:
        """
        Validates that a command is in the explicit allowlist and does not
        match any destructive/mutating patterns.
        """
        clean_cmd = command.strip().lower()

        # Check mutating blacklist
        for pat in FORBIDDEN_MUTATING_PATTERNS:
            if re.search(pat, clean_cmd, re.IGNORECASE):
                raise ConnectorSecurityViolation(
                    f"Command '{command}' contains forbidden mutating token matching pattern '{pat}'."
                )

        # Check explicit allowlist
        allowed_clean = {c.strip().lower() for c in self.allowed_commands}
        if clean_cmd not in allowed_clean:
            # Check prefix allowlist if base command starts with allowed prefix
            if not any(clean_cmd.startswith(a) for a in allowed_clean):
                raise ConnectorSecurityViolation(
                    f"Command '{command}' is not in the read-only allowlist for vendor {self.vendor_name}."
                )

    @abstractmethod
    def test_connection(self) -> bool:
        """Verifies reachability and authentication without pulling full configuration."""
        pass

    @abstractmethod
    def collect_configuration(self) -> str:
        """Pulls running configuration text using safe read-only commands."""
        pass

    @abstractmethod
    def normalize_configuration(self, raw_config: str) -> NormalizedDeviceConfig:
        """Parses collected raw configuration into canonical NormalizedDeviceConfig."""
        pass
