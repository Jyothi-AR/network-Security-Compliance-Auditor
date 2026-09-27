"""
Base Remediation Provider Interface and Data Models.

Defines deterministic, vendor-specific remediation logic, precondition checks,
idempotency evaluation, diff generation, and safe rollback synthesis.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import difflib
import re
from typing import Any


@dataclass
class PreconditionCheck:
    name: str
    passed: bool
    message: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class RemediationDefinition:
    control_id: str
    commands: list[str]
    rollback_commands: list[str]
    risk_level: str  # SAFE | LOW | MEDIUM | HIGH | MANUAL_ONLY
    description: str
    is_conservative: bool = False
    manual_guidance: str = ""
    requires_change_window: bool = True
    preconditions: list[str] = field(default_factory=list)


@dataclass
class RemediationProposal:
    proposal_id: str
    control_id: str
    vendor: str
    platform: str
    title: str
    description: str
    commands: list[str]
    rollback_commands: list[str]
    risk_level: str
    is_idempotent: bool
    auto_applicable: bool
    preconditions: list[PreconditionCheck]
    unified_diff: str
    proposed_config: str
    manual_guidance: str = ""
    target_type: str = "upload"  # "upload" | "live_device"
    target_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "control_id": self.control_id,
            "vendor": self.vendor,
            "platform": self.platform,
            "title": self.title,
            "description": self.description,
            "commands": self.commands,
            "rollback_commands": self.rollback_commands,
            "risk_level": self.risk_level,
            "is_idempotent": self.is_idempotent,
            "auto_applicable": self.auto_applicable,
            "preconditions": [
                {
                    "name": p.name,
                    "passed": p.passed,
                    "message": p.message,
                    "details": p.details,
                }
                for p in self.preconditions
            ],
            "unified_diff": self.unified_diff,
            "proposed_config": self.proposed_config,
            "manual_guidance": self.manual_guidance,
            "target_type": self.target_type,
            "target_id": self.target_id,
        }


# Destructive patterns that MUST NEVER be allowed in any remediation command
FORBIDDEN_REMEDIATION_PATTERNS = [
    r"\breload\b",
    r"\breboot\b",
    r"\bwrite\s+erase\b",
    r"\berase\s+startup-config\b",
    r"\bformat\b",
    r"\bdelete\s+/force\b",
    r"\bdelete\s+/recursive\b",
    r"\bshutdown\b",
    r"\bpoweroff\b",
    r"\brm\s+-rf\b",
    r"\bdrop\s+database\b",
]


class BaseRemediationProvider(ABC):
    """
    Abstract Vendor Remediation Provider.

    Ensures that remediation commands are deterministic, validated,
    preconditioned against lockouts, and idempotent.
    """

    @property
    @abstractmethod
    def vendor_name(self) -> str:
        """Name of vendor (e.g. cisco, fortinet, paloalto, juniper, mikrotik, linux)."""
        pass

    @property
    @abstractmethod
    def platform_name(self) -> str:
        """Platform name (e.g. ios, junos, panos, fortios, routeros, linux)."""
        pass

    @property
    @abstractmethod
    def rules(self) -> dict[str, RemediationDefinition]:
        """Dictionary of supported control IDs mapped to remediation definitions."""
        pass

    def validate_command_safety(self, command: str) -> list[str]:
        """Validates that a command does not contain destructive keywords."""
        errors: list[str] = []
        for pat in FORBIDDEN_REMEDIATION_PATTERNS:
            if re.search(pat, command, re.IGNORECASE):
                errors.append(
                    f"Command '{command}' rejected: contains prohibited destructive pattern '{pat}'."
                )
        return errors

    @abstractmethod
    def check_preconditions(
        self,
        control_id: str,
        current_config: str,
        baseline: dict[str, Any] | None = None,
    ) -> list[PreconditionCheck]:
        """Check prerequisites (e.g. verify SSH before disabling Telnet)."""
        pass

    @abstractmethod
    def is_already_compliant(
        self,
        control_id: str,
        current_config: str,
        baseline: dict[str, Any] | None = None,
    ) -> bool:
        """Determines if the configuration already adheres to this control."""
        pass

    @abstractmethod
    def apply_to_config_text(
        self,
        original_config: str,
        commands: list[str],
        control_id: str,
    ) -> str:
        """Generates the updated configuration text by applying remediation cleanly."""
        pass

    def generate_unified_diff(
        self,
        original_config: str,
        updated_config: str,
        filename: str = "running-config",
    ) -> str:
        """Generates standard unified diff representation."""
        orig_lines = original_config.splitlines(keepends=True)
        updated_lines = updated_config.splitlines(keepends=True)
        diff = difflib.unified_diff(
            orig_lines,
            updated_lines,
            fromfile=f"a/{filename} (current)",
            tofile=f"b/{filename} (remediated)",
            n=3,
        )
        return "".join(diff)
