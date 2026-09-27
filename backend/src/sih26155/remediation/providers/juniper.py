"""
Juniper JunOS Remediation Provider.

Deterministic JunOS set/delete commands, lockout safety checks, config synthesis,
and rollback instructions.
"""

from __future__ import annotations

import re
from typing import Any

from .base import (
    BaseRemediationProvider,
    PreconditionCheck,
    RemediationDefinition,
)


class JuniperRemediationProvider(BaseRemediationProvider):
    """Remediation provider for Juniper JunOS devices."""

    @property
    def vendor_name(self) -> str:
        return "juniper"

    @property
    def platform_name(self) -> str:
        return "junos"

    @property
    def rules(self) -> dict[str, RemediationDefinition]:
        return {
            "MGMT-TELNET-001": RemediationDefinition(
                control_id="MGMT-TELNET-001",
                commands=[
                    "delete system services telnet",
                ],
                rollback_commands=[
                    "set system services telnet",
                ],
                risk_level="MEDIUM",
                description="Disable unencrypted Telnet service on JunOS.",
                requires_change_window=True,
                preconditions=["JUNOS_SSH_RUNNING"],
            ),
            "MGMT-SSH-001": RemediationDefinition(
                control_id="MGMT-SSH-001",
                commands=[
                    "set system services ssh protocol-version v2",
                ],
                rollback_commands=[
                    "delete system services ssh protocol-version",
                ],
                risk_level="LOW",
                description="Enforce SSH protocol version 2 on JunOS system services.",
                requires_change_window=False,
            ),
            "MGMT-HTTP-001": RemediationDefinition(
                control_id="MGMT-HTTP-001",
                commands=[
                    "delete system services web-management http",
                    "set system services web-management https system-generated-certificate",
                ],
                rollback_commands=[
                    "set system services web-management http",
                ],
                risk_level="LOW",
                description="Disable cleartext HTTP web management and activate HTTPS with SSL certificate.",
                requires_change_window=False,
            ),
            "AUTH-LOGIN-001": RemediationDefinition(
                control_id="AUTH-LOGIN-001",
                commands=[
                    "set system login retry-options tries-before-lockout 3 backoff-threshold 1 backoff-factor 5 lockout-period 15",
                ],
                rollback_commands=[
                    "delete system login retry-options",
                ],
                risk_level="SAFE",
                description="Configure JunOS login retry lockout protection.",
                requires_change_window=False,
            ),
            "LOG-001": RemediationDefinition(
                control_id="LOG-001",
                commands=[
                    "set system syslog host 10.10.40.50 any notice",
                ],
                rollback_commands=[
                    "delete system syslog host 10.10.40.50",
                ],
                risk_level="SAFE",
                description="Enable remote syslog notice logging on JunOS.",
                requires_change_window=False,
            ),
        }

    def check_preconditions(
        self,
        control_id: str,
        current_config: str,
        baseline: dict[str, Any] | None = None,
    ) -> list[PreconditionCheck]:
        checks: list[PreconditionCheck] = []
        cfg_lower = current_config.lower()

        if control_id == "MGMT-TELNET-001":
            has_ssh = bool(
                "system services ssh" in cfg_lower
                or "set system services ssh" in cfg_lower
                or (baseline and baseline.get("management", {}).get("ssh", {}).get("enabled") is True)
            )
            checks.append(
                PreconditionCheck(
                    name="JUNOS_SSH_ACTIVE",
                    passed=has_ssh,
                    message=(
                        "JunOS SSH subsystem is configured. Safe to disable Telnet."
                        if has_ssh
                        else "CRITICAL WARNING: JunOS SSH is not enabled. Disabling Telnet will lock you out!"
                    ),
                    details={"ssh_configured": has_ssh},
                )
            )

        return checks

    def is_already_compliant(
        self,
        control_id: str,
        current_config: str,
        baseline: dict[str, Any] | None = None,
    ) -> bool:
        cfg = current_config.lower()
        if control_id == "MGMT-TELNET-001":
            return "system services telnet" not in cfg or "delete system services telnet" in cfg
        elif control_id == "MGMT-SSH-001":
            return "protocol-version v2" in cfg
        elif control_id == "MGMT-HTTP-001":
            return "web-management http" not in cfg
        elif control_id == "AUTH-LOGIN-001":
            return "retry-options" in cfg
        elif control_id == "LOG-001":
            return "syslog host" in cfg
        return False

    def apply_to_config_text(
        self,
        original_config: str,
        commands: list[str],
        control_id: str,
    ) -> str:
        lines = original_config.splitlines()
        updated_lines: list[str] = []

        # If it's set commands format:
        if original_config.strip().startswith("set "):
            for line in lines:
                if control_id == "MGMT-TELNET-001" and "set system services telnet" in line:
                    continue
                if control_id == "MGMT-HTTP-001" and "set system services web-management http" in line and "https" not in line:
                    continue
                updated_lines.append(line)
            for cmd in commands:
                if not cmd.startswith("delete") and cmd not in updated_lines:
                    updated_lines.append(cmd)
            return "\n".join(updated_lines) + "\n"

        # Hierarchical XML/brace JunOS format
        patch = "\n".join(commands)
        return original_config.rstrip() + f"\n\n/* --- Remediation Commands for {control_id} --- */\n" + patch + "\n"
