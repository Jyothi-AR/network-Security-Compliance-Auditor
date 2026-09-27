"""
MikroTik RouterOS Remediation Provider.

Deterministic /ip service and firewall commands, safety checks, and rollback instructions.
"""

from __future__ import annotations

import re
from typing import Any

from .base import (
    BaseRemediationProvider,
    PreconditionCheck,
    RemediationDefinition,
)


class MikroTikRemediationProvider(BaseRemediationProvider):
    """Remediation provider for MikroTik RouterOS devices."""

    @property
    def vendor_name(self) -> str:
        return "mikrotik"

    @property
    def platform_name(self) -> str:
        return "routeros"

    @property
    def rules(self) -> dict[str, RemediationDefinition]:
        return {
            "MGMT-TELNET-001": RemediationDefinition(
                control_id="MGMT-TELNET-001",
                commands=[
                    "/ip service set telnet disabled=yes",
                ],
                rollback_commands=[
                    "/ip service set telnet disabled=no",
                ],
                risk_level="MEDIUM",
                description="Disable unencrypted RouterOS Telnet service daemon.",
                requires_change_window=True,
                preconditions=["ROUTEROS_SSH_ACTIVE"],
            ),
            "MGMT-SSH-001": RemediationDefinition(
                control_id="MGMT-SSH-001",
                commands=[
                    "/ip service set ssh port=22 disabled=no",
                    "/ip ssh set strong-crypto=yes",
                ],
                rollback_commands=[
                    "/ip ssh set strong-crypto=no",
                ],
                risk_level="LOW",
                description="Enforce strong cryptography on RouterOS SSH service.",
                requires_change_window=False,
            ),
            "MGMT-HTTP-001": RemediationDefinition(
                control_id="MGMT-HTTP-001",
                commands=[
                    "/ip service set www disabled=yes",
                    "/ip service set www-ssl disabled=no port=443",
                ],
                rollback_commands=[
                    "/ip service set www disabled=no",
                ],
                risk_level="LOW",
                description="Disable cleartext WebFig HTTP service and enforce HTTPS (www-ssl).",
                requires_change_window=False,
            ),
            "AUTH-LOGIN-001": RemediationDefinition(
                control_id="AUTH-LOGIN-001",
                commands=[
                    "/ip firewall filter add chain=input protocol=tcp dst-port=22 connection-state=new src-address-list=ssh_blacklist action=drop comment='drop ssh brute-force'",
                ],
                rollback_commands=[
                    "/ip firewall filter remove [find comment='drop ssh brute-force']",
                ],
                risk_level="SAFE",
                description="Add RouterOS firewall brute-force blacklist protection.",
                requires_change_window=False,
            ),
            "LOG-001": RemediationDefinition(
                control_id="LOG-001",
                commands=[
                    "/system logging action add name=remote-syslog target=remote remote=10.10.40.50",
                    "/system logging add topics=account,critical,error,warning action=remote-syslog",
                ],
                rollback_commands=[
                    "/system logging remove [find action=remote-syslog]",
                    "/system logging action remove [find name=remote-syslog]",
                ],
                risk_level="SAFE",
                description="Configure RouterOS remote system logging target.",
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
            has_ssh_winbox = bool(
                "set ssh" in cfg_lower
                or "winbox" in cfg_lower
                or "api-ssl" in cfg_lower
                or (baseline and baseline.get("management", {}).get("ssh", {}).get("enabled") is True)
            )
            checks.append(
                PreconditionCheck(
                    name="ROUTEROS_SSH_ACTIVE",
                    passed=has_ssh_winbox,
                    message=(
                        "RouterOS SSH or WinBox active. Safe to disable Telnet service."
                        if has_ssh_winbox
                        else "CRITICAL: Ensure SSH or WinBox is enabled before disabling Telnet."
                    ),
                    details={"ssh_winbox_active": has_ssh_winbox},
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
            return "set telnet disabled=yes" in cfg
        elif control_id == "MGMT-SSH-001":
            return "strong-crypto=yes" in cfg or "set ssh port=22" in cfg
        elif control_id == "MGMT-HTTP-001":
            return "set www disabled=yes" in cfg
        elif control_id == "AUTH-LOGIN-001":
            return "ssh_blacklist" in cfg
        elif control_id == "LOG-001":
            return "remote-syslog" in cfg
        return False

    def apply_to_config_text(
        self,
        original_config: str,
        commands: list[str],
        control_id: str,
    ) -> str:
        lines = original_config.splitlines()
        updated_lines: list[str] = []
        for line in lines:
            if control_id == "MGMT-TELNET-001" and "/ip service" in line and "telnet" in line and "disabled=no" in line:
                updated_lines.append(line.replace("disabled=no", "disabled=yes"))
                continue
            if control_id == "MGMT-HTTP-001" and "/ip service" in line and "www" in line and "disabled=no" in line:
                updated_lines.append(line.replace("disabled=no", "disabled=yes"))
                continue
            updated_lines.append(line)

        patch = "\n".join(commands)
        if patch not in "\n".join(updated_lines):
            updated_lines.append(f"\n# --- MikroTik Remediation: {control_id} ---\n{patch}")

        return "\n".join(updated_lines) + "\n"
