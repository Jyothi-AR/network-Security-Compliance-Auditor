"""
Fortinet FortiOS Remediation Provider.

Deterministic FortiOS CLI commands, lockout prevention, configuration patching,
and inverse rollback templates.
"""

from __future__ import annotations

import re
from typing import Any

from .base import (
    BaseRemediationProvider,
    PreconditionCheck,
    RemediationDefinition,
)


class FortinetRemediationProvider(BaseRemediationProvider):
    """Remediation provider for Fortinet FortiGate / FortiOS."""

    @property
    def vendor_name(self) -> str:
        return "fortinet"

    @property
    def platform_name(self) -> str:
        return "fortios"

    @property
    def rules(self) -> dict[str, RemediationDefinition]:
        return {
            "MGMT-TELNET-001": RemediationDefinition(
                control_id="MGMT-TELNET-001",
                commands=[
                    "config system global",
                    "    set admin-telnet disable",
                    "end",
                ],
                rollback_commands=[
                    "config system global",
                    "    set admin-telnet enable",
                    "end",
                ],
                risk_level="MEDIUM",
                description="Disable administrative Telnet daemon on FortiOS.",
                requires_change_window=True,
                preconditions=["SSH_OR_HTTPS_ACTIVE"],
            ),
            "MGMT-SSH-001": RemediationDefinition(
                control_id="MGMT-SSH-001",
                commands=[
                    "config system global",
                    "    set admin-ssh-port 22",
                    "    set admin-ssh-v1 disable",
                    "end",
                ],
                rollback_commands=[
                    "config system global",
                    "    set admin-ssh-v1 enable",
                    "end",
                ],
                risk_level="LOW",
                description="Enforce SSH protocol v2 only on FortiOS administrative interface.",
                requires_change_window=False,
            ),
            "MGMT-HTTP-001": RemediationDefinition(
                control_id="MGMT-HTTP-001",
                commands=[
                    "config system global",
                    "    set admin-sport 443",
                    "    set admin-http-redirect enable",
                    "end",
                ],
                rollback_commands=[
                    "config system global",
                    "    set admin-http-redirect disable",
                    "end",
                ],
                risk_level="LOW",
                description="Enforce HTTPS administration and redirect cleartext HTTP requests.",
                requires_change_window=False,
            ),
            "AUTH-LOGIN-001": RemediationDefinition(
                control_id="AUTH-LOGIN-001",
                commands=[
                    "config system global",
                    "    set admin-lockout-threshold 3",
                    "    set admin-lockout-duration 300",
                    "end",
                ],
                rollback_commands=[
                    "config system global",
                    "    set admin-lockout-threshold 0",
                    "end",
                ],
                risk_level="SAFE",
                description="Set FortiOS admin brute-force lockout threshold to 3 attempts.",
                requires_change_window=False,
            ),
            "LOG-001": RemediationDefinition(
                control_id="LOG-001",
                commands=[
                    "config log syslogd setting",
                    "    set status enable",
                    "    set server 10.10.40.50",
                    "end",
                ],
                rollback_commands=[
                    "config log syslogd setting",
                    "    set status disable",
                    "end",
                ],
                risk_level="SAFE",
                description="Enable remote syslog forwarding on FortiOS.",
                requires_change_window=False,
            ),
            "SEC-ACL-001": RemediationDefinition(
                control_id="SEC-ACL-001",
                commands=[],
                rollback_commands=[],
                risk_level="MANUAL_ONLY",
                is_conservative=True,
                description="FortiOS Firewall Policy Zone enforcement.",
                manual_guidance=(
                    "Manual Remediation Required: Modifying firewall policies directly can block business traffic. "
                    "Review active sessions before applying in GUI or CLI:\n"
                    "  config firewall policy\n"
                    "      edit 0\n"
                    "          set name 'Deny-All-Untrusted'\n"
                    "          set srcintf 'port1'\n"
                    "          set dstintf 'port2'\n"
                    "          set action deny\n"
                    "          set schedule 'always'\n"
                    "          set service 'ALL'\n"
                    "      next\n"
                    "  end"
                ),
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
            has_ssh_or_https = bool(
                "admin-ssh-port" in cfg_lower
                or "admin-sport" in cfg_lower
                or "allowaccess ping https ssh" in cfg_lower
                or (baseline and baseline.get("management", {}).get("ssh", {}).get("enabled") is True)
            )
            checks.append(
                PreconditionCheck(
                    name="FORTINET_SECURE_MGMT_ACTIVE",
                    passed=has_ssh_or_https,
                    message=(
                        "HTTPS or SSH management interface is active. Safe to disable administrative Telnet."
                        if has_ssh_or_https
                        else "CRITICAL WARNING: No SSH or HTTPS management interface found on FortiGate."
                    ),
                    details={"secure_mgmt_active": has_ssh_or_https},
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
            return "set admin-telnet disable" in cfg or "admin-telnet" not in cfg
        elif control_id == "MGMT-SSH-001":
            return "set admin-ssh-v1 disable" in cfg or "admin-ssh-port 22" in cfg
        elif control_id == "MGMT-HTTP-001":
            return "set admin-sport 443" in cfg or "set admin-http-redirect enable" in cfg
        elif control_id == "AUTH-LOGIN-001":
            return "set admin-lockout-threshold" in cfg
        elif control_id == "LOG-001":
            return "config log syslogd setting" in cfg
        return False

    def apply_to_config_text(
        self,
        original_config: str,
        commands: list[str],
        control_id: str,
    ) -> str:
        clean_patch = "\n".join(commands)
        if clean_patch in original_config:
            return original_config
        return original_config.rstrip() + f"\n\n# --- Remediation Patch: {control_id} ---\n" + clean_patch + "\n"
