"""
Palo Alto Networks PAN-OS Remediation Provider.

Deterministic set CLI commands for PAN-OS management profiles, safe defaults,
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


class PaloAltoRemediationProvider(BaseRemediationProvider):
    """Remediation provider for Palo Alto Networks PAN-OS next-generation firewalls."""

    @property
    def vendor_name(self) -> str:
        return "palo_alto"

    @property
    def platform_name(self) -> str:
        return "panos"

    @property
    def rules(self) -> dict[str, RemediationDefinition]:
        return {
            "MGMT-TELNET-001": RemediationDefinition(
                control_id="MGMT-TELNET-001",
                commands=[
                    "set deviceconfig system service disable-telnet yes",
                ],
                rollback_commands=[
                    "set deviceconfig system service disable-telnet no",
                ],
                risk_level="MEDIUM",
                description="Disable unencrypted Telnet service on PAN-OS.",
                requires_change_window=True,
                preconditions=["PANOS_SSH_HTTPS_ACTIVE"],
            ),
            "MGMT-SSH-001": RemediationDefinition(
                control_id="MGMT-SSH-001",
                commands=[
                    "set deviceconfig system ssh ciphers aes256-gcm",
                    "set deviceconfig system ssh regen-keys",
                ],
                rollback_commands=[
                    "delete deviceconfig system ssh ciphers",
                ],
                risk_level="LOW",
                description="Harden SSH cryptographic ciphers on PAN-OS management profile.",
                requires_change_window=False,
            ),
            "MGMT-HTTP-001": RemediationDefinition(
                control_id="MGMT-HTTP-001",
                commands=[
                    "set deviceconfig system service disable-http yes",
                ],
                rollback_commands=[
                    "set deviceconfig system service disable-http no",
                ],
                risk_level="LOW",
                description="Disable cleartext HTTP administrative access on PAN-OS.",
                requires_change_window=False,
            ),
            "AUTH-LOGIN-001": RemediationDefinition(
                control_id="AUTH-LOGIN-001",
                commands=[
                    "set mgt-config users admin failed-attempts 3",
                    "set mgt-config users admin lockout-time 15",
                ],
                rollback_commands=[
                    "delete mgt-config users admin failed-attempts",
                ],
                risk_level="SAFE",
                description="Configure PAN-OS administrative login failed attempt lockouts.",
                requires_change_window=False,
            ),
            "LOG-001": RemediationDefinition(
                control_id="LOG-001",
                commands=[
                    "set shared log-settings syslog PAN-SYSLOG server 10.10.40.50 port 514 facility LOG_USER",
                ],
                rollback_commands=[
                    "delete shared log-settings syslog PAN-SYSLOG",
                ],
                risk_level="SAFE",
                description="Configure centralized PAN-OS syslog forwarding server profile.",
                requires_change_window=False,
            ),
            "SEC-ACL-001": RemediationDefinition(
                control_id="SEC-ACL-001",
                commands=[],
                rollback_commands=[],
                risk_level="MANUAL_ONLY",
                is_conservative=True,
                description="PAN-OS Security Rulebase & Application Inspection.",
                manual_guidance=(
                    "Manual Remediation Required: Security policy changes must be reviewed to prevent application outage. "
                    "CLI rulebase addition template:\n"
                    "  set rulebase security rules 'DENY-INBOUND-UNTRUST' from untrust to trust source any destination any application any service any action drop log-end yes"
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
            has_https = bool(
                "https" in cfg_lower
                or "service disable-http yes" in cfg_lower
                or "<ssl-tls-service-profile>" in cfg_lower
                or (baseline and baseline.get("management", {}).get("ssh", {}).get("enabled") is True)
            )
            checks.append(
                PreconditionCheck(
                    name="PANOS_SECURE_ACCESS",
                    passed=has_https,
                    message=(
                        "HTTPS WebUI / SSH service verified on PAN-OS. Safe to disable Telnet."
                        if has_https
                        else "CRITICAL: Ensure HTTPS management access is active before disabling Telnet."
                    ),
                    details={"https_active": has_https},
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
            return "disable-telnet yes" in cfg or "telnet" not in cfg
        elif control_id == "MGMT-SSH-001":
            return "ssh ciphers" in cfg or "ssh-ciphers" in cfg
        elif control_id == "MGMT-HTTP-001":
            return "disable-http yes" in cfg
        elif control_id == "AUTH-LOGIN-001":
            return "failed-attempts" in cfg
        elif control_id == "LOG-001":
            return "syslog" in cfg
        return False

    def apply_to_config_text(
        self,
        original_config: str,
        commands: list[str],
        control_id: str,
    ) -> str:
        patch = "\n".join(commands)
        if patch in original_config:
            return original_config
        return original_config.rstrip() + f"\n\n# --- PAN-OS Set Commands for {control_id} ---\n" + patch + "\n"
