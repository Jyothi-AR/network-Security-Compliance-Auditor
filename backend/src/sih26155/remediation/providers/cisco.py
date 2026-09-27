"""
Cisco IOS / IOS-XE Remediation Provider.

Deterministic remediation commands, precondition safety checks (e.g. lockout prevention),
unified config patching, and inverse rollback command templates.
"""

from __future__ import annotations

import re
from typing import Any

from .base import (
    BaseRemediationProvider,
    PreconditionCheck,
    RemediationDefinition,
)


class CiscoRemediationProvider(BaseRemediationProvider):
    """Remediation provider for Cisco IOS / IOS-XE network devices."""

    @property
    def vendor_name(self) -> str:
        return "cisco"

    @property
    def platform_name(self) -> str:
        return "ios"

    @property
    def rules(self) -> dict[str, RemediationDefinition]:
        return {
            "MGMT-TELNET-001": RemediationDefinition(
                control_id="MGMT-TELNET-001",
                commands=[
                    "line vty 0 4",
                    "transport input ssh",
                ],
                rollback_commands=[
                    "line vty 0 4",
                    "transport input telnet ssh",
                ],
                risk_level="MEDIUM",
                description="Disable insecure Telnet and restrict VTY management access to SSH.",
                requires_change_window=True,
                preconditions=["SSH_ENABLED_CHECK", "VTY_LINE_EXISTS"],
            ),
            "MGMT-SSH-001": RemediationDefinition(
                control_id="MGMT-SSH-001",
                commands=[
                    "ip ssh version 2",
                    "ip ssh time-out 60",
                    "ip ssh authentication-retries 3",
                ],
                rollback_commands=[
                    "ip ssh version 1",
                ],
                risk_level="LOW",
                description="Enforce SSH Version 2 with hardened timeout and retry thresholds.",
                requires_change_window=False,
                preconditions=["DOMAIN_NAME_CONFIGURED"],
            ),
            "MGMT-HTTP-001": RemediationDefinition(
                control_id="MGMT-HTTP-001",
                commands=[
                    "no ip http server",
                    "ip http secure-server",
                ],
                rollback_commands=[
                    "ip http server",
                    "no ip http secure-server",
                ],
                risk_level="LOW",
                description="Disable plaintext HTTP web management and enforce HTTPS.",
                requires_change_window=False,
            ),
            "AUTH-LOGIN-001": RemediationDefinition(
                control_id="AUTH-LOGIN-001",
                commands=[
                    "login block-for 120 attempts 3 within 60",
                ],
                rollback_commands=[
                    "no login block-for",
                ],
                risk_level="SAFE",
                description="Enable brute-force login protection and rate-limiting lockout.",
                requires_change_window=False,
            ),
            "LOG-001": RemediationDefinition(
                control_id="LOG-001",
                commands=[
                    "logging buffered 64000 informational",
                    "service timestamps log datetime msec",
                ],
                rollback_commands=[
                    "no logging buffered",
                ],
                risk_level="SAFE",
                description="Enable centralized buffered system logging with millisecond timestamps.",
                requires_change_window=False,
            ),
            # Conservative rule examples (ACL / NAT / Firewall)
            "SEC-ACL-001": RemediationDefinition(
                control_id="SEC-ACL-001",
                commands=[],
                rollback_commands=[],
                risk_level="MANUAL_ONLY",
                is_conservative=True,
                description="Inbound perimeter access-control filtering policy.",
                manual_guidance=(
                    "Manual Remediation Required: Dynamic routing or business services could be disrupted. "
                    "Apply the following verified baseline ACL during an approved change window:\n"
                    "  ip access-list extended HARDENED_INBOUND\n"
                    "   permit tcp any host <WAN_IP> eq 22\n"
                    "   permit tcp any host <WAN_IP> eq 443\n"
                    "   deny ip any any log"
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
            # 1. SSH Precondition check: Must verify SSH is enabled before killing Telnet to avoid lockout
            has_ssh = bool(
                re.search(r"ip\s+ssh\s+version", cfg_lower)
                or "transport input ssh" in cfg_lower
                or (baseline and baseline.get("management", {}).get("ssh", {}).get("enabled") is True)
                or (baseline and baseline.get("ssh_version", 0) >= 1)
            )
            checks.append(
                PreconditionCheck(
                    name="SSH_SERVICE_ACTIVE",
                    passed=has_ssh,
                    message=(
                        "SSH service detected and active. Safe to disable Telnet without management lockout."
                        if has_ssh
                        else "CRITICAL WARNING: No SSH configuration found. Disabling Telnet now will cause management lockout! Configure SSH first."
                    ),
                    details={"ssh_configured": has_ssh},
                )
            )

        elif control_id == "MGMT-SSH-001":
            # Domain name check: Cisco IOS requires an IP domain-name to generate RSA keys for SSH
            has_domain = bool(re.search(r"ip\s+domain[\s-]name\s+\S+", cfg_lower))
            checks.append(
                PreconditionCheck(
                    name="DOMAIN_NAME_DEFINED",
                    passed=has_domain,
                    message=(
                        "Device domain name is configured."
                        if has_domain
                        else "Notice: No 'ip domain name' line detected; key generation may require setting domain name first."
                    ),
                    details={"has_domain": has_domain},
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
            return "transport input ssh" in cfg and "transport input telnet" not in cfg
        elif control_id == "MGMT-SSH-001":
            return bool(re.search(r"ip\s+ssh\s+version\s+2", cfg))
        elif control_id == "MGMT-HTTP-001":
            return "no ip http server" in cfg
        elif control_id == "AUTH-LOGIN-001":
            return bool(re.search(r"login\s+block-for\s+\d+", cfg))
        elif control_id == "LOG-001":
            return bool(re.search(r"logging\s+buffered", cfg))
        return False

    def apply_to_config_text(
        self,
        original_config: str,
        commands: list[str],
        control_id: str,
    ) -> str:
        """Applies Cisco commands cleanly into running configuration."""
        lines = original_config.splitlines()
        updated_lines: list[str] = []

        if control_id == "MGMT-TELNET-001":
            # Replace transport input lines in line vty blocks
            in_vty = False
            vty_replaced = False
            for line in lines:
                stripped = line.strip()
                if stripped.startswith("line vty"):
                    in_vty = True
                    updated_lines.append(line)
                    continue
                elif in_vty and (stripped.startswith("line ") or stripped.startswith("interface ") or stripped == "!" or stripped == "end"):
                    if not vty_replaced:
                        updated_lines.append(" transport input ssh")
                        vty_replaced = True
                    in_vty = False
                    updated_lines.append(line)
                    continue
                elif in_vty and stripped.startswith("transport input"):
                    updated_lines.append(" transport input ssh")
                    vty_replaced = True
                    continue
                updated_lines.append(line)
            if not vty_replaced:
                updated_lines.extend(["line vty 0 4", " transport input ssh"])

        elif control_id == "MGMT-HTTP-001":
            # Remove 'ip http server' if present and add 'no ip http server'
            for line in lines:
                if line.strip() == "ip http server":
                    continue
                updated_lines.append(line)
            if "no ip http server" not in [l.strip() for l in updated_lines]:
                updated_lines.append("no ip http server")
                updated_lines.append("ip http secure-server")

        else:
            # General clean placement
            for line in lines:
                if line.strip() in commands:
                    continue
                updated_lines.append(line)
            # Insert before 'end' if present, otherwise append
            end_idx = len(updated_lines)
            for idx, l in enumerate(updated_lines):
                if l.strip() == "end":
                    end_idx = idx
                    break
            for c in reversed(commands):
                if c not in [l.strip() for l in updated_lines]:
                    updated_lines.insert(end_idx, c)

        return "\n".join(updated_lines) + "\n"
