"""
Linux / Host OS Remediation Provider.

Deterministic sshd_config, sysctl, and iptables rules with safety validations.
"""

from __future__ import annotations

import re
from typing import Any

from .base import (
    BaseRemediationProvider,
    PreconditionCheck,
    RemediationDefinition,
)


class LinuxRemediationProvider(BaseRemediationProvider):
    """Remediation provider for Linux / UNIX network endpoints and appliances."""

    @property
    def vendor_name(self) -> str:
        return "linux"

    @property
    def platform_name(self) -> str:
        return "linux"

    @property
    def rules(self) -> dict[str, RemediationDefinition]:
        return {
            "MGMT-TELNET-001": RemediationDefinition(
                control_id="MGMT-TELNET-001",
                commands=[
                    "systemctl stop telnet.socket telnetd",
                    "systemctl disable telnet.socket telnetd",
                ],
                rollback_commands=[
                    "systemctl enable telnet.socket",
                    "systemctl start telnet.socket",
                ],
                risk_level="MEDIUM",
                description="Disable Linux Telnet daemon socket service.",
                requires_change_window=True,
                preconditions=["SSHD_ACTIVE"],
            ),
            "MGMT-SSH-001": RemediationDefinition(
                control_id="MGMT-SSH-001",
                commands=[
                    "echo 'Protocol 2' >> /etc/ssh/sshd_config",
                    "echo 'PermitRootLogin no' >> /etc/ssh/sshd_config",
                    "echo 'ClientAliveInterval 300' >> /etc/ssh/sshd_config",
                    "systemctl reload sshd",
                ],
                rollback_commands=[
                    "sed -i '/ClientAliveInterval/d' /etc/ssh/sshd_config",
                    "systemctl reload sshd",
                ],
                risk_level="LOW",
                description="Enforce SSH Protocol 2 and disable direct root login in sshd_config.",
                requires_change_window=False,
            ),
            "MGMT-HTTP-001": RemediationDefinition(
                control_id="MGMT-HTTP-001",
                commands=[
                    "systemctl stop apache2 nginx 2>/dev/null || true",
                    "iptables -A INPUT -p tcp --dport 80 -j DROP",
                ],
                rollback_commands=[
                    "iptables -D INPUT -p tcp --dport 80 -j DROP",
                ],
                risk_level="LOW",
                description="Block cleartext HTTP port 80 traffic via iptables.",
                requires_change_window=False,
            ),
            "AUTH-LOGIN-001": RemediationDefinition(
                control_id="AUTH-LOGIN-001",
                commands=[
                    "echo 'auth required pam_faillock.so preauth silent audit deny=3 unlock_time=900' >> /etc/pam.d/password-auth",
                ],
                rollback_commands=[
                    "sed -i '/pam_faillock/d' /etc/pam.d/password-auth",
                ],
                risk_level="SAFE",
                description="Enable PAM faillock account lockout after 3 failed login attempts.",
                requires_change_window=False,
            ),
            "LOG-001": RemediationDefinition(
                control_id="LOG-001",
                commands=[
                    "echo '*.* @10.10.40.50:514' >> /etc/rsyslog.d/50-remote.conf",
                    "systemctl restart rsyslog",
                ],
                rollback_commands=[
                    "rm -f /etc/rsyslog.d/50-remote.conf",
                    "systemctl restart rsyslog",
                ],
                risk_level="SAFE",
                description="Forward Linux system logs to central rsyslog server.",
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
            has_sshd = bool(
                "sshd" in cfg_lower
                or "protocol 2" in cfg_lower
                or "permitrootlogin" in cfg_lower
                or (baseline and baseline.get("management", {}).get("ssh", {}).get("enabled") is True)
            )
            checks.append(
                PreconditionCheck(
                    name="SSHD_ACTIVE",
                    passed=has_sshd,
                    message=(
                        "OpenSSH daemon is active. Safe to stop and disable Telnet daemon."
                        if has_sshd
                        else "CRITICAL: Ensure OpenSSH service is active before disabling Telnet."
                    ),
                    details={"sshd_active": has_sshd},
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
            return "disable telnet" in cfg or "telnet" not in cfg
        elif control_id == "MGMT-SSH-001":
            return "protocol 2" in cfg or "permitrootlogin no" in cfg
        elif control_id == "MGMT-HTTP-001":
            return "dport 80 -j drop" in cfg
        elif control_id == "AUTH-LOGIN-001":
            return "pam_faillock" in cfg or "faillock" in cfg
        elif control_id == "LOG-001":
            return "rsyslog" in cfg or "@10.10" in cfg
        return False

    def apply_to_config_text(
        self,
        original_config: str,
        commands: list[str],
        control_id: str,
    ) -> str:
        patch = "\n".join(commands)
        return original_config.rstrip() + f"\n\n# --- Linux Remediation Commands: {control_id} ---\n" + patch + "\n"
