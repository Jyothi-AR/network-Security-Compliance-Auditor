"""
Safe Remediation Validation.

Validates proposed remediation commands for safety *before* they are
deployed to a live device. This extends the existing RemediationValidator
(structural checks) with semantic safety checks:

- Conflict detection: does this change contradict the current baseline?
- Side-effect analysis: could enabling feature X disable feature Y?
- Rollback feasibility: is an undo command available?
- Risk scoring: how risky is this remediation to apply?

No actual commands are executed — this is a static analysis pass only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class RemediationSafetyReport:
    """Result of safe-remediation validation for one remediation step."""
    control_id: str
    command: str
    is_safe: bool
    risk_level: str            # SAFE / LOW / MEDIUM / HIGH / BLOCKED
    warnings: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)
    side_effects: list[str] = field(default_factory=list)
    rollback_command: str = ""
    recommendation: str = ""


# ---------------------------------------------------------------------------
# Side-effect rules
# ---------------------------------------------------------------------------

@dataclass
class SideEffectRule:
    pattern: str          # regex matched against the command
    side_effect: str
    rollback_template: str


SIDE_EFFECT_RULES: list[SideEffectRule] = [
    SideEffectRule(
        pattern=r"ip ssh version 2",
        side_effect="Disables SSHv1 connections — any legacy SSHv1 clients will be disconnected.",
        rollback_template="ip ssh version 1",
    ),
    SideEffectRule(
        pattern=r"no\s+service\s+telnet|transport\s+input\s+ssh",
        side_effect="Disables Telnet management access — ensure SSH is working before applying.",
        rollback_template="transport input telnet ssh",
    ),
    SideEffectRule(
        pattern=r"service\s+password-encryption",
        side_effect="Encrypts existing plaintext passwords in running-config using type-7 (reversible).",
        rollback_template="no service password-encryption",
    ),
    SideEffectRule(
        pattern=r"snmp-server\s+version\s+3|snmp-server\s+group.*v3",
        side_effect="Adds SNMPv3 group; existing v1/v2c community strings remain until explicitly removed.",
        rollback_template="no snmp-server group <name> v3",
    ),
    SideEffectRule(
        pattern=r"logging\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        side_effect="Adds remote syslog server; may increase network traffic from device.",
        rollback_template="no logging <ip>",
    ),
    SideEffectRule(
        pattern=r"ntp\s+server",
        side_effect="Enables NTP synchronisation; clock will adjust which may briefly affect log timestamps.",
        rollback_template="no ntp server <ip>",
    ),
    SideEffectRule(
        pattern=r"ip\s+access-group|set\s+zone",
        side_effect="Applies ACL/zone policy — may block currently-allowed traffic if misconfigured.",
        rollback_template="no ip access-group <name> in|out",
    ),
]


# ---------------------------------------------------------------------------
# Conflict detection
# ---------------------------------------------------------------------------

CONFLICT_PAIRS: list[tuple[str, str, str]] = [
    # (pattern_A, pattern_B, conflict_description)
    (
        r"ip ssh version 2",
        r"transport input telnet",
        "Enabling SSHv2 while Telnet is still allowed may give false security impression.",
    ),
    (
        r"no\s+snmp-server",
        r"snmp-server\s+community",
        "Disabling SNMP globally conflicts with adding a community string.",
    ),
]


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------

class SafeRemediationValidator:
    """
    Validates a list of remediation commands for safety before deployment.

    Usage::

        validator = SafeRemediationValidator()
        reports = validator.validate_batch(
            remediations=[{"control_id": "SSH-001", "command": "ip ssh version 2"}],
            current_baseline={"ssh_version": 1, "telnet_enabled": True},
        )
    """

    # Patterns that are always BLOCKED regardless of context
    BLOCKED_PATTERNS: list[str] = [
        r"\breload\b",
        r"\breboot\b",
        r"\bwrite\s+erase\b",
        r"\berase\s+startup-config\b",
        r"\bformat\b",
        r"\bdelete\s+/force\b",
        r"\bshutdown\b",
        r"\bpoweroff\b",
    ]

    def validate_single(
        self,
        control_id: str,
        command: str,
        current_baseline: dict[str, Any] | None = None,
        all_commands: list[str] | None = None,
    ) -> RemediationSafetyReport:
        """
        Validate one remediation command.

        Args:
            control_id: The control this remediation addresses.
            command: The remediation CLI command.
            current_baseline: Current device state (semantic fields).
            all_commands: All other commands being applied together
                          (used for conflict detection).

        Returns:
            RemediationSafetyReport.
        """
        warnings: list[str] = []
        conflicts: list[str] = []
        side_effects: list[str] = []
        rollback_cmd = ""
        blocked = False

        # 1. Blocked command check
        for pattern in self.BLOCKED_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                return RemediationSafetyReport(
                    control_id=control_id,
                    command=command,
                    is_safe=False,
                    risk_level="BLOCKED",
                    warnings=[f"Command contains a dangerous pattern '{pattern}' and has been blocked."],
                    recommendation="Remove this command from the remediation plan.",
                )

        # 2. Side-effect analysis
        for rule in SIDE_EFFECT_RULES:
            if re.search(rule.pattern, command, re.IGNORECASE):
                side_effects.append(rule.side_effect)
                rollback_cmd = rollback_cmd or rule.rollback_template

        # 3. Conflict detection (against other commands being applied)
        if all_commands:
            for cmd_a_pat, cmd_b_pat, desc in CONFLICT_PAIRS:
                if re.search(cmd_a_pat, command, re.IGNORECASE):
                    for other_cmd in all_commands:
                        if other_cmd != command and re.search(cmd_b_pat, other_cmd, re.IGNORECASE):
                            conflicts.append(desc)

        # 4. Baseline conflict (does this command address an already-correct state?)
        if current_baseline:
            warnings.extend(self._check_baseline_conflicts(command, current_baseline))

        # 5. Determine risk level
        if conflicts:
            risk_level = "HIGH"
        elif len(side_effects) > 1:
            risk_level = "MEDIUM"
        elif side_effects:
            risk_level = "LOW"
        else:
            risk_level = "SAFE"

        is_safe = risk_level in ("SAFE", "LOW")

        recommendation = ""
        if not is_safe:
            recommendation = (
                "Test in a lab environment first. "
                "Apply during a maintenance window with rollback plan ready."
            )
            if rollback_cmd:
                recommendation += f" Rollback: `{rollback_cmd}`."

        return RemediationSafetyReport(
            control_id=control_id,
            command=command,
            is_safe=is_safe,
            risk_level=risk_level,
            warnings=warnings,
            conflicts=conflicts,
            side_effects=side_effects,
            rollback_command=rollback_cmd,
            recommendation=recommendation,
        )

    def validate_batch(
        self,
        remediations: list[dict[str, Any]],
        current_baseline: dict[str, Any] | None = None,
    ) -> list[RemediationSafetyReport]:
        """
        Validate a list of remediations together (enables cross-command conflict detection).

        Args:
            remediations: List of dicts with ``control_id`` and ``command`` keys.
            current_baseline: Current device state.

        Returns:
            List of RemediationSafetyReport, one per input remediation.
        """
        all_commands = [r.get("command", "") for r in remediations]
        return [
            self.validate_single(
                control_id=r.get("control_id", "UNKNOWN"),
                command=r.get("command", ""),
                current_baseline=current_baseline,
                all_commands=all_commands,
            )
            for r in remediations
        ]

    @staticmethod
    def _check_baseline_conflicts(command: str, baseline: dict[str, Any]) -> list[str]:
        warnings: list[str] = []

        if re.search(r"ip ssh version 2", command, re.IGNORECASE):
            if baseline.get("ssh_version") == 2:
                warnings.append("SSH version 2 is already configured — this command may be redundant.")

        if re.search(r"service\s+password-encryption", command, re.IGNORECASE):
            if baseline.get("password_encryption_enabled"):
                warnings.append("Password encryption is already enabled.")

        if re.search(r"logging\s+\d", command, re.IGNORECASE):
            if baseline.get("logging_enabled"):
                warnings.append("Logging is already enabled — verify the log server IP is correct.")

        return warnings
