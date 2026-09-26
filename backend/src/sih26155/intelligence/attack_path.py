"""
Attack-Path Intelligence.

Analyses compliance findings across one or more devices and identifies
chains of weaknesses that an attacker could exploit to move laterally
or escalate privileges.

This is a rule-based engine (no LLM required). Attack paths are built
from a graph where nodes are devices and edges are exploitable
control-failures.  The module is designed to be extensible — new
attack-step rules can be added to ATTACK_STEP_RULES without touching
the graph traversal logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Attack-step rule registry
# ---------------------------------------------------------------------------

@dataclass
class AttackStepRule:
    """
    A single rule that maps a compliance control failure to an
    exploitable attack step.
    """
    step_id: str
    control_ids: list[str]       # Any of these failing triggers the step
    technique: str               # MITRE ATT&CK technique name / ID
    description: str
    severity: str                # CRITICAL / HIGH / MEDIUM / LOW
    lateral_movement: bool = False  # Can attacker reach other devices?
    privilege_escalation: bool = False


ATTACK_STEP_RULES: list[AttackStepRule] = [
    AttackStepRule(
        step_id="UNENCRYPTED_MGMT",
        control_ids=["SSH-001", "SSH-002", "ISO27001-A.8.20-001", "NIST-IA-003"],
        technique="T1040 – Network Sniffing",
        description="Management traffic is unencrypted. An attacker on the same segment can capture credentials.",
        severity="CRITICAL",
        lateral_movement=True,
    ),
    AttackStepRule(
        step_id="WEAK_AUTH",
        control_ids=["AUTH-001", "ISO27001-A.8.21-001", "NIST-IA-005"],
        technique="T1110 – Brute Force",
        description="Plaintext or weak passwords allow credential brute-forcing.",
        severity="HIGH",
        privilege_escalation=True,
    ),
    AttackStepRule(
        step_id="SNMP_COMMUNITY",
        control_ids=["SNMP-001", "ISO27001-A.5.14-001"],
        technique="T1040 – Network Sniffing / T1078 – Valid Accounts",
        description="SNMPv1/v2 community strings exposed; attacker can read/write device config.",
        severity="HIGH",
        lateral_movement=True,
    ),
    AttackStepRule(
        step_id="NO_LOGGING",
        control_ids=["LOG-001", "ISO27001-A.8.16-001"],
        technique="T1562.002 – Disable Windows Event Logging (analogous)",
        description="Logging is disabled. Attacker activity will not be recorded.",
        severity="MEDIUM",
    ),
    AttackStepRule(
        step_id="NO_ACL",
        control_ids=["ACL-001", "ISO27001-A.8.22-001"],
        technique="T1021 – Remote Services",
        description="No ACL/zone policy restricts access. Attacker can reach all services.",
        severity="HIGH",
        lateral_movement=True,
    ),
    AttackStepRule(
        step_id="NO_NTP",
        control_ids=["NTP-001", "ISO27001-A.8.16-002"],
        technique="T1070 – Indicator Removal (log tampering via time skew)",
        description="NTP not configured — log timestamps unreliable, enabling log-manipulation attacks.",
        severity="LOW",
    ),
]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class AttackStep:
    """One exploitable step in an attack path."""
    step_id: str
    device: str
    technique: str
    description: str
    severity: str
    triggering_controls: list[str]
    lateral_movement: bool
    privilege_escalation: bool


@dataclass
class AttackPath:
    """
    An ordered sequence of attack steps that form a coherent exploit chain.
    """
    path_id: str
    steps: list[AttackStep]
    risk_score: float           # 0-10
    summary: str


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class AttackPathEngine:
    """
    Identifies attack paths from compliance findings.

    Usage::

        engine = AttackPathEngine()
        paths = engine.analyse(
            device_findings={"router-1": findings_list}
        )
    """

    def analyse(
        self,
        device_findings: dict[str, list[Any]],
    ) -> list[AttackPath]:
        """
        Analyse findings across devices and return a list of attack paths.

        Args:
            device_findings: Mapping of device name → list of Finding objects
                             (must have ``.control_id`` and ``.status``).

        Returns:
            List of AttackPath objects ordered by descending risk_score.
        """
        all_paths: list[AttackPath] = []

        for device_name, findings in device_findings.items():
            failed_controls = {
                f.control_id
                for f in findings
                if getattr(f, "status", None) == "FAIL"
            }

            steps = self._match_steps(device_name, failed_controls)
            if steps:
                path = self._build_path(device_name, steps)
                all_paths.append(path)

        return sorted(all_paths, key=lambda p: p.risk_score, reverse=True)

    def _match_steps(
        self,
        device: str,
        failed_controls: set[str],
    ) -> list[AttackStep]:
        steps: list[AttackStep] = []
        for rule in ATTACK_STEP_RULES:
            matched = [c for c in rule.control_ids if c in failed_controls]
            if matched:
                steps.append(AttackStep(
                    step_id=rule.step_id,
                    device=device,
                    technique=rule.technique,
                    description=rule.description,
                    severity=rule.severity,
                    triggering_controls=matched,
                    lateral_movement=rule.lateral_movement,
                    privilege_escalation=rule.privilege_escalation,
                ))
        return steps

    def _build_path(self, device: str, steps: list[AttackStep]) -> AttackPath:
        severity_weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}
        raw_score = sum(severity_weights.get(s.severity, 0) for s in steps)
        risk_score = min(raw_score / len(steps) if steps else 0, 10.0)

        lateral = any(s.lateral_movement for s in steps)
        privesc = any(s.privilege_escalation for s in steps)

        parts = [f"{device}: {len(steps)} exploitable weaknesses"]
        if lateral:
            parts.append("lateral movement possible")
        if privesc:
            parts.append("privilege escalation possible")

        return AttackPath(
            path_id=f"PATH-{device}",
            steps=steps,
            risk_score=round(risk_score, 2),
            summary="; ".join(parts),
        )
