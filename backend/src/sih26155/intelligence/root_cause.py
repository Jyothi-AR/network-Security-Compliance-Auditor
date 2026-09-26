"""
AI Root-Cause Analysis.

Correlates compliance findings with known configuration anti-patterns
to identify the *root cause* of a security failure rather than just
reporting the symptom.

Rule-based (no LLM): each root-cause rule maps a set of co-occurring
control failures to a probable root cause with a corrective action.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class RootCauseRule:
    """Maps a combination of failing controls to a root cause."""
    rule_id: str
    trigger_controls: list[str]   # ALL of these must be failing
    root_cause: str
    corrective_action: str
    category: str


ROOT_CAUSE_RULES: list[RootCauseRule] = [
    RootCauseRule(
        rule_id="RCA-001",
        trigger_controls=["SSH-001", "SSH-002"],
        root_cause="SSH is not configured or version 1 is in use.",
        corrective_action="Enable SSH version 2 and disable Telnet. On Cisco: `ip ssh version 2` + `no service telnet`.",
        category="Encrypted Management",
    ),
    RootCauseRule(
        rule_id="RCA-002",
        trigger_controls=["AUTH-001", "AUTH-002"],
        root_cause="Password security policy not enforced — plaintext credentials stored or no AAA.",
        corrective_action="Enable `service password-encryption` and configure AAA via RADIUS/TACACS+.",
        category="Authentication",
    ),
    RootCauseRule(
        rule_id="RCA-003",
        trigger_controls=["SNMP-001"],
        root_cause="Legacy SNMP (v1/v2c) in use with community strings.",
        corrective_action="Migrate to SNMPv3 with authentication (SHA) and privacy (AES).",
        category="Management Protocol Security",
    ),
    RootCauseRule(
        rule_id="RCA-004",
        trigger_controls=["LOG-001", "NTP-001"],
        root_cause="Logging infrastructure incomplete — no centralized log server or unreliable timestamps.",
        corrective_action="Configure `logging host <syslog-server>` and `ntp server <ntp-server>`.",
        category="Audit Logging",
    ),
    RootCauseRule(
        rule_id="RCA-005",
        trigger_controls=["ACL-001", "ISO27001-A.8.22-001"],
        root_cause="No network segmentation enforced at this device — all traffic permitted.",
        corrective_action="Configure inbound/outbound ACLs on all interfaces or define security zones.",
        category="Network Segmentation",
    ),
    RootCauseRule(
        rule_id="RCA-006",
        trigger_controls=["ISO27001-A.8.20-001", "ISO27001-A.8.20-002"],
        root_cause="Management access relies on legacy unencrypted protocols.",
        corrective_action="Disable Telnet/HTTP management and enforce SSH/HTTPS only.",
        category="Encrypted Management",
    ),
]


@dataclass
class RootCauseResult:
    """A root-cause finding for a set of failing controls."""
    rule_id: str
    matched_controls: list[str]
    root_cause: str
    corrective_action: str
    category: str


class RootCauseAnalyser:
    """
    Correlates compliance failures to identify root causes.

    Usage::

        analyser = RootCauseAnalyser()
        results = analyser.analyse(failing_control_ids=["SSH-001", "SSH-002", "LOG-001"])
    """

    def analyse(
        self,
        failing_control_ids: list[str],
        *,
        rules: list[RootCauseRule] | None = None,
    ) -> list[RootCauseResult]:
        """
        Match failing controls against root-cause rules.

        Args:
            failing_control_ids: Control IDs with status FAIL.
            rules: Optional override rule set (defaults to ROOT_CAUSE_RULES).

        Returns:
            List of RootCauseResult, ordered from most to fewest matched controls.
        """
        rule_set = rules if rules is not None else ROOT_CAUSE_RULES
        failing = set(failing_control_ids)
        results: list[RootCauseResult] = []

        for rule in rule_set:
            matched = [c for c in rule.trigger_controls if c in failing]
            # Require ALL trigger controls to be present for a match
            if len(matched) == len(rule.trigger_controls):
                results.append(RootCauseResult(
                    rule_id=rule.rule_id,
                    matched_controls=matched,
                    root_cause=rule.root_cause,
                    corrective_action=rule.corrective_action,
                    category=rule.category,
                ))

        # Also include partial matches (>= 50% of triggers matched) with a note
        for rule in rule_set:
            matched = [c for c in rule.trigger_controls if c in failing]
            full_match_ids = {r.rule_id for r in results}
            if (
                rule.rule_id not in full_match_ids
                and matched
                and len(matched) / len(rule.trigger_controls) >= 0.5
            ):
                results.append(RootCauseResult(
                    rule_id=f"{rule.rule_id}-PARTIAL",
                    matched_controls=matched,
                    root_cause=f"[Partial match] {rule.root_cause}",
                    corrective_action=rule.corrective_action,
                    category=rule.category,
                ))

        results.sort(key=lambda r: len(r.matched_controls), reverse=True)
        return results
