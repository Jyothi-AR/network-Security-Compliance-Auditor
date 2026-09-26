"""
ISO/IEC 27001:2022 compliance framework.

Maps ISO 27001 Annex A controls relevant to network device security
to the Universal Configuration Model semantic fields.
"""

from __future__ import annotations

from sih26155.compliance.policy.models import PolicyRule, PolicySet


def build_iso27001_policy() -> PolicySet:
    """
    Return a PolicySet covering ISO 27001:2022 Annex A network controls.

    Controls included:
        A.8.1  - Network configuration documentation
        A.8.20 - Network security (encrypted management protocols)
        A.8.21 - Security of network services (authentication)
        A.8.22 - Segregation of networks (ACL / zone policy)
        A.5.16 - Identity management (local auth / AAA)
        A.8.16 - Monitoring (logging enabled)
        A.5.14 - Information transfer (encryption in transit)
    """
    rules = [
        # A.8.20 – Network security: Telnet must be disabled
        PolicyRule(
            control_id="ISO27001-A.8.20-001",
            description="Telnet must be disabled; use SSH for encrypted management.",
            semantic_field="telnet_enabled",
            operator="eq",
            expected=False,
            severity="HIGH",
        ),
        # A.8.20 – SSH must be enabled
        PolicyRule(
            control_id="ISO27001-A.8.20-002",
            description="SSH must be enabled for encrypted device management.",
            semantic_field="ssh_enabled",
            operator="eq",
            expected=True,
            severity="HIGH",
        ),
        # A.8.20 – SSH version must be 2
        PolicyRule(
            control_id="ISO27001-A.8.20-003",
            description="SSH version 2 must be enforced (SSHv1 is insecure).",
            semantic_field="ssh_version",
            operator="eq",
            expected=2,
            severity="HIGH",
        ),
        # A.8.21 – Authentication: no default credentials
        PolicyRule(
            control_id="ISO27001-A.8.21-001",
            description="Password encryption must be enabled (no plaintext passwords).",
            semantic_field="password_encryption_enabled",
            operator="eq",
            expected=True,
            severity="CRITICAL",
        ),
        # A.8.21 – AAA authentication required
        PolicyRule(
            control_id="ISO27001-A.8.21-002",
            description="AAA authentication should be configured for device access.",
            semantic_field="aaa_authentication_enabled",
            operator="eq",
            expected=True,
            severity="HIGH",
        ),
        # A.8.16 – Monitoring: logging must be enabled
        PolicyRule(
            control_id="ISO27001-A.8.16-001",
            description="Centralized logging must be enabled for audit trail.",
            semantic_field="logging_enabled",
            operator="eq",
            expected=True,
            severity="MEDIUM",
        ),
        # A.8.16 – NTP must be configured for accurate log timestamps
        PolicyRule(
            control_id="ISO27001-A.8.16-002",
            description="NTP must be configured for accurate audit log timestamps.",
            semantic_field="ntp_configured",
            operator="eq",
            expected=True,
            severity="MEDIUM",
        ),
        # A.5.14 – SNMP: SNMPv1/v2 must be disabled (use SNMPv3)
        PolicyRule(
            control_id="ISO27001-A.5.14-001",
            description="SNMPv3 must be used; SNMPv1/v2c transmit credentials in plaintext.",
            semantic_field="snmp_version",
            operator="eq",
            expected=3,
            severity="HIGH",
        ),
        # A.8.22 – Network segregation: ACL / zone policy must exist
        PolicyRule(
            control_id="ISO27001-A.8.22-001",
            description="Access control lists or zone policies must be configured.",
            semantic_field="acl_configured",
            operator="eq",
            expected=True,
            severity="MEDIUM",
        ),
        # A.8.20 – Minimum SSH key length
        PolicyRule(
            control_id="ISO27001-A.8.20-004",
            description="SSH RSA key length must be at least 2048 bits.",
            semantic_field="ssh_key_bits",
            operator="gte",
            expected=2048,
            severity="MEDIUM",
        ),
    ]

    return PolicySet(
        name="ISO/IEC 27001:2022",
        rules=rules,
    )
