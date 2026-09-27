"""
Normalized Configuration Model.

Provides a vendor-agnostic internal representation of a network device's
configuration and operational posture so that security evaluation engines
do not need to understand every individual vendor's syntax.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class InterfaceInfo:
    name: str
    ip_address: str | None = None
    subnet_mask: str | None = None
    status: str = "up"  # up | down | admin_down
    vlan_id: int | None = None
    description: str = ""


@dataclass
class ManagementServiceInfo:
    ssh_enabled: bool = False
    ssh_version: int = 0
    telnet_enabled: bool = False
    http_enabled: bool = False
    https_enabled: bool = False
    snmp_enabled: bool = False
    snmp_version: str = "none"  # none | v1 | v2c | v3
    netconf_enabled: bool = False
    restconf_enabled: bool = False


@dataclass
class FirewallRuleInfo:
    rule_id: str
    action: str  # permit | deny | drop
    source: str
    destination: str
    port: str
    protocol: str = "ip"
    direction: str = "inbound"  # inbound | outbound


@dataclass
class NormalizedDeviceConfig:
    """
    Common internal device model.

    Retains the original raw configuration text as cryptographic evidence
    while exposing normalized structural fields for policy evaluation.
    """

    id: str
    hostname: str
    ip_address: str
    vendor: str                         # Cisco | Fortinet | Palo Alto | MikroTik | Linux | Unknown
    model: str = "Generic Network Device"
    device_type: str = "Unknown"        # Router | Switch | Firewall | Security Gateway | Server | Unknown
    os_version: str = "Unknown"
    is_live: bool = False
    credential_status: str = "none"     # none | authenticated | failed
    interfaces: list[InterfaceInfo] = field(default_factory=list)
    management_services: ManagementServiceInfo = field(default_factory=ManagementServiceInfo)
    firewall_rules: list[FirewallRuleInfo] = field(default_factory=list)
    routing_rules: list[dict[str, Any]] = field(default_factory=list)
    vlans: list[dict[str, Any]] = field(default_factory=list)
    authentication: dict[str, Any] = field(default_factory=dict)
    logging: dict[str, Any] = field(default_factory=dict)
    raw_configuration: str = ""
    collected_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "vendor": self.vendor,
            "model": self.model,
            "device_type": self.device_type,
            "os_version": self.os_version,
            "is_live": self.is_live,
            "credential_status": self.credential_status,
            "interfaces": [i.__dict__ for i in self.interfaces],
            "management_services": self.management_services.__dict__,
            "firewall_rules": [f.__dict__ for f in self.firewall_rules],
            "routing_rules": self.routing_rules,
            "vlans": self.vlans,
            "authentication": self.authentication,
            "logging": self.logging,
            "raw_configuration": self.raw_configuration,
            "collected_at": self.collected_at,
        }
