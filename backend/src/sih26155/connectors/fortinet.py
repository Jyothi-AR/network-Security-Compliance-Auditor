"""
Fortinet FortiOS Device Connector.

Supports Fortinet FortiGate appliances with read-only command isolation.
"""

from __future__ import annotations

import re
from typing import Any

from sih26155.connectors.base import DeviceConnector, DeviceConnectorError
from sih26155.core.schema.normalized_device import (
    FirewallRuleInfo,
    InterfaceInfo,
    ManagementServiceInfo,
    NormalizedDeviceConfig,
)


class FortinetConnector(DeviceConnector):
    """Safe read-only connector for Fortinet FortiOS appliances."""

    @property
    def vendor_name(self) -> str:
        return "Fortinet"

    @property
    def allowed_commands(self) -> set[str]:
        return {
            "get system status",
            "show system status",
            "show full-configuration",
            "show system interface",
            "show firewall policy",
            "show firewall address",
            "show system admin",
            "show router static",
        }

    def test_connection(self) -> bool:
        """Tests SSH reachability to FortiGate."""
        try:
            from netmiko import ConnectHandler  # type: ignore

            device_params = {
                "device_type": "fortinet",
                "host": self.host,
                "username": self.username,
                "password": self.password,
                "port": self.port,
                "conn_timeout": self.timeout,
                "auth_timeout": self.timeout,
            }
            with ConnectHandler(**device_params) as net_connect:
                return bool(net_connect.is_alive())
        except Exception:
            return False

    def collect_configuration(self) -> str:
        """Safely collects FortiOS full configuration."""
        try:
            from netmiko import ConnectHandler  # type: ignore

            self.validate_command("show full-configuration")

            device_params = {
                "device_type": "fortinet",
                "host": self.host,
                "username": self.username,
                "password": self.password,
                "port": self.port,
                "conn_timeout": self.timeout,
                "auth_timeout": self.timeout,
            }
            with ConnectHandler(**device_params) as net_connect:
                output = net_connect.send_command("show full-configuration")
                return output
        except Exception as exc:
            raise DeviceConnectorError(f"Failed to collect Fortinet config from {self.host}: {exc}") from exc

    def normalize_configuration(self, raw_config: str) -> NormalizedDeviceConfig:
        """Extracts normalized fields from FortiOS config."""
        hostname_match = re.search(r'set\s+hostname\s+"?([^"\n]+)"?', raw_config)
        hostname = hostname_match.group(1) if hostname_match else self.host

        version_match = re.search(r'#config-version=([^:\n]+)', raw_config)
        os_version = f"FortiOS {version_match.group(1)}" if version_match else "FortiOS"

        # Interfaces
        interfaces: list[InterfaceInfo] = []
        int_matches = re.finditer(r'edit\s+"?([^"\n]+)"?\s*\n(?:\s+set\s+ip\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+))?', raw_config)
        for m in int_matches:
            name = m.group(1)
            ip_addr = m.group(2)
            mask = m.group(3)
            interfaces.append(InterfaceInfo(name=name, ip_address=ip_addr, subnet_mask=mask))

        # Policies / Firewall
        fw_rules: list[FirewallRuleInfo] = []
        policy_matches = re.finditer(
            r'edit\s+(\d+)\s*\n(?:[^\n]*\n)*?\s+set\s+action\s+(accept|deny)',
            raw_config,
        )
        for pm in policy_matches:
            rule_id = pm.group(1)
            action = "permit" if pm.group(2) == "accept" else "deny"
            fw_rules.append(
                FirewallRuleInfo(
                    rule_id=rule_id,
                    action=action,
                    source="all",
                    destination="all",
                    port="all",
                )
            )

        mgmt = ManagementServiceInfo(
            ssh_enabled=True,
            ssh_version=2,
            telnet_enabled=False,
            http_enabled=bool(re.search(r"set allowaccess .*?http\b", raw_config)),
            https_enabled=bool(re.search(r"set allowaccess .*?https\b", raw_config)),
            snmp_enabled=bool(re.search(r"config system snmp", raw_config)),
        )

        return NormalizedDeviceConfig(
            id=f"fortinet-{self.host.replace('.', '-')}",
            hostname=hostname,
            ip_address=self.host,
            vendor="Fortinet",
            device_type="Firewall",
            os_version=os_version,
            is_live=True,
            credential_status="authenticated",
            interfaces=interfaces,
            management_services=mgmt,
            firewall_rules=fw_rules,
            raw_configuration=raw_config,
        )
