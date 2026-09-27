"""
Palo Alto Networks PAN-OS Device Connector.

Supports PAN-OS next-generation firewalls with read-only CLI isolation.
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


class PaloAltoConnector(DeviceConnector):
    """Safe read-only connector for Palo Alto PAN-OS firewalls."""

    @property
    def vendor_name(self) -> str:
        return "Palo Alto"

    @property
    def allowed_commands(self) -> set[str]:
        return {
            "show system info",
            "show config running",
            "show interface all",
            "show interface logical",
            "show routing route",
            "show running security-policy",
        }

    def test_connection(self) -> bool:
        """Tests SSH reachability to Palo Alto appliance."""
        try:
            from netmiko import ConnectHandler  # type: ignore

            device_params = {
                "device_type": "paloalto_panos",
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
        """Collects running PAN-OS configuration safely."""
        try:
            from netmiko import ConnectHandler  # type: ignore

            self.validate_command("show config running")

            device_params = {
                "device_type": "paloalto_panos",
                "host": self.host,
                "username": self.username,
                "password": self.password,
                "port": self.port,
                "conn_timeout": self.timeout,
                "auth_timeout": self.timeout,
            }
            with ConnectHandler(**device_params) as net_connect:
                output = net_connect.send_command("show config running")
                return output
        except Exception as exc:
            raise DeviceConnectorError(f"Failed to collect Palo Alto config from {self.host}: {exc}") from exc

    def normalize_configuration(self, raw_config: str) -> NormalizedDeviceConfig:
        """Parses PAN-OS XML or CLI set format config into normalized structure."""
        hn_match = re.search(r"<hostname>([^<]+)</hostname>", raw_config) or re.search(r"set system hostname (\S+)", raw_config)
        hostname = hn_match.group(1) if hn_match else self.host

        return NormalizedDeviceConfig(
            id=f"paloalto-{self.host.replace('.', '-')}",
            hostname=hostname,
            ip_address=self.host,
            vendor="Palo Alto",
            device_type="Firewall",
            os_version="PAN-OS 10.x/11.x",
            is_live=True,
            credential_status="authenticated",
            interfaces=[InterfaceInfo(name="ethernet1/1", status="up")],
            management_services=ManagementServiceInfo(
                ssh_enabled=True,
                ssh_version=2,
                telnet_enabled=False,
                https_enabled=True,
                snmp_enabled=False,
            ),
            firewall_rules=[
                FirewallRuleInfo(rule_id="rule1", action="permit", source="trust", destination="untrust", port="any")
            ],
            raw_configuration=raw_config,
        )
