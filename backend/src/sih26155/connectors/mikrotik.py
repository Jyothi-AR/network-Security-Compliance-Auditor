"""
MikroTik RouterOS Device Connector.

Supports MikroTik RouterOS appliances with read-only command isolation.
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


class MikroTikConnector(DeviceConnector):
    """Safe read-only connector for MikroTik RouterOS appliances."""

    @property
    def vendor_name(self) -> str:
        return "MikroTik"

    @property
    def allowed_commands(self) -> set[str]:
        return {
            "/export",
            "/export verbose",
            "/export compact",
            "/system resource print",
            "/system identity print",
            "/ip address print",
            "/ip service print",
            "/ip firewall filter print",
            "/ip route print",
        }

    def test_connection(self) -> bool:
        """Tests SSH reachability to MikroTik device."""
        try:
            from netmiko import ConnectHandler  # type: ignore

            device_params = {
                "device_type": "mikrotik_routeros",
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
        """Collects MikroTik RouterOS configuration using /export compact."""
        try:
            from netmiko import ConnectHandler  # type: ignore

            self.validate_command("/export compact")

            device_params = {
                "device_type": "mikrotik_routeros",
                "host": self.host,
                "username": self.username,
                "password": self.password,
                "port": self.port,
                "conn_timeout": self.timeout,
                "auth_timeout": self.timeout,
            }
            with ConnectHandler(**device_params) as net_connect:
                output = net_connect.send_command("/export compact")
                return output
        except Exception as exc:
            raise DeviceConnectorError(f"Failed to collect MikroTik config from {self.host}: {exc}") from exc

    def normalize_configuration(self, raw_config: str) -> NormalizedDeviceConfig:
        """Extracts normalized fields from RouterOS export."""
        hn_match = re.search(r'set name="?([^"\n]+)"?', raw_config)
        hostname = hn_match.group(1) if hn_match else self.host

        interfaces: list[InterfaceInfo] = []
        int_matches = re.finditer(r'add\s+address=([0-9./]+)\s+interface=([a-zA-Z0-9_-]+)', raw_config)
        for im in int_matches:
            interfaces.append(
                InterfaceInfo(
                    name=im.group(2),
                    ip_address=im.group(1),
                    status="up",
                )
            )

        mgmt = ManagementServiceInfo(
            ssh_enabled=bool(re.search(r"ssh.*enabled=yes", raw_config, re.IGNORECASE)) or True,
            ssh_version=2,
            telnet_enabled=bool(re.search(r"telnet.*enabled=yes", raw_config, re.IGNORECASE)),
            http_enabled=bool(re.search(r"www.*enabled=yes", raw_config, re.IGNORECASE)),
            https_enabled=bool(re.search(r"www-ssl.*enabled=yes", raw_config, re.IGNORECASE)),
            snmp_enabled=bool(re.search(r"/snmp\s+set\s+enabled=yes", raw_config, re.IGNORECASE)),
        )

        return NormalizedDeviceConfig(
            id=f"mikrotik-{self.host.replace('.', '-')}",
            hostname=hostname,
            ip_address=self.host,
            vendor="MikroTik",
            device_type="Router",
            os_version="RouterOS v6/v7",
            is_live=True,
            credential_status="authenticated",
            interfaces=interfaces,
            management_services=mgmt,
            firewall_rules=[],
            raw_configuration=raw_config,
        )
