"""
Cisco Device Connector.

Supports Cisco IOS / IOS-XE devices with read-only command isolation.
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


class CiscoConnector(DeviceConnector):
    """Safe read-only connector for Cisco IOS/IOS-XE appliances."""

    @property
    def vendor_name(self) -> str:
        return "Cisco"

    @property
    def allowed_commands(self) -> set[str]:
        return {
            "show running-config",
            "show run",
            "show version",
            "show ip interface brief",
            "show interfaces",
            "show ip access-lists",
            "show access-lists",
            "show ip route",
            "show vlan",
            "show vlan brief",
            "show logging",
            "show inventory",
        }

    def test_connection(self) -> bool:
        """Tests SSH authentication using safe probe."""
        try:
            from netmiko import ConnectHandler  # type: ignore

            device_params = {
                "device_type": "cisco_ios",
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
        """Pulls running-config safely via Netmiko."""
        try:
            from netmiko import ConnectHandler  # type: ignore

            self.validate_command("show running-config")

            device_params = {
                "device_type": "cisco_ios",
                "host": self.host,
                "username": self.username,
                "password": self.password,
                "port": self.port,
                "conn_timeout": self.timeout,
                "auth_timeout": self.timeout,
                "global_delay_factor": 1,
            }
            with ConnectHandler(**device_params) as net_connect:
                net_connect.enable()
                output = net_connect.send_command("show running-config")
                return output
        except Exception as exc:
            raise DeviceConnectorError(f"Failed to collect Cisco config from {self.host}: {exc}") from exc

    def normalize_configuration(self, raw_config: str) -> NormalizedDeviceConfig:
        """Extracts normalized fields from Cisco IOS configuration."""
        hostname_match = re.search(r"^hostname\s+(\S+)", raw_config, re.MULTILINE | re.IGNORECASE)
        hostname = hostname_match.group(1) if hostname_match else self.host

        version_match = re.search(r"^version\s+(\S+)", raw_config, re.MULTILINE | re.IGNORECASE)
        os_version = f"Cisco IOS {version_match.group(1)}" if version_match else "Cisco IOS"

        # Interfaces
        interfaces: list[InterfaceInfo] = []
        int_blocks = re.split(r"(?=^interface\s+)", raw_config, flags=re.MULTILINE)
        for block in int_blocks:
            if not block.strip().startswith("interface"):
                continue
            first_line = block.splitlines()[0]
            name = first_line.replace("interface", "").strip()
            ip_match = re.search(r"ip address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)", block)
            ip_addr = ip_match.group(1) if ip_match else None
            mask = ip_match.group(2) if ip_match else None
            status = "admin_down" if "shutdown" in block else "up"
            interfaces.append(
                InterfaceInfo(
                    name=name,
                    ip_address=ip_addr,
                    subnet_mask=mask,
                    status=status,
                )
            )

        # Management services
        ssh_v2 = bool(re.search(r"ip ssh version 2", raw_config, re.IGNORECASE))
        ssh_enabled = bool(re.search(r"ip ssh", raw_config, re.IGNORECASE)) or ssh_v2
        telnet_disabled = bool(re.search(r"transport input ssh", raw_config, re.IGNORECASE))
        http_server = bool(re.search(r"^ip http server", raw_config, re.MULTILINE | re.IGNORECASE))
        https_server = bool(re.search(r"^ip http secure-server", raw_config, re.MULTILINE | re.IGNORECASE))
        snmp = bool(re.search(r"snmp-server community", raw_config, re.IGNORECASE))

        mgmt = ManagementServiceInfo(
            ssh_enabled=ssh_enabled,
            ssh_version=2 if ssh_v2 else (1 if ssh_enabled else 0),
            telnet_enabled=not telnet_disabled,
            http_enabled=http_server,
            https_enabled=https_server,
            snmp_enabled=snmp,
            snmp_version="v2c" if snmp else "none",
        )

        # ACLs / Firewall
        fw_rules: list[FirewallRuleInfo] = []
        for line in raw_config.splitlines():
            line = line.strip()
            if line.startswith("access-list") or line.startswith("ip access-list"):
                parts = line.split()
                action = "permit" if "permit" in parts else ("deny" if "deny" in parts else "permit")
                fw_rules.append(
                    FirewallRuleInfo(
                        rule_id=parts[1] if len(parts) > 1 else "acl",
                        action=action,
                        source="any" if "any" in parts else "subnet",
                        destination="any" if "any" in parts else "host",
                        port="any",
                        protocol="ip",
                    )
                )

        return NormalizedDeviceConfig(
            id=f"cisco-{self.host.replace('.', '-')}",
            hostname=hostname,
            ip_address=self.host,
            vendor="Cisco",
            device_type="Switch" if "catalyst" in raw_config.lower() else "Router",
            os_version=os_version,
            is_live=True,
            credential_status="authenticated",
            interfaces=interfaces,
            management_services=mgmt,
            firewall_rules=fw_rules,
            raw_configuration=raw_config,
        )
