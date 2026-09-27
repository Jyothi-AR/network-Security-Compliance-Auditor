"""
Linux Network Server / Gateway Connector.

Supports Linux network hosts, gateways, and bastions with read-only inspection.
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


class LinuxConnector(DeviceConnector):
    """Safe read-only connector for Linux servers, firewalls, and gateways."""

    @property
    def vendor_name(self) -> str:
        return "Linux"

    @property
    def allowed_commands(self) -> set[str]:
        return {
            "cat /etc/hostname",
            "hostname",
            "uname -a",
            "cat /etc/os-release",
            "cat /etc/ssh/sshd_config",
            "iptables-save",
            "nft list ruleset",
            "ip addr",
            "ip route",
            "ss -tuln",
            "cat /etc/audit/auditd.conf",
        }

    def test_connection(self) -> bool:
        """Tests SSH reachability to Linux host."""
        try:
            import paramiko  # type: ignore

            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout,
            )
            client.close()
            return True
        except Exception:
            return False

    def collect_configuration(self) -> str:
        """Collects Linux system configuration using safe read-only commands."""
        try:
            import paramiko  # type: ignore

            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
            )

            outputs: list[str] = []
            for cmd in ["cat /etc/hostname", "cat /etc/os-release", "cat /etc/ssh/sshd_config", "ip addr", "iptables-save"]:
                self.validate_command(cmd)
                stdin, stdout, stderr = client.exec_command(cmd, timeout=5)
                out_text = stdout.read().decode("utf-8", errors="ignore").strip()
                outputs.append(f"# --- {cmd} ---\n{out_text}")

            client.close()
            return "\n\n".join(outputs)
        except Exception as exc:
            raise DeviceConnectorError(f"Failed to collect Linux config from {self.host}: {exc}") from exc

    def normalize_configuration(self, raw_config: str) -> NormalizedDeviceConfig:
        """Parses Linux configuration telemetry into canonical model."""
        hn_match = re.search(r"# --- cat /etc/hostname ---\s*([\w.-]+)", raw_config)
        hostname = hn_match.group(1) if hn_match else self.host

        os_match = re.search(r'PRETTY_NAME="([^"]+)"', raw_config)
        os_version = os_match.group(1) if os_match else "Linux"

        ssh_root_login = bool(re.search(r"^\s*PermitRootLogin\s+no", raw_config, re.MULTILINE | re.IGNORECASE))
        ssh_pw_auth = bool(re.search(r"^\s*PasswordAuthentication\s+no", raw_config, re.MULTILINE | re.IGNORECASE))

        mgmt = ManagementServiceInfo(
            ssh_enabled=True,
            ssh_version=2,
            telnet_enabled=False,
            http_enabled=False,
            https_enabled=False,
            snmp_enabled=False,
        )

        return NormalizedDeviceConfig(
            id=f"linux-{self.host.replace('.', '-')}",
            hostname=hostname,
            ip_address=self.host,
            vendor="Linux",
            device_type="Linux/Network Server",
            os_version=os_version,
            is_live=True,
            credential_status="authenticated",
            interfaces=[InterfaceInfo(name="eth0", status="up")],
            management_services=mgmt,
            firewall_rules=[],
            raw_configuration=raw_config,
        )
