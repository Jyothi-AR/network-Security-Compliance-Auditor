"""
Device Connector Factory.

Instantiates the proper vendor-specific connector based on detected device vendor/platform.
"""

from __future__ import annotations

from typing import Type

from sih26155.connectors.base import DeviceConnector
from sih26155.connectors.cisco import CiscoConnector
from sih26155.connectors.fortinet import FortinetConnector
from sih26155.connectors.linux import LinuxConnector
from sih26155.connectors.mikrotik import MikroTikConnector
from sih26155.connectors.paloalto import PaloAltoConnector


_CONNECTOR_REGISTRY: dict[str, Type[DeviceConnector]] = {
    "cisco": CiscoConnector,
    "cisco_ios": CiscoConnector,
    "cisco_xe": CiscoConnector,
    "fortinet": FortinetConnector,
    "fortios": FortinetConnector,
    "paloalto": PaloAltoConnector,
    "palo_alto": PaloAltoConnector,
    "panos": PaloAltoConnector,
    "mikrotik": MikroTikConnector,
    "routeros": MikroTikConnector,
    "linux": LinuxConnector,
    "debian": LinuxConnector,
    "ubuntu": LinuxConnector,
    "rhel": LinuxConnector,
}


def get_connector(
    vendor: str,
    host: str,
    username: str = "",
    password: str = "",
    port: int = 22,
    timeout: int = 15,
) -> DeviceConnector:
    """
    Returns an instantiated DeviceConnector for the given vendor.
    Falls back to CiscoConnector if vendor is unknown or generic.
    """
    key = vendor.strip().lower().replace(" ", "_")
    connector_cls = _CONNECTOR_REGISTRY.get(key, CiscoConnector)
    return connector_cls(
        host=host,
        username=username,
        password=password,
        port=port,
        timeout=timeout,
    )
