"""
Vendor Remediation Provider Factory.
"""

from __future__ import annotations

from .base import BaseRemediationProvider
from .cisco import CiscoRemediationProvider
from .fortinet import FortinetRemediationProvider
from .juniper import JuniperRemediationProvider
from .linux import LinuxRemediationProvider
from .mikrotik import MikroTikRemediationProvider
from .paloalto import PaloAltoRemediationProvider


_PROVIDERS: dict[str, type[BaseRemediationProvider]] = {
    "cisco": CiscoRemediationProvider,
    "cisco_ios": CiscoRemediationProvider,
    "ios": CiscoRemediationProvider,
    "fortinet": FortinetRemediationProvider,
    "fortios": FortinetRemediationProvider,
    "juniper": JuniperRemediationProvider,
    "junos": JuniperRemediationProvider,
    "paloalto": PaloAltoRemediationProvider,
    "palo_alto": PaloAltoRemediationProvider,
    "panos": PaloAltoRemediationProvider,
    "mikrotik": MikroTikRemediationProvider,
    "routeros": MikroTikRemediationProvider,
    "linux": LinuxRemediationProvider,
    "debian": LinuxRemediationProvider,
    "ubuntu": LinuxRemediationProvider,
    "centos": LinuxRemediationProvider,
    "host": LinuxRemediationProvider,
    "local_host": LinuxRemediationProvider,
}


def get_remediation_provider(vendor: str) -> BaseRemediationProvider:
    """
    Returns an instantiated BaseRemediationProvider for the specified vendor.
    Defaults to CiscoRemediationProvider if vendor is unrecognized.
    """
    clean_v = vendor.strip().lower().replace("-", "_").replace(" ", "_")
    provider_cls = _PROVIDERS.get(clean_v, CiscoRemediationProvider)
    return provider_cls()
