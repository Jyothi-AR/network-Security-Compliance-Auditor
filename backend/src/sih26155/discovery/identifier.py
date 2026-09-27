"""
Device Identification Engine.

Inspects collected network discovery telemetry (open management ports,
service banners, MAC OUIs, hostnames, and SNMP responses) to accurately
identify the device vendor and device role without speculative guessing.
If evidence is insufficient, marks device as "Unknown network device".
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any


@dataclass
class DeviceIdentification:
    vendor: str                         # Cisco | Fortinet | Palo Alto | MikroTik | Linux | Unknown
    device_type: str                    # Switch | Router | Firewall | Security Gateway | Linux/Network Server | Unknown network device
    model: str = "Generic Network Device"
    os_version: str = "Unknown"
    confidence: float = 0.0             # 0.0 to 1.0
    evidence: list[str] = field(default_factory=list)


# Standard MAC OUI vendor prefix signatures
MAC_OUI_PATTERNS: list[tuple[str, str, str]] = [
    (r"^(00:00:0c|00:01:42|00:01:43|00:01:63|00:01:64|00:01:96|00:01:97|00:01:c7|00:01:c9|00:02:16|00:02:17|00:02:4a|00:02:4b|00:02:7d|00:02:7e|00:02:ba|00:02:bb|00:02:fc|00:02:fd|00:03:31|00:03:32|00:03:6b|00:03:6c|00:03:9f|00:03:a0|00:03:e3|00:03:e4|00:04:4d|00:04:4e|00:04:9a|00:04:9b|00:04:c0|00:04:c1|00:04:dd|00:05:31|00:05:32|00:05:5e|00:05:73|00:05:9a|00:05:dc|00:06:28|00:06:52|00:06:53|00:06:c1|00:07:0d|00:07:0e|00:07:4f|00:07:50|00:07:84|00:07:85|00:07:b3|00:07:b4|00:07:eb|00:07:ec|00:08:20|00:08:21|00:08:7c|00:08:7d|00:08:a3|00:08:a4|00:08:e2|00:08:e3)", "Cisco", "Switch"),
    (r"^(00:09:0f|00:09:6b|00:65:42|08:5b:0e|20:00:2b|70:4c:a5|90:6c:ac|00:0c:e6)", "Fortinet", "Firewall"),
    (r"^(00:1b:17|00:30:48|08:66:98|d4:f4:be)", "Palo Alto", "Firewall"),
    (r"^(00:0c:42|2c:c8:1b|48:8f:5a|64:d1:54|6c:3b:6b|74:4d:28|b8:69:f4|c4:ad:34|cc:2d:e0|d4:01:c3|e4:8d:8c)", "MikroTik", "Router"),
]


def identify_device(
    ip: str,
    hostname: str = "",
    open_ports: list[int] | None = None,
    banners: dict[int, str] | None = None,
    mac_address: str = "",
    snmp_sysdescr: str = "",
) -> DeviceIdentification:
    """
    Deterministically evaluates evidence to classify device type and vendor.
    """
    open_ports = open_ports or []
    banners = banners or {}
    evidence: list[str] = []

    vendor = "Unknown"
    device_type = "Unknown network device"
    model = "Generic Network Device"
    os_version = "Unknown"
    confidence = 0.0

    # 1. Inspect SNMP sysDescr if present (Strongest deterministic proof)
    if snmp_sysdescr:
        snmp_lower = snmp_sysdescr.lower()
        if "cisco" in snmp_lower:
            vendor = "Cisco"
            confidence = 0.95
            evidence.append(f"SNMP sysDescr identified Cisco appliance: {snmp_sysdescr[:60]}")
            if any(k in snmp_lower for k in ["switch", "catalyst", "nexus", "c2960", "c3850"]):
                device_type = "Switch"
            elif any(k in snmp_lower for k in ["router", "isr", "asr", "c800", "c1900"]):
                device_type = "Router"
            elif "asa" in snmp_lower or "firepower" in snmp_lower:
                device_type = "Firewall"
        elif "fortinet" in snmp_lower or "fortios" in snmp_lower or "fortigate" in snmp_lower:
            vendor = "Fortinet"
            device_type = "Firewall"
            confidence = 0.95
            evidence.append(f"SNMP sysDescr identified Fortinet firewall: {snmp_sysdescr[:60]}")
        elif "palo alto" in snmp_lower or "pan-os" in snmp_lower:
            vendor = "Palo Alto"
            device_type = "Firewall"
            confidence = 0.95
            evidence.append(f"SNMP sysDescr identified Palo Alto PAN-OS: {snmp_sysdescr[:60]}")
        elif "mikrotik" in snmp_lower or "routeros" in snmp_lower:
            vendor = "MikroTik"
            device_type = "Router"
            confidence = 0.95
            evidence.append(f"SNMP sysDescr identified MikroTik RouterOS: {snmp_sysdescr[:60]}")
        elif "linux" in snmp_lower:
            vendor = "Linux"
            device_type = "Linux/Network Server"
            confidence = 0.90
            evidence.append("SNMP sysDescr identified Linux operating system")

    # 2. Inspect Service Banners (SSH / HTTP / Telnet)
    if vendor == "Unknown":
        for port, banner in banners.items():
            b_lower = banner.lower()
            if "cisco" in b_lower:
                vendor = "Cisco"
                confidence = 0.85
                evidence.append(f"Port {port} service banner contains Cisco identifier")
                if "ios-xe" in b_lower or "ios" in b_lower:
                    device_type = "Router" if "router" in hostname.lower() else "Switch"
            elif "fortigate" in b_lower or "fortios" in b_lower:
                vendor = "Fortinet"
                device_type = "Firewall"
                confidence = 0.90
                evidence.append(f"Port {port} banner contains FortiGate / FortiOS identifier")
            elif "pan-os" in b_lower or "palo alto" in b_lower:
                vendor = "Palo Alto"
                device_type = "Firewall"
                confidence = 0.90
                evidence.append(f"Port {port} banner contains Palo Alto signature")
            elif "mikrotik" in b_lower or "routeros" in b_lower:
                vendor = "MikroTik"
                device_type = "Router"
                confidence = 0.90
                evidence.append(f"Port {port} banner contains MikroTik RouterOS signature")
            elif "openssh" in b_lower or "debian" in b_lower or "ubuntu" in b_lower:
                vendor = "Linux"
                device_type = "Linux/Network Server"
                confidence = 0.80
                evidence.append(f"Port {port} SSH banner indicates Linux host ({banner.strip()})")

    # 3. MAC OUI Vendor lookup
    if vendor == "Unknown" and mac_address:
        mac_clean = mac_address.lower().replace("-", ":")
        for pattern, m_vendor, m_type in MAC_OUI_PATTERNS:
            if re.match(pattern, mac_clean):
                vendor = m_vendor
                device_type = m_type
                confidence = 0.70
                evidence.append(f"MAC OUI prefix {mac_clean[:8]} matches {m_vendor} registered hardware")
                break

    # 4. Hostname Heuristics (if vendor still undetermined or to clarify device type)
    h_lower = hostname.lower()
    if h_lower:
        if any(h_lower.startswith(p) for p in ["rtr", "router", "gw", "gateway"]):
            if device_type == "Unknown network device":
                device_type = "Router"
                evidence.append(f"Hostname '{hostname}' matches router naming convention")
        elif any(h_lower.startswith(p) for p in ["sw", "switch", "access-sw", "core-sw"]):
            if device_type == "Unknown network device":
                device_type = "Switch"
                evidence.append(f"Hostname '{hostname}' matches switch naming convention")
        elif any(h_lower.startswith(p) for p in ["fw", "firewall", "sec-gw"]):
            if device_type == "Unknown network device":
                device_type = "Firewall"
                evidence.append(f"Hostname '{hostname}' matches firewall naming convention")
        elif any(h_lower.startswith(p) for p in ["srv", "server", "linux", "host"]):
            if device_type == "Unknown network device":
                device_type = "Linux/Network Server"
                evidence.append(f"Hostname '{hostname}' matches server naming convention")

    # 5. Open Management Port Profile Inference
    if device_type == "Unknown network device" and open_ports:
        if 8728 in open_ports or 8729 in open_ports:  # MikroTik RouterOS API
            vendor = "MikroTik"
            device_type = "Router"
            confidence = max(confidence, 0.75)
            evidence.append("Port 8728/8729 (MikroTik RouterOS API) detected")
        elif 830 in open_ports:  # NETCONF
            confidence = max(confidence, 0.60)
            evidence.append("Port 830 (NETCONF) active - Enterprise Network Appliance")
        elif 22 in open_ports and not any(p in open_ports for p in [80, 443, 8080]):
            confidence = max(confidence, 0.40)
            evidence.append("Port 22 SSH active - Secure CLI management endpoint")

    # Strict fallback: If no confident evidence, clearly state unknown
    if confidence < 0.4:
        vendor = "Unknown"
        device_type = "Unknown network device"
        if not evidence:
            evidence.append("Insufficient telemetry to confidently identify device type or vendor")

    return DeviceIdentification(
        vendor=vendor,
        device_type=device_type,
        model=model,
        os_version=os_version,
        confidence=round(confidence, 2),
        evidence=evidence,
    )
