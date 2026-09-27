"""
Automated Unit and Integration Tests for Live Network Audit Pipeline.

Tests:
1. Identification Rules & Evidence Classification
2. Discovery Safety Constraints & Rate Limits
3. Vendor Connector Read-Only Command Allowlists & Mutating Command Rejection
4. Canonical Normalized Device Model Conversion
5. Cross-Device Topology Graph & Multi-Hop Risk Exposure Analysis
6. Network Audit REST API Integration
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from sih26155.api.main import app
from sih26155.connectors.base import ConnectorSecurityViolation
from sih26155.connectors.cisco import CiscoConnector
from sih26155.connectors.factory import get_connector
from sih26155.connectors.fortinet import FortinetConnector
from sih26155.connectors.linux import LinuxConnector
from sih26155.connectors.mikrotik import MikroTikConnector
from sih26155.connectors.paloalto import PaloAltoConnector
from sih26155.core.schema.normalized_device import NormalizedDeviceConfig
from sih26155.discovery.engine import generate_demo_lab_hosts
from sih26155.discovery.identifier import identify_device
from sih26155.intelligence.cross_device import analyze_cross_device_exposure
from sih26155.storage.database import create_all_tables

create_all_tables()
client = TestClient(app)


# ===========================================================================
# 1. Device Identification Tests
# ===========================================================================

def test_identify_cisco_from_banner():
    ident = identify_device(
        ip="192.168.1.1",
        hostname="router-01",
        open_ports=[22],
        banners={22: "SSH-2.0-Cisco-1.25"},
    )
    assert ident.vendor == "Cisco"
    assert ident.confidence >= 0.80
    assert "Cisco" in ident.evidence[0]


def test_identify_fortinet_from_snmp():
    ident = identify_device(
        ip="192.168.1.20",
        hostname="fw-edge",
        snmp_sysdescr="FortiGate-100E v7.2.4,build1396,230309 (GA)",
    )
    assert ident.vendor == "Fortinet"
    assert ident.device_type == "Firewall"
    assert ident.confidence >= 0.90


def test_identify_mikrotik_from_port():
    ident = identify_device(
        ip="192.168.1.50",
        hostname="branch-gw",
        open_ports=[22, 8728],
        banners={22: "SSH-2.0-ROUTEROS", 8728: "MikroTik API"},
    )
    assert ident.vendor == "MikroTik"
    assert ident.device_type == "Router"


def test_identify_unknown_device_when_no_signatures():
    ident = identify_device(
        ip="192.168.1.145",
        hostname="192.168.1.145",
        open_ports=[80],
        banners={},
    )
    assert ident.vendor == "Unknown"
    assert ident.device_type == "Unknown network device"
    assert ident.confidence < 0.5


# ===========================================================================
# 2. Connector Read-Only Security & Command Allowlists
# ===========================================================================

def test_cisco_allows_show_running_config():
    conn = CiscoConnector(host="192.168.1.1")
    # Should not raise
    conn.validate_command("show running-config")
    conn.validate_command("show version")


def test_cisco_blocks_mutating_commands():
    conn = CiscoConnector(host="192.168.1.1")

    with pytest.raises(ConnectorSecurityViolation):
        conn.validate_command("configure terminal")

    with pytest.raises(ConnectorSecurityViolation):
        conn.validate_command("config t")

    with pytest.raises(ConnectorSecurityViolation):
        conn.validate_command("reload")

    with pytest.raises(ConnectorSecurityViolation):
        conn.validate_command("write memory")


def test_fortinet_connector_safety():
    conn = FortinetConnector(host="192.168.1.20")
    conn.validate_command("show full-configuration")

    with pytest.raises(ConnectorSecurityViolation):
        conn.validate_command("set hostname hacker")

    with pytest.raises(ConnectorSecurityViolation):
        conn.validate_command("reboot")


def test_connector_factory_resolution():
    cisco = get_connector("cisco", host="10.0.0.1")
    assert isinstance(cisco, CiscoConnector)

    forti = get_connector("fortinet", host="10.0.0.2")
    assert isinstance(forti, FortinetConnector)

    palo = get_connector("paloalto", host="10.0.0.3")
    assert isinstance(palo, PaloAltoConnector)

    mt = get_connector("mikrotik", host="10.0.0.4")
    assert isinstance(mt, MikroTikConnector)

    linux = get_connector("linux", host="10.0.0.5")
    assert isinstance(linux, LinuxConnector)


# ===========================================================================
# 3. Canonical Model Normalization
# ===========================================================================

def test_cisco_normalization():
    conn = CiscoConnector(host="192.168.1.1")
    cisco_cfg = """\
hostname EDGE-RTR-01
version 15.6
ip ssh version 2
ip http server
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
interface GigabitEthernet0/1
 shutdown
"""
    norm = conn.normalize_configuration(cisco_cfg)
    assert norm.hostname == "EDGE-RTR-01"
    assert norm.vendor == "Cisco"
    assert norm.management_services.ssh_version == 2
    assert norm.management_services.http_enabled is True
    assert len(norm.interfaces) == 2
    assert norm.interfaces[0].ip_address == "192.168.1.1"
    assert norm.interfaces[1].status == "admin_down"


# ===========================================================================
# 4. Cross-Device Topology & Exposure Analysis
# ===========================================================================

def test_cross_device_exposure_analysis():
    devices = [
        {
            "id": "dev-fw",
            "ip": "192.168.1.1",
            "hostname": "EDGE-FW-01",
            "device_type": "Firewall",
            "vendor": "Fortinet",
            "status": "AUDITED",
            "latest_analysis": {"compliance_score": 90.0, "findings": []},
        },
        {
            "id": "dev-sw",
            "ip": "192.168.1.10",
            "hostname": "DIST-SW-01",
            "device_type": "Switch",
            "vendor": "Cisco",
            "status": "AUDITED",
            "latest_analysis": {
                "compliance_score": 60.0,
                "findings": [
                    {"control_id": "CIS-4.1-TELNET", "status": "FAIL", "severity": "high"},
                ],
            },
        },
    ]

    result = analyze_cross_device_exposure(devices)
    assert len(result.nodes) == 2
    assert len(result.edges) >= 1
    assert len(result.exposure_vectors) >= 1
    assert "Compound" in result.exposure_vectors[0].title


# ===========================================================================
# 5. Network Audit API Integration
# ===========================================================================

def test_api_network_discovery_demo():
    resp = client.post(
        "/api/network/discover",
        json={"cidr": "192.168.1.0/24", "is_demo": True},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "COMPLETED"
    assert data["hosts_found"] >= 5
    assert any(d["vendor"] == "Cisco" for d in data["devices"])
    assert any(d["vendor"] == "Fortinet" for d in data["devices"])


def test_api_network_list_devices():
    resp = client.get("/api/network/devices")
    assert resp.status_code == 200
    data = resp.json()
    assert "total" in data
    assert "devices" in data


def test_api_network_authenticate_demo():
    resp = client.post(
        "/api/network/authenticate",
        json={"device_id": "dev-demo-rtr-01", "username": "admin", "password": "safe", "is_demo": True},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "AUTHENTICATED"


def test_api_network_audit_device():
    resp = client.post(
        "/api/network/audit-device",
        json={"device_id": "dev-demo-rtr-01", "is_demo": True},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "AUDITED"
    assert data["compliance_score"] > 0
    assert "findings" in data["analysis"]


def test_api_network_topology():
    resp = client.get("/api/network/topology")
    assert resp.status_code == 200
    data = resp.json()
    assert "nodes" in data
    assert "edges" in data
    assert "systemic_risk_score" in data
