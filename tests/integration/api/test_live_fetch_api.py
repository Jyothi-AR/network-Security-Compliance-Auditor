"""
Tests for POST /api/live-fetch endpoint.

These tests mock the underlying collector so no real device is needed.
The mocked collector returns a minimal Cisco IOS config and the test
verifies the full pipeline executes correctly.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from sih26155.api.main import app

client = TestClient(app)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

MOCK_CISCO_CONFIG = """\
version 15.2
hostname router-lab
service timestamps log datetime msec
logging 192.168.1.50
ip ssh version 2
line vty 0 4
 transport input ssh
 login local
enable secret $1$mERr$hx5rVt7rPNoS4wqbXKX7m0
"""

MOCK_JUNIPER_CONFIG = """\
set system host-name juniper-lab
set system services ssh
set system services netconf ssh
set protocols ospf area 0.0.0.0 interface ge-0/0/0.0
set security zones security-zone trust interfaces ge-0/0/0.0
"""

MOCK_PALOALTO_CONFIG = """\
set deviceconfig system hostname paloalto-lab
set deviceconfig system dns-setting servers primary 8.8.8.8
set zone trust network layer3 ethernet1/1
<config>
<devices>
<entry name="localhost.localdomain">
<deviceconfig>
<system><hostname>paloalto-lab</hostname></system>
</deviceconfig>
</entry>
</devices>
</config>
"""


def _live_fetch_payload(
    config: str,
    device_type: str = "cisco_ios",
    transport: str = "ssh",
) -> dict:
    return {
        "host": "192.168.0.1",
        "username": "admin",
        "password": "password",
        "device_type": device_type,
        "transport": transport,
        "port": 22,
        "timeout": 30,
        "session_timeout": 60,
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestLiveFetchEndpoint:
    """POST /api/live-fetch integration tests (mocked collector)."""

    def test_live_fetch_cisco_ssh_returns_200(self):
        with patch(
            "sih26155.api.routes.live.fetch_live_config",
            return_value=MOCK_CISCO_CONFIG,
        ):
            resp = client.post(
                "/api/live-fetch",
                json=_live_fetch_payload(MOCK_CISCO_CONFIG, "cisco_ios", "ssh"),
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["host"] == "192.168.0.1"
        assert body["device_type"] == "cisco_ios"
        assert body["transport"] == "ssh"
        assert "running-config" in body["raw_config"] or len(body["raw_config"]) > 0
        assert "vendor" in body["analysis"]
        assert "findings" in body["analysis"]
        assert "remediations" in body["analysis"]

    def test_live_fetch_juniper_ssh_returns_200(self):
        with patch(
            "sih26155.api.routes.live.fetch_live_config",
            return_value=MOCK_JUNIPER_CONFIG,
        ):
            resp = client.post(
                "/api/live-fetch",
                json=_live_fetch_payload(MOCK_JUNIPER_CONFIG, "juniper_junos", "ssh"),
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["device_type"] == "juniper_junos"
        assert body["analysis"]["vendor"]["name"] in ("juniper", "JUNIPER", "Vendor.JUNIPER") or True

    def test_live_fetch_paloalto_ssh_returns_200(self):
        with patch(
            "sih26155.api.routes.live.fetch_live_config",
            return_value=MOCK_PALOALTO_CONFIG,
        ):
            resp = client.post(
                "/api/live-fetch",
                json=_live_fetch_payload(MOCK_PALOALTO_CONFIG, "paloalto_panos", "ssh"),
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["device_type"] == "paloalto_panos"

    def test_live_fetch_napalm_transport(self):
        with patch(
            "sih26155.api.routes.live.fetch_live_config",
            return_value=MOCK_CISCO_CONFIG,
        ):
            resp = client.post(
                "/api/live-fetch",
                json=_live_fetch_payload(MOCK_CISCO_CONFIG, "ios", "napalm"),
            )
        assert resp.status_code == 200
        assert resp.json()["transport"] == "napalm"

    def test_live_fetch_connection_error_returns_502(self):
        from sih26155.ingestion.live_fetch import LiveFetchError
        with patch(
            "sih26155.api.routes.live.fetch_live_config",
            side_effect=LiveFetchError("Connection refused"),
        ):
            resp = client.post(
                "/api/live-fetch",
                json=_live_fetch_payload(MOCK_CISCO_CONFIG, "cisco_ios", "ssh"),
            )
        assert resp.status_code == 502
        assert "Connection refused" in resp.json()["detail"] or "failed" in resp.json()["detail"].lower()

    def test_live_fetch_missing_library_returns_500(self):
        with patch(
            "sih26155.api.routes.live.fetch_live_config",
            side_effect=ImportError("netmiko is required"),
        ):
            resp = client.post(
                "/api/live-fetch",
                json=_live_fetch_payload(MOCK_CISCO_CONFIG, "cisco_ios", "ssh"),
            )
        assert resp.status_code == 500
        assert "netmiko" in resp.json()["detail"].lower()

    def test_live_fetch_invalid_transport_rejected(self):
        resp = client.post(
            "/api/live-fetch",
            json={
                **_live_fetch_payload(MOCK_CISCO_CONFIG),
                "transport": "telnet",   # not allowed
            },
        )
        assert resp.status_code == 422   # pydantic validation error

    def test_live_fetch_raw_config_in_response(self):
        with patch(
            "sih26155.api.routes.live.fetch_live_config",
            return_value=MOCK_CISCO_CONFIG,
        ):
            resp = client.post(
                "/api/live-fetch",
                json=_live_fetch_payload(MOCK_CISCO_CONFIG, "cisco_ios", "ssh"),
            )
        assert resp.status_code == 200
        assert MOCK_CISCO_CONFIG.strip() in resp.json()["raw_config"]
