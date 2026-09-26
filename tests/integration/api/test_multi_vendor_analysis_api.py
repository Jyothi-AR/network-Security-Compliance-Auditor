from fastapi.testclient import TestClient

from sih26155.api.main import app

client = TestClient(app)


def test_api_analysis_cisco():
    config = "hostname CISCO-CORE-01\nip ssh version 2\nno ip http server\n"
    response = client.post(
        "/api/analysis",
        json={"config": config, "source_file": "cisco.conf"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["vendor"]["name"] == "cisco"
    assert data["baseline"]["device"]["hostname"] == "CISCO-CORE-01"


def test_api_analysis_juniper():
    config = """\
set system host-name JUNIPER-MX
set system services ssh protocol-version v2
set system services telnet
set interfaces ge-0/0/0 unit 0 family inet
"""
    response = client.post(
        "/api/analysis",
        json={"config": config, "source_file": "juniper.conf"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["vendor"]["name"] == "juniper"
    assert data["baseline"]["device"]["hostname"] == "JUNIPER-MX"


def test_api_analysis_paloalto():
    config = """\
set deviceconfig system hostname PAN-FIREWALL
set deviceconfig system service disable-http yes
set shared log-settings syslog SYSLOG-SERVER
"""
    response = client.post(
        "/api/analysis",
        json={"config": config, "source_file": "paloalto.conf"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["vendor"]["name"] == "paloalto"
    assert data["baseline"]["device"]["hostname"] == "PAN-FIREWALL"
