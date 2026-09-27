"""
Unit and Integration Tests for AI-Assisted Auto-Fix and Remediation Pipeline.
"""

import pytest
from fastapi.testclient import TestClient

from sih26155.api.main import app
from sih26155.remediation.engine import RemediationEngine
from sih26155.remediation.providers import (
    CiscoRemediationProvider,
    FortinetRemediationProvider,
    JuniperRemediationProvider,
    LinuxRemediationProvider,
    MikroTikRemediationProvider,
    PaloAltoRemediationProvider,
    get_remediation_provider,
)
from sih26155.storage.database import create_all_tables, get_db
from sih26155.storage.repositories import DiscoveredDeviceRepository, RemediationAuditRepository


@pytest.fixture(autouse=True)
def setup_test_db():
    create_all_tables()


@pytest.fixture
def client():
    return TestClient(app)


SAMPLE_CISCO_NON_COMPLIANT = """\
! Cisco IOS Running Configuration
version 15.2
hostname TEST-RTR-01
!
line vty 0 4
 transport input telnet
 login
!
ip http server
end
"""

SAMPLE_CISCO_WITH_SSH = """\
! Cisco IOS Running Configuration
version 15.2
hostname TEST-RTR-01
ip domain-name test.local
ip ssh version 2
!
line vty 0 4
 transport input telnet
 login
!
end
"""


def test_cisco_provider_precondition_telnet_fails_without_ssh():
    provider = CiscoRemediationProvider()
    checks = provider.check_preconditions("MGMT-TELNET-001", SAMPLE_CISCO_NON_COMPLIANT)
    assert len(checks) == 1
    assert checks[0].name == "SSH_SERVICE_ACTIVE"
    assert checks[0].passed is False  # Fails because no SSH is configured


def test_cisco_provider_precondition_telnet_passes_with_ssh():
    provider = CiscoRemediationProvider()
    checks = provider.check_preconditions("MGMT-TELNET-001", SAMPLE_CISCO_WITH_SSH)
    assert len(checks) == 1
    assert checks[0].name == "SSH_SERVICE_ACTIVE"
    assert checks[0].passed is True  # Passes because ip ssh version 2 is present


def test_cisco_provider_apply_and_idempotency():
    provider = CiscoRemediationProvider()
    patched = provider.apply_to_config_text(
        SAMPLE_CISCO_WITH_SSH,
        ["line vty 0 4", "transport input ssh"],
        "MGMT-TELNET-001",
    )
    assert "transport input ssh" in patched
    assert "transport input telnet" not in patched
    assert provider.is_already_compliant("MGMT-TELNET-001", patched) is True


def test_all_vendor_providers_instantiation():
    vendors = ["cisco", "fortinet", "juniper", "palo_alto", "mikrotik", "linux"]
    for v in vendors:
        provider = get_remediation_provider(v)
        assert provider is not None
        assert len(provider.rules) > 0


def test_conservative_acl_rules_require_manual_remediation():
    provider = CiscoRemediationProvider()
    acl_rule = provider.rules.get("SEC-ACL-001")
    assert acl_rule is not None
    assert acl_rule.is_conservative is True
    assert acl_rule.risk_level == "MANUAL_ONLY"
    assert "Manual Remediation Required" in acl_rule.manual_guidance


def test_engine_generate_proposals_for_uploaded_config():
    findings = [
        {"control_id": "MGMT-TELNET-001", "status": "FAIL", "description": "Telnet enabled"},
        {"control_id": "MGMT-HTTP-001", "status": "FAIL", "description": "HTTP enabled"},
    ]
    proposals = RemediationEngine.generate_proposals(
        vendor="cisco",
        raw_config=SAMPLE_CISCO_WITH_SSH,
        findings=findings,
        target_type="upload",
        target_id="uploaded_test.cfg",
    )
    assert len(proposals) == 2
    telnet_prop = next(p for p in proposals if p.control_id == "MGMT-TELNET-001")
    assert telnet_prop.auto_applicable is True
    assert len(telnet_prop.unified_diff) > 0
    assert "--- a/uploaded_test.cfg (current)" in telnet_prop.unified_diff


def test_engine_generate_download_file_contains_disclaimer():
    findings = [
        {"control_id": "MGMT-TELNET-001", "status": "FAIL", "description": "Telnet enabled"},
    ]
    proposals = RemediationEngine.generate_proposals(
        vendor="cisco",
        raw_config=SAMPLE_CISCO_WITH_SSH,
        findings=findings,
    )
    download_text = RemediationEngine.generate_full_remediated_config(
        vendor="cisco",
        raw_config=SAMPLE_CISCO_WITH_SSH,
        proposals=proposals,
        source_name="cisco_edge.conf",
    )
    assert "AEGISGUARD AI REMEDIATED CONFIGURATION" in download_text
    assert "THIS IS AN OFFLINE REMEDIATED CONFIGURATION" in download_text or "The physical device has NOT" in download_text
    assert "transport input ssh" in download_text


def test_engine_live_remediation_workflow():
    result = RemediationEngine.execute_live_remediation_workflow(
        vendor="cisco",
        device_id="dev-test-1",
        hostname="CORE-RTR-01",
        control_id="MGMT-TELNET-001",
        raw_config=SAMPLE_CISCO_WITH_SSH,
        approved_by="SecAdmin",
    )
    assert result["status"] == "RESOLVED"
    assert result["resolved"] is True
    assert result["backup_snapshot_id"].startswith("backup-dev-test-1-")
    assert "transport input ssh" in result["updated_config"]
    assert result["new_compliance_score"] > 0


def test_api_remediation_endpoints(client):
    # 1. Propose
    res_prop = client.post(
        "/api/remediation/proposals",
        json={
            "vendor": "cisco",
            "raw_config": SAMPLE_CISCO_WITH_SSH,
            "findings": [
                {"control_id": "MGMT-TELNET-001", "status": "FAIL"},
            ],
            "target_type": "upload",
            "target_id": "rtr.cfg",
        },
    )
    assert res_prop.status_code == 200
    data_prop = res_prop.json()
    assert data_prop["total_proposals"] == 1
    assert data_prop["proposals"][0]["control_id"] == "MGMT-TELNET-001"

    # 2. Download Offline Config
    res_dl = client.post(
        "/api/remediation/download-config",
        json={
            "vendor": "cisco",
            "raw_config": SAMPLE_CISCO_WITH_SSH,
            "findings": [
                {"control_id": "MGMT-TELNET-001", "status": "FAIL"},
            ],
            "source_name": "rtr.cfg",
        },
    )
    assert res_dl.status_code == 200
    data_dl = res_dl.json()
    assert "remediated_rtr.cfg" in data_dl["filename"]
    assert "AEGISGUARD AI REMEDIATED CONFIGURATION" in data_dl["content"]

    # 3. Live Device Application with DB Setup
    with get_db() as db:
        dev_repo = DiscoveredDeviceRepository(db)
        dev_repo.upsert({
            "id": "dev-live-cisco",
            "ip": "10.0.0.1",
            "hostname": "EDGE-CISCO-01",
            "vendor": "Cisco",
            "device_type": "Cisco IOS-XE Gateway",
            "status": "AUTHENTICATED",
            "raw_config": SAMPLE_CISCO_WITH_SSH,
        })

    res_live = client.post(
        "/api/remediation/live/apply",
        json={
            "device_id": "dev-live-cisco",
            "control_id": "MGMT-TELNET-001",
            "approved": True,
            "approved_by": "Lead Network Engineer",
        },
    )
    assert res_live.status_code == 200
    data_live = res_live.json()
    assert data_live["resolved"] is True
    assert data_live["status"] == "RESOLVED"
    audit_id = data_live["audit_record_id"]

    # 4. Audit Trail Verification
    res_trail = client.get("/api/remediation/audit-trail")
    assert res_trail.status_code == 200
    trail = res_trail.json()
    assert trail["total"] >= 1
    assert any(r["id"] == audit_id for r in trail["records"])

    # 5. Rollback Live Device
    res_rb = client.post(
        "/api/remediation/live/rollback",
        json={
            "audit_record_id": audit_id,
            "device_id": "dev-live-cisco",
            "approved_by": "SecAdmin",
        },
    )
    assert res_rb.status_code == 200
    data_rb = res_rb.json()
    assert data_rb["success"] is True
    assert data_rb["status"] == "ROLLED_BACK"
