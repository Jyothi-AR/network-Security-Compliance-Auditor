"""
Unit tests for intelligence modules:
  - Attack-Path Intelligence
  - Blast-Radius Analysis
  - Root-Cause Analysis
  - Safe Remediation Validation
  - ISO 27001 framework
  - Adaptive Learning mapping store
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from sih26155.api.main import app
from sih26155.intelligence.attack_path import AttackPathEngine
from sih26155.intelligence.blast_radius import BlastRadiusAnalyser, DeviceTopology
from sih26155.intelligence.root_cause import RootCauseAnalyser
from sih26155.intelligence.safe_remediation import SafeRemediationValidator

client = TestClient(app)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(control_id: str, status: str = "FAIL"):
    m = MagicMock()
    m.control_id = control_id
    m.status = status
    return m


# ===========================================================================
# 1. Attack-Path Intelligence
# ===========================================================================

class TestAttackPathEngine:

    def test_identifies_unencrypted_mgmt_path(self):
        engine = AttackPathEngine()
        paths = engine.analyse({
            "router-1": [
                _finding("SSH-001"),
                _finding("SSH-002"),
            ]
        })
        assert len(paths) == 1
        step_ids = [s.step_id for s in paths[0].steps]
        assert "UNENCRYPTED_MGMT" in step_ids

    def test_risk_score_nonzero(self):
        engine = AttackPathEngine()
        paths = engine.analyse({"fw-1": [_finding("AUTH-001"), _finding("AUTH-002")]})
        assert paths[0].risk_score > 0

    def test_no_failures_produces_no_paths(self):
        engine = AttackPathEngine()
        paths = engine.analyse({"sw-1": [_finding("SSH-001", "PASS")]})
        assert paths == []

    def test_lateral_movement_flagged(self):
        engine = AttackPathEngine()
        paths = engine.analyse({"r-1": [_finding("SSH-001"), _finding("ACL-001")]})
        assert any(s.lateral_movement for p in paths for s in p.steps)

    def test_api_attack_paths(self):
        resp = client.post("/api/intelligence/attack-paths", json={
            "device_findings": {
                "router-1": [
                    {"control_id": "SSH-001", "status": "FAIL"},
                    {"control_id": "LOG-001", "status": "FAIL"},
                ]
            }
        })
        assert resp.status_code == 200
        assert "attack_paths" in resp.json()


# ===========================================================================
# 2. Blast-Radius Analysis
# ===========================================================================

class TestBlastRadiusAnalyser:

    def _topo(self):
        return DeviceTopology(
            device_segments={
                "fw-1": ["dmz", "lan"],
                "router-1": ["lan", "wan"],
                "server-1": ["dmz"],
            },
            device_acl_status={
                "fw-1": True,
                "router-1": False,
                "server-1": False,
            },
        )

    def test_exposed_devices_identified(self):
        analyser = BlastRadiusAnalyser(self._topo())
        result = analyser.analyse("fw-1")
        # router-1 and server-1 share segments with fw-1
        all_affected = result.exposed_devices + result.partially_exposed_devices
        assert len(all_affected) > 0

    def test_risk_score_scales_with_exposure(self):
        analyser = BlastRadiusAnalyser(self._topo())
        r = analyser.analyse("fw-1")
        assert 0 <= r.risk_score <= 10

    def test_isolated_device_low_risk(self):
        topo = DeviceTopology(
            device_segments={"isolated": ["mgmt"]},
            device_acl_status={"isolated": True},
        )
        analyser = BlastRadiusAnalyser(topo)
        r = analyser.analyse("isolated")
        assert r.exposed_devices == []
        assert r.risk_score <= 1.0  # minimal: only segment weight, no co-resident devices

    def test_api_blast_radius(self):
        resp = client.post("/api/intelligence/blast-radius", json={
            "source_devices": ["fw-1"],
            "device_segments": {
                "fw-1": ["lan"],
                "pc-1": ["lan"],
            },
            "device_acl_status": {"pc-1": False},
        })
        assert resp.status_code == 200
        assert "blast_radius" in resp.json()


# ===========================================================================
# 3. Root-Cause Analysis
# ===========================================================================

class TestRootCauseAnalyser:

    def test_exact_match_rca(self):
        analyser = RootCauseAnalyser()
        results = analyser.analyse(["SSH-001", "SSH-002"])
        assert any(r.rule_id == "RCA-001" for r in results)

    def test_partial_match_flagged(self):
        analyser = RootCauseAnalyser()
        results = analyser.analyse(["AUTH-001"])  # only 1 of 2 triggers
        partial_ids = [r.rule_id for r in results]
        assert any("PARTIAL" in rid for rid in partial_ids)

    def test_no_match_returns_empty(self):
        analyser = RootCauseAnalyser()
        results = analyser.analyse(["COMPLETELY-UNKNOWN-001"])
        assert results == []

    def test_api_root_cause(self):
        resp = client.post("/api/intelligence/root-cause", json={
            "failing_control_ids": ["SSH-001", "SSH-002", "AUTH-001", "AUTH-002"]
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "root_causes" in data
        assert len(data["root_causes"]) > 0


# ===========================================================================
# 4. Safe Remediation Validation
# ===========================================================================

class TestSafeRemediationValidator:

    def test_blocked_dangerous_command(self):
        v = SafeRemediationValidator()
        report = v.validate_single("TEST-001", "reload")
        assert report.risk_level == "BLOCKED"
        assert not report.is_safe

    def test_safe_command(self):
        v = SafeRemediationValidator()
        report = v.validate_single("SSH-001", "ip ssh version 2")
        assert report.risk_level in ("SAFE", "LOW", "MEDIUM")

    def test_side_effect_detected(self):
        v = SafeRemediationValidator()
        report = v.validate_single("SSH-001", "ip ssh version 2")
        assert len(report.side_effects) > 0

    def test_rollback_provided(self):
        v = SafeRemediationValidator()
        report = v.validate_single("TEL-001", "transport input ssh")
        assert report.rollback_command != ""

    def test_batch_overall_safe(self):
        v = SafeRemediationValidator()
        reports = v.validate_batch([
            {"control_id": "SSH-001", "command": "ip ssh version 2"},
            {"control_id": "LOG-001", "command": "logging 192.168.1.100"},
        ])
        assert all(r.risk_level != "BLOCKED" for r in reports)

    def test_batch_blocked_counted(self):
        v = SafeRemediationValidator()
        reports = v.validate_batch([
            {"control_id": "BAD-001", "command": "write erase"},
        ])
        assert any(r.risk_level == "BLOCKED" for r in reports)

    def test_api_safe_remediation(self):
        resp = client.post("/api/intelligence/safe-remediation", json={
            "remediations": [
                {"control_id": "SSH-001", "command": "ip ssh version 2"},
                {"control_id": "DANGER-001", "command": "reload"},
            ],
            "current_baseline": {"ssh_version": 1},
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["blocked_count"] == 1
        assert not data["overall_safe"]


# ===========================================================================
# 5. ISO 27001 Framework
# ===========================================================================

class TestISO27001Framework:

    def test_policy_builds(self):
        from sih26155.compliance.frameworks.iso27001 import build_iso27001_policy
        policy = build_iso27001_policy()
        assert policy.name == "ISO/IEC 27001:2022"
        assert len(policy.rules) > 0

    def test_all_rules_have_control_ids(self):
        from sih26155.compliance.frameworks.iso27001 import build_iso27001_policy
        policy = build_iso27001_policy()
        for rule in policy.rules:
            assert rule.control_id.startswith("ISO27001-")


# ===========================================================================
# 6. Adaptive Learning API
# ===========================================================================

class TestAdaptiveLearningAPI:

    def test_register_and_list_vendor(self):
        resp = client.post("/api/learning/vendors", json={
            "vendor_id": "test_vyos",
            "display_name": "VyOS",
            "signatures": ["set system host-name", "set interfaces ethernet"],
            "field_mappings": {"ssh_enabled": "set service ssh"},
        })
        assert resp.status_code == 200
        assert resp.json()["vendor_id"] == "test_vyos"

        list_resp = client.get("/api/learning/vendors")
        assert list_resp.status_code == 200
        vendor_ids = [v["vendor_id"] for v in list_resp.json()["vendors"]]
        assert "test_vyos" in vendor_ids

    def test_get_specific_vendor(self):
        client.post("/api/learning/vendors", json={
            "vendor_id": "test_sonic",
            "display_name": "SONiC OS",
            "signatures": ["sonic-cfggen", "DEVICE_METADATA"],
        })
        resp = client.get("/api/learning/vendors/test_sonic")
        assert resp.status_code == 200
        assert resp.json()["display_name"] == "SONiC OS"

    def test_get_nonexistent_vendor_returns_404(self):
        resp = client.get("/api/learning/vendors/does_not_exist_xyz")
        assert resp.status_code == 404

    def test_delete_vendor(self):
        client.post("/api/learning/vendors", json={
            "vendor_id": "test_delete_me",
            "display_name": "Delete Me",
            "signatures": ["delete-sig"],
        })
        del_resp = client.delete("/api/learning/vendors/test_delete_me")
        assert del_resp.status_code == 200
        assert del_resp.json()["status"] == "deleted"

    def test_delete_nonexistent_returns_404(self):
        resp = client.delete("/api/learning/vendors/no_such_vendor_xyz")
        assert resp.status_code == 404
