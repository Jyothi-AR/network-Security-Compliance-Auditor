"""
Intelligence API routes.

POST /api/intelligence/attack-paths
    Analyse findings across devices for attack paths.

POST /api/intelligence/blast-radius
    Calculate blast radius of a compromised device.

POST /api/intelligence/root-cause
    Correlate failing controls to root causes.

POST /api/intelligence/safe-remediation
    Validate remediation commands for safety before deployment.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from sih26155.intelligence import (
    AttackPathEngine,
    BlastRadiusAnalyser,
    DeviceTopology,
    RemediationSafetyReport,
    RootCauseAnalyser,
    SafeRemediationValidator,
)

router = APIRouter(prefix="/api/intelligence", tags=["intelligence"])


# ---------------------------------------------------------------------------
# Attack-Path Intelligence
# ---------------------------------------------------------------------------

class DeviceFindingsInput(BaseModel):
    device_findings: dict[str, list[dict[str, Any]]] = Field(
        description="Map of device_name -> list of finding dicts (must have control_id and status)."
    )


class _FakeFinding:
    def __init__(self, d: dict) -> None:
        self.control_id = d.get("control_id", "")
        self.status = d.get("status", "UNKNOWN")


@router.post("/attack-paths", summary="Identify attack paths from compliance findings")
def attack_paths(body: DeviceFindingsInput) -> dict[str, Any]:
    engine = AttackPathEngine()
    device_findings = {
        device: [_FakeFinding(f) for f in findings]
        for device, findings in body.device_findings.items()
    }
    paths = engine.analyse(device_findings)
    return {
        "attack_paths": [
            {
                "path_id": p.path_id,
                "risk_score": p.risk_score,
                "summary": p.summary,
                "steps": [
                    {
                        "step_id": s.step_id,
                        "device": s.device,
                        "technique": s.technique,
                        "description": s.description,
                        "severity": s.severity,
                        "triggering_controls": s.triggering_controls,
                        "lateral_movement": s.lateral_movement,
                        "privilege_escalation": s.privilege_escalation,
                    }
                    for s in p.steps
                ],
            }
            for p in paths
        ]
    }


# ---------------------------------------------------------------------------
# Blast-Radius Analysis
# ---------------------------------------------------------------------------

class BlastRadiusRequest(BaseModel):
    source_devices: list[str] = Field(description="Device(s) that are compromised / failing.")
    device_segments: dict[str, list[str]] = Field(
        description="Map of device_name -> list of network segments."
    )
    device_acl_status: dict[str, bool] = Field(
        default_factory=dict,
        description="Map of device_name -> True if ACL/zone policy exists.",
    )


@router.post("/blast-radius", summary="Calculate blast radius of compromised device(s)")
def blast_radius(body: BlastRadiusRequest) -> dict[str, Any]:
    topo = DeviceTopology(
        device_segments=body.device_segments,
        device_acl_status=body.device_acl_status,
    )
    analyser = BlastRadiusAnalyser(topology=topo)
    results = analyser.analyse_multi(body.source_devices)
    return {
        "blast_radius": [
            {
                "source_device": r.source_device,
                "affected_segments": r.affected_segments,
                "exposed_devices": r.exposed_devices,
                "partially_exposed_devices": r.partially_exposed_devices,
                "risk_score": r.risk_score,
                "summary": r.summary,
            }
            for r in results
        ]
    }


# ---------------------------------------------------------------------------
# Root-Cause Analysis
# ---------------------------------------------------------------------------

class RootCauseRequest(BaseModel):
    failing_control_ids: list[str] = Field(
        description="List of control IDs with status FAIL."
    )


@router.post("/root-cause", summary="Correlate failing controls to root causes")
def root_cause(body: RootCauseRequest) -> dict[str, Any]:
    analyser = RootCauseAnalyser()
    results = analyser.analyse(body.failing_control_ids)
    return {
        "root_causes": [
            {
                "rule_id": r.rule_id,
                "matched_controls": r.matched_controls,
                "root_cause": r.root_cause,
                "corrective_action": r.corrective_action,
                "category": r.category,
            }
            for r in results
        ]
    }


# ---------------------------------------------------------------------------
# Safe Remediation Validation
# ---------------------------------------------------------------------------

class RemediationItem(BaseModel):
    control_id: str
    command: str


class SafeRemediationRequest(BaseModel):
    remediations: list[RemediationItem]
    current_baseline: dict[str, Any] = Field(default_factory=dict)


@router.post("/safe-remediation", summary="Validate remediation commands for safety before deployment")
def safe_remediation(body: SafeRemediationRequest) -> dict[str, Any]:
    validator = SafeRemediationValidator()
    reports = validator.validate_batch(
        remediations=[r.model_dump() for r in body.remediations],
        current_baseline=body.current_baseline or None,
    )
    return {
        "validation_reports": [
            {
                "control_id": r.control_id,
                "command": r.command,
                "is_safe": r.is_safe,
                "risk_level": r.risk_level,
                "warnings": r.warnings,
                "conflicts": r.conflicts,
                "side_effects": r.side_effects,
                "rollback_command": r.rollback_command,
                "recommendation": r.recommendation,
            }
            for r in reports
        ],
        "overall_safe": all(r.is_safe for r in reports),
        "blocked_count": sum(1 for r in reports if r.risk_level == "BLOCKED"),
        "high_risk_count": sum(1 for r in reports if r.risk_level == "HIGH"),
    }
