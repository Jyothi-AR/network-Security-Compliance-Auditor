"""
AI-Assisted Remediation & Auto-Fix API Routes.

Endpoints for:
1. Proposing structured, safe remediations for findings (uploaded or live).
2. Generating downloadable offline corrected configs with non-production disclaimers.
3. Executing live approved remediations with precondition checks, backups, and re-audit verification.
4. One-click rollback to pre-change backups.
5. Querying immutable remediation audit logs.
"""

from __future__ import annotations

from typing import Any
import uuid

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from sih26155.core.pipeline.analyze import analyze_config
from sih26155.remediation.engine import RemediationEngine
from sih26155.storage.database import get_db
from sih26155.storage.repositories import (
    DiscoveredDeviceRepository,
    RemediationAuditRepository,
)


router = APIRouter(
    prefix="/api/remediation",
    tags=["remediation-auto-fix"],
)


# ===========================================================================
# Request & Response Schemas
# ===========================================================================

class GenerateProposalsRequest(BaseModel):
    vendor: str = Field("cisco", description="Device vendor (cisco, fortinet, etc.)")
    raw_config: str = Field(..., description="Raw running configuration text")
    findings: list[dict[str, Any]] = Field(default_factory=list)
    baseline: dict[str, Any] | None = None
    target_type: str = Field("upload", description="'upload' or 'live_device'")
    target_id: str = Field("config.conf", description="Device ID or filename")


class DownloadConfigRequest(BaseModel):
    vendor: str = "cisco"
    raw_config: str
    selected_control_ids: list[str] = Field(default_factory=list)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    source_name: str = "remediated_config.conf"


class LiveApplyRequest(BaseModel):
    device_id: str
    control_id: str
    approved: bool = Field(True, description="Explicit operator approval required")
    approved_by: str = Field("Security Administrator", description="Username or role of operator")
    is_demo: bool = False
    # Optional inline fields — used when the device is an SSH/demo device not yet in the discovered_devices table
    raw_config: str | None = Field(None, description="Raw config text (pass for SSH/demo devices not in DB)")
    vendor: str | None = Field(None, description="Vendor override (e.g. 'cisco') when device not in DB")
    hostname: str | None = Field(None, description="Hostname override when device not in DB")


class LiveRollbackRequest(BaseModel):
    audit_record_id: str | None = None
    device_id: str
    approved_by: str = "Security Administrator"


# ===========================================================================
# Endpoints
# ===========================================================================

@router.post("/proposals", summary="Generate structured remediation proposals for findings")
def get_remediation_proposals(req: GenerateProposalsRequest):
    proposals = RemediationEngine.generate_proposals(
        vendor=req.vendor,
        raw_config=req.raw_config,
        findings=req.findings,
        baseline=req.baseline,
        target_type=req.target_type,
        target_id=req.target_id,
    )
    return {
        "vendor": req.vendor,
        "target_type": req.target_type,
        "target_id": req.target_id,
        "total_proposals": len(proposals),
        "auto_applicable_count": sum(1 for p in proposals if p.auto_applicable),
        "proposals": [p.to_dict() for p in proposals],
    }


@router.post("/download-config", summary="Generate offline corrected configuration for download")
def download_corrected_config(req: DownloadConfigRequest):
    """
    Applies approved fixes to the uploaded configuration and prepends
    clear disclaimers that physical hardware was NOT touched.
    """
    proposals = RemediationEngine.generate_proposals(
        vendor=req.vendor,
        raw_config=req.raw_config,
        findings=req.findings,
        target_type="upload",
        target_id=req.source_name,
    )

    filtered_proposals = [
        p for p in proposals
        if not req.selected_control_ids or p.control_id in req.selected_control_ids
    ]

    full_remediated_text = RemediationEngine.generate_full_remediated_config(
        vendor=req.vendor,
        raw_config=req.raw_config,
        proposals=filtered_proposals,
        source_name=req.source_name,
    )

    return {
        "filename": f"remediated_{req.source_name}",
        "vendor": req.vendor,
        "remediated_controls": [p.control_id for p in filtered_proposals if p.auto_applicable],
        "content": full_remediated_text,
    }


@router.post("/live/apply", summary="Apply approved live remediation with pre-check, backup & verification")
def apply_live_remediation(req: LiveApplyRequest):
    if not req.approved:
        raise HTTPException(
            status_code=400,
            detail="Explicit operator approval is strictly required before applying live changes.",
        )

    with get_db() as db:
        dev_repo = DiscoveredDeviceRepository(db)
        audit_repo = RemediationAuditRepository(db)

        dev = dev_repo.get_by_id(req.device_id)

        # Auto-upsert: SSH / demo devices may not be in DB yet — create a record on the fly
        if not dev:
            if not req.raw_config:
                raise HTTPException(
                    status_code=404,
                    detail=f"Device {req.device_id} not found in inventory. Pass 'raw_config' to register it on-the-fly.",
                )
            dev = dev_repo.upsert({
                "id": req.device_id,
                "ip": req.hostname or req.device_id,
                "hostname": req.hostname or req.device_id,
                "vendor": req.vendor or "cisco",
                "device_type": "Network Device",
                "status": "AUTHENTICATED",
                "is_demo": req.is_demo,
                "raw_config": req.raw_config,
            })

        # Use inline raw_config if provided (e.g. live SSH devices pass their current running config)
        raw_config = req.raw_config or dev.raw_config
        if not raw_config:
            raise HTTPException(status_code=400, detail="Device has no collected configuration to remediate.")

        # Calculate before score
        before_analysis = dev.latest_analysis or {}
        before_score = before_analysis.get("compliance_score", 0.0)

        # Run live remediation pipeline
        result = RemediationEngine.execute_live_remediation_workflow(
            vendor=req.vendor or dev.vendor,
            device_id=dev.id,
            hostname=req.hostname or dev.hostname or dev.ip,
            control_id=req.control_id,
            raw_config=raw_config,
            approved_by=req.approved_by,
            is_demo=req.is_demo or dev.is_demo,
        )

        if result.get("status") == "ABORTED_PRECONDITION_FAILED":
            return {
                "success": False,
                "status": "ABORTED_PRECONDITION_FAILED",
                "message": result.get("error"),
                "preconditions": result.get("preconditions"),
            }

        # If successfully applied or verified, update DB record
        if result.get("resolved") or result.get("status") == "RESOLVED":
            dev.raw_config = result["updated_config"]
            dev.latest_analysis = result["re_audit_analysis"]
            dev.status = "AUDITED"
            db.flush()

        # Save immutable audit record
        audit_rec = audit_repo.record_action({
            "device_id": dev.id,
            "hostname": dev.hostname or dev.ip,
            "control_id": req.control_id,
            "vendor": dev.vendor,
            "commands_applied": result.get("commands_applied", []),
            "rollback_commands": result.get("rollback_commands", []),
            "backup_snapshot_id": result.get("backup_snapshot_id", ""),
            "backup_config": result.get("backup_config"),
            "updated_config": result.get("updated_config"),
            "diff": result.get("diff"),
            "status": result.get("status"),
            "resolved": result.get("resolved", False),
            "before_score": before_score,
            "after_score": result.get("new_compliance_score", 0.0),
            "approved_by": req.approved_by,
        })

        return {
            "success": result.get("resolved", False),
            "audit_record_id": audit_rec.id,
            "status": result.get("status"),
            "resolved": result.get("resolved"),
            "control_id": req.control_id,
            "device_id": dev.id,
            "hostname": dev.hostname or dev.ip,
            "commands_applied": result.get("commands_applied", []),
            "rollback_commands": result.get("rollback_commands", []),
            "backup_snapshot_id": result.get("backup_snapshot_id"),
            "diff": result.get("diff"),
            "before_score": before_score,
            "new_compliance_score": result.get("new_compliance_score"),
            "message": (
                f"Fix verified: Control {req.control_id} is now COMPLIANT. Post-audit score increased from {before_score}% to {result.get('new_compliance_score')}%."
                if result.get("resolved")
                else f"Fix was pushed but re-audit verification failed for {req.control_id}."
            ),
        }


@router.post("/live/rollback", summary="Rollback a live device to its pre-change backup snapshot")
def rollback_live_device(req: LiveRollbackRequest):
    with get_db() as db:
        dev_repo = DiscoveredDeviceRepository(db)
        audit_repo = RemediationAuditRepository(db)

        dev = dev_repo.get_by_id(req.device_id)
        if not dev:
            raise HTTPException(status_code=404, detail="Device not found")

        # Find backup from audit record
        audit_rec = None
        if req.audit_record_id:
            audit_rec = audit_repo.get_by_id(req.audit_record_id)

        if not audit_rec or not audit_rec.backup_config:
            # Look up latest audit record for device
            records = [r for r in audit_repo.list_all(50) if r.device_id == dev.id and r.backup_config]
            if records:
                audit_rec = records[0]

        if not audit_rec or not audit_rec.backup_config:
            raise HTTPException(status_code=400, detail="No pre-change backup found for this device")

        # Restore configuration
        restored_config = audit_rec.backup_config
        re_audit = analyze_config(
            config=restored_config,
            source_file=f"rollback:{dev.hostname or dev.ip}",
        )
        re_audit_dict = re_audit.to_dict()

        findings = re_audit_dict.get("findings", [])
        total = len(findings)
        passed = sum(1 for f in findings if f.get("status") == "PASS")
        restored_score = round((passed / total * 100) if total else 0.0, 2)
        re_audit_dict["compliance_score"] = restored_score

        dev.raw_config = restored_config
        dev.latest_analysis = re_audit_dict
        db.flush()

        # Log rollback
        audit_repo.record_action({
            "device_id": dev.id,
            "hostname": dev.hostname or dev.ip,
            "control_id": f"ROLLBACK-{audit_rec.control_id}",
            "vendor": dev.vendor,
            "commands_applied": audit_rec.rollback_commands or ["RESTORE_BACKUP_IMAGE"],
            "rollback_commands": [],
            "backup_snapshot_id": f"restored-from-{audit_rec.backup_snapshot_id}",
            "backup_config": dev.raw_config,
            "updated_config": restored_config,
            "status": "ROLLED_BACK",
            "resolved": False,
            "before_score": dev.latest_analysis.get("compliance_score", 0.0) if dev.latest_analysis else 0.0,
            "after_score": restored_score,
            "approved_by": req.approved_by,
        })

        return {
            "success": True,
            "status": "ROLLED_BACK",
            "device_id": dev.id,
            "hostname": dev.hostname or dev.ip,
            "restored_snapshot_id": audit_rec.backup_snapshot_id,
            "compliance_score": restored_score,
            "message": f"Successfully rolled back {dev.hostname or dev.ip} to snapshot {audit_rec.backup_snapshot_id}.",
        }


@router.get("/audit-trail", summary="Retrieve complete remediation audit history")
def get_remediation_audit_trail(limit: int = 50):
    with get_db() as db:
        repo = RemediationAuditRepository(db)
        records = repo.list_all(limit=limit)
        return {
            "total": len(records),
            "records": [
                {
                    "id": r.id,
                    "device_id": r.device_id,
                    "hostname": r.hostname,
                    "control_id": r.control_id,
                    "vendor": r.vendor,
                    "commands_applied": r.commands_applied or [],
                    "rollback_commands": r.rollback_commands or [],
                    "backup_snapshot_id": r.backup_snapshot_id,
                    "status": r.status,
                    "resolved": r.resolved,
                    "before_score": r.before_score,
                    "after_score": r.after_score,
                    "approved_by": r.approved_by,
                    "has_diff": bool(r.diff),
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                }
                for r in records
            ],
        }
