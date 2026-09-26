"""
Device history and config drift API routes.

GET  /api/history/devices                  - List all tracked devices
GET  /api/history/{hostname}               - Analysis history for a device
GET  /api/history/{hostname}/snapshots     - Config snapshots for a device
GET  /api/history/{hostname}/drift         - Compare last two analyses (drift)
GET  /api/history/{hostname}/latest        - Most recent analysis result
DELETE /api/history/{hostname}             - Remove device + all history
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from sih26155.storage.database import get_db_session
from sih26155.storage.repositories import (
    AnalysisRepository,
    ConfigSnapshotRepository,
    DeviceRepository,
)

router = APIRouter(prefix="/api/history", tags=["history"])


def _analysis_summary(a: Any) -> dict:
    return {
        "analysis_id": a.id,
        "analysed_at": a.analysed_at.isoformat(),
        "vendor_detected": a.vendor_detected,
        "vendor_confidence": a.vendor_confidence,
        "total_controls": a.total_controls,
        "passed_controls": a.passed_controls,
        "failed_controls": a.failed_controls,
        "unknown_controls": a.unknown_controls,
        "compliance_score": a.compliance_score,
    }


# ---------------------------------------------------------------------------
# Devices list
# ---------------------------------------------------------------------------

@router.get("/devices", summary="List all tracked devices")
def list_devices(db: Session = Depends(get_db_session)) -> dict[str, Any]:
    repo = DeviceRepository(db)
    devices = repo.list_all()
    return {
        "devices": [
            {
                "hostname": d.hostname,
                "vendor": d.vendor,
                "device_type": d.device_type,
                "created_at": d.created_at.isoformat(),
                "updated_at": d.updated_at.isoformat(),
            }
            for d in devices
        ]
    }


# ---------------------------------------------------------------------------
# Analysis history
# ---------------------------------------------------------------------------

@router.get("/{hostname}", summary="Analysis history for a device")
def device_history(
    hostname: str,
    limit: int = 20,
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    device = DeviceRepository(db).get_by_hostname(hostname)
    if device is None:
        raise HTTPException(status_code=404, detail=f"Device '{hostname}' not found.")

    analyses = AnalysisRepository(db).list_for_device(device.id, limit=limit)
    return {
        "hostname": hostname,
        "vendor": device.vendor,
        "analyses": [_analysis_summary(a) for a in analyses],
    }


# ---------------------------------------------------------------------------
# Latest analysis
# ---------------------------------------------------------------------------

@router.get("/{hostname}/latest", summary="Most recent full analysis for a device")
def latest_analysis(
    hostname: str,
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    device = DeviceRepository(db).get_by_hostname(hostname)
    if device is None:
        raise HTTPException(status_code=404, detail=f"Device '{hostname}' not found.")

    analyses = AnalysisRepository(db).list_for_device(device.id, limit=1)
    if not analyses:
        raise HTTPException(status_code=404, detail=f"No analyses found for '{hostname}'.")

    latest = analyses[0]
    return {
        "hostname": hostname,
        "summary": _analysis_summary(latest),
        "full_result": latest.full_result,
    }


# ---------------------------------------------------------------------------
# Config snapshots
# ---------------------------------------------------------------------------

@router.get("/{hostname}/snapshots", summary="Config snapshot history for a device")
def config_snapshots(
    hostname: str,
    limit: int = 10,
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    device = DeviceRepository(db).get_by_hostname(hostname)
    if device is None:
        raise HTTPException(status_code=404, detail=f"Device '{hostname}' not found.")

    snaps = ConfigSnapshotRepository(db).list_for_device(device.id, limit=limit)
    return {
        "hostname": hostname,
        "snapshots": [
            {
                "snapshot_id": s.id,
                "source": s.source,
                "captured_at": s.captured_at.isoformat(),
                "config_length": len(s.raw_config),
                "config_preview": s.raw_config[:300] + ("..." if len(s.raw_config) > 300 else ""),
            }
            for s in snaps
        ],
    }


# ---------------------------------------------------------------------------
# Config drift detection
# ---------------------------------------------------------------------------

@router.get("/{hostname}/drift", summary="Detect compliance drift between last two analyses")
def config_drift(
    hostname: str,
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    device = DeviceRepository(db).get_by_hostname(hostname)
    if device is None:
        raise HTTPException(status_code=404, detail=f"Device '{hostname}' not found.")

    analyses = AnalysisRepository(db).latest_two(device.id)
    if len(analyses) < 2:
        return {
            "hostname": hostname,
            "drift_detected": False,
            "message": "Need at least 2 analyses to detect drift.",
            "analyses_available": len(analyses),
        }

    latest, previous = analyses[0], analyses[1]

    # Compare findings
    def _finding_map(analysis: Any) -> dict[str, str]:
        if not analysis.full_result:
            return {}
        return {
            f["control_id"]: f["status"]
            for f in analysis.full_result.get("findings", [])
        }

    latest_map = _finding_map(latest)
    previous_map = _finding_map(previous)

    all_controls = set(latest_map) | set(previous_map)
    newly_failing: list[str] = []
    newly_passing: list[str] = []
    unchanged_fail: list[str] = []
    unchanged_pass: list[str] = []

    for ctrl in sorted(all_controls):
        prev_status = previous_map.get(ctrl, "UNKNOWN")
        curr_status = latest_map.get(ctrl, "UNKNOWN")

        if prev_status != "FAIL" and curr_status == "FAIL":
            newly_failing.append(ctrl)
        elif prev_status == "FAIL" and curr_status != "FAIL":
            newly_passing.append(ctrl)
        elif curr_status == "FAIL":
            unchanged_fail.append(ctrl)
        elif curr_status == "PASS":
            unchanged_pass.append(ctrl)

    score_delta = round(latest.compliance_score - previous.compliance_score, 2)
    drift_detected = bool(newly_failing or newly_passing)

    return {
        "hostname": hostname,
        "drift_detected": drift_detected,
        "latest_analysis": {
            "analysis_id": latest.id,
            "analysed_at": latest.analysed_at.isoformat(),
            "compliance_score": latest.compliance_score,
        },
        "previous_analysis": {
            "analysis_id": previous.id,
            "analysed_at": previous.analysed_at.isoformat(),
            "compliance_score": previous.compliance_score,
        },
        "score_delta": score_delta,
        "newly_failing_controls": newly_failing,
        "newly_passing_controls": newly_passing,
        "persistently_failing": unchanged_fail,
        "persistently_passing": unchanged_pass,
        "summary": (
            f"{len(newly_failing)} control(s) regressed, "
            f"{len(newly_passing)} control(s) improved, "
            f"score delta: {score_delta:+.1f}%"
        ),
    }


# ---------------------------------------------------------------------------
# Delete device history
# ---------------------------------------------------------------------------

@router.delete("/{hostname}", summary="Remove a device and all its history")
def delete_device(
    hostname: str,
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    deleted = DeviceRepository(db).delete(hostname)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Device '{hostname}' not found.")
    return {"status": "deleted", "hostname": hostname}
