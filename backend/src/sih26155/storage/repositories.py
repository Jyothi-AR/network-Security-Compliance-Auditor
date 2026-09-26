"""
ORM models and repository classes for the compliance engine.

Tables
------
devices          - One row per device (hostname + vendor).
config_snapshots - Raw config text captured per device per timestamp.
analyses         - Full analysis result (findings, remediations, risk score).
findings         - Individual compliance findings linked to an analysis.

Repository classes provide a clean CRUD API; no SQL leaks outside this module.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
    select,
)
from sqlalchemy.orm import Mapped, Session, mapped_column, relationship

from sih26155.storage.database import Base


# ===========================================================================
# ORM Models
# ===========================================================================

class Device(Base):
    """A network device whose configurations are tracked over time."""

    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    hostname: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    vendor: Mapped[str] = mapped_column(String(100), nullable=False, default="unknown")
    device_type: Mapped[str] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    snapshots: Mapped[list["ConfigSnapshot"]] = relationship(
        "ConfigSnapshot", back_populates="device", cascade="all, delete-orphan"
    )
    analyses: Mapped[list["Analysis"]] = relationship(
        "Analysis", back_populates="device", cascade="all, delete-orphan"
    )


class ConfigSnapshot(Base):
    """A point-in-time capture of a device's raw running configuration."""

    __tablename__ = "config_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), nullable=False, index=True)
    raw_config: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(50), default="upload")  # upload | live_ssh | live_napalm
    captured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )

    device: Mapped["Device"] = relationship("Device", back_populates="snapshots")
    analysis: Mapped["Analysis | None"] = relationship(
        "Analysis", back_populates="snapshot", uselist=False
    )


class Analysis(Base):
    """Full compliance analysis result for one config snapshot."""

    __tablename__ = "analyses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), nullable=False, index=True)
    snapshot_id: Mapped[int] = mapped_column(
        ForeignKey("config_snapshots.id"), nullable=True, unique=True
    )
    vendor_detected: Mapped[str] = mapped_column(String(100), nullable=False)
    vendor_confidence: Mapped[float] = mapped_column(Float, default=0.0)
    total_controls: Mapped[int] = mapped_column(Integer, default=0)
    passed_controls: Mapped[int] = mapped_column(Integer, default=0)
    failed_controls: Mapped[int] = mapped_column(Integer, default=0)
    unknown_controls: Mapped[int] = mapped_column(Integer, default=0)
    compliance_score: Mapped[float] = mapped_column(Float, default=0.0)  # 0-100 %
    full_result: Mapped[dict] = mapped_column(JSON, nullable=True)       # entire analysis dict
    analysed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )

    device: Mapped["Device"] = relationship("Device", back_populates="analyses")
    snapshot: Mapped["ConfigSnapshot | None"] = relationship(
        "ConfigSnapshot", back_populates="analysis"
    )
    findings: Mapped[list["Finding"]] = relationship(
        "Finding", back_populates="analysis", cascade="all, delete-orphan"
    )


class Finding(Base):
    """Individual compliance finding within an analysis."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analyses.id"), nullable=False, index=True)
    control_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False)   # PASS | FAIL | UNKNOWN
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")
    description: Mapped[str] = mapped_column(Text, nullable=True)
    observed: Mapped[str] = mapped_column(Text, nullable=True)        # JSON-encoded
    expected: Mapped[str] = mapped_column(Text, nullable=True)        # JSON-encoded

    analysis: Mapped["Analysis"] = relationship("Analysis", back_populates="findings")


# ===========================================================================
# Repository classes
# ===========================================================================

class DeviceRepository:
    """CRUD for Device records."""

    def __init__(self, db: Session) -> None:
        self._db = db

    def get_or_create(self, hostname: str, vendor: str = "unknown", device_type: str = "") -> Device:
        """Return existing device or create a new one."""
        device = self._db.execute(
            select(Device).where(Device.hostname == hostname)
        ).scalar_one_or_none()

        if device is None:
            device = Device(hostname=hostname, vendor=vendor, device_type=device_type)
            self._db.add(device)
            self._db.flush()  # get the ID without committing
        else:
            device.vendor = vendor
            device.device_type = device_type or device.device_type
        return device

    def list_all(self) -> list[Device]:
        return list(self._db.execute(select(Device).order_by(Device.hostname)).scalars())

    def get_by_hostname(self, hostname: str) -> Device | None:
        return self._db.execute(
            select(Device).where(Device.hostname == hostname)
        ).scalar_one_or_none()

    def delete(self, hostname: str) -> bool:
        device = self.get_by_hostname(hostname)
        if device is None:
            return False
        self._db.delete(device)
        return True


class ConfigSnapshotRepository:
    """CRUD for ConfigSnapshot records."""

    def __init__(self, db: Session) -> None:
        self._db = db

    def save(self, device_id: int, raw_config: str, source: str = "upload") -> ConfigSnapshot:
        snap = ConfigSnapshot(device_id=device_id, raw_config=raw_config, source=source)
        self._db.add(snap)
        self._db.flush()
        return snap

    def list_for_device(self, device_id: int, limit: int = 20) -> list[ConfigSnapshot]:
        return list(
            self._db.execute(
                select(ConfigSnapshot)
                .where(ConfigSnapshot.device_id == device_id)
                .order_by(ConfigSnapshot.captured_at.desc())
                .limit(limit)
            ).scalars()
        )

    def latest_two(self, device_id: int) -> list[ConfigSnapshot]:
        return self.list_for_device(device_id, limit=2)


class AnalysisRepository:
    """CRUD for Analysis records."""

    def __init__(self, db: Session) -> None:
        self._db = db

    def save(
        self,
        device_id: int,
        snapshot_id: int | None,
        result_dict: dict[str, Any],
    ) -> Analysis:
        findings_data = result_dict.get("findings", [])
        total = len(findings_data)
        passed = sum(1 for f in findings_data if f.get("status") == "PASS")
        failed = sum(1 for f in findings_data if f.get("status") == "FAIL")
        unknown = total - passed - failed
        score = round((passed / total * 100) if total else 0.0, 2)

        vendor_info = result_dict.get("vendor", {})

        analysis = Analysis(
            device_id=device_id,
            snapshot_id=snapshot_id,
            vendor_detected=vendor_info.get("name", "unknown"),
            vendor_confidence=vendor_info.get("confidence", 0.0),
            total_controls=total,
            passed_controls=passed,
            failed_controls=failed,
            unknown_controls=unknown,
            compliance_score=score,
            full_result=result_dict,
        )
        self._db.add(analysis)
        self._db.flush()

        # Save individual findings
        for f in findings_data:
            finding = Finding(
                analysis_id=analysis.id,
                control_id=f.get("control_id", ""),
                status=f.get("status", "UNKNOWN"),
                severity=f.get("severity", "medium"),
                description=f.get("description", ""),
                observed=json.dumps(f.get("observed")),
                expected=json.dumps(f.get("expected")),
            )
            self._db.add(finding)

        return analysis

    def list_for_device(self, device_id: int, limit: int = 50) -> list[Analysis]:
        return list(
            self._db.execute(
                select(Analysis)
                .where(Analysis.device_id == device_id)
                .order_by(Analysis.analysed_at.desc())
                .limit(limit)
            ).scalars()
        )

    def latest_two(self, device_id: int) -> list[Analysis]:
        return self.list_for_device(device_id, limit=2)

    def get_by_id(self, analysis_id: int) -> Analysis | None:
        return self._db.get(Analysis, analysis_id)
