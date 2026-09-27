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


# ===========================================================================
# Live Network Discovery & Topology ORM Models
# ===========================================================================

class DiscoveredDeviceRecord(Base):
    """Network device discovered passively or actively over subnet."""

    __tablename__ = "discovered_devices"

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    ip: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    hostname: Mapped[str] = mapped_column(String(255), default="")
    mac_address: Mapped[str] = mapped_column(String(50), default="")
    vendor: Mapped[str] = mapped_column(String(100), default="Unknown")
    device_type: Mapped[str] = mapped_column(String(100), default="Unknown network device")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    reachability: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[str] = mapped_column(
        String(50), default="DISCOVERED"
    )  # DISCOVERED | IDENTIFIED | AUTHENTICATED | AUDITED
    open_ports: Mapped[list] = mapped_column(JSON, default=list)
    banners: Mapped[dict] = mapped_column(JSON, default=dict)
    evidence: Mapped[list] = mapped_column(JSON, default=list)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)
    raw_config: Mapped[str | None] = mapped_column(Text, nullable=True)
    normalized_config: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    latest_analysis: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class DiscoveryJobRecord(Base):
    """Discovery scan execution job tracker."""

    __tablename__ = "discovery_jobs"

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    cidr: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="RUNNING")  # RUNNING | COMPLETED | FAILED
    hosts_found: Mapped[int] = mapped_column(Integer, default=0)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)


class DeviceCredentialReference(Base):
    """Stores credential reference and auth status without persisting plain text secrets."""

    __tablename__ = "device_credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    username: Mapped[str] = mapped_column(String(100), nullable=False)
    auth_type: Mapped[str] = mapped_column(String(50), default="ssh_password")
    port: Mapped[int] = mapped_column(Integer, default=22)
    status: Mapped[str] = mapped_column(String(50), default="UNTESTED")  # VALID | INVALID | UNTESTED
    last_tested: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class NetworkRelationshipRecord(Base):
    """Inter-device relationship for topology and blast-radius graph."""

    __tablename__ = "network_relationships"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source_device_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    target_device_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    relationship_type: Mapped[str] = mapped_column(
        String(50), default="connected_to"
    )  # routed_to | switched_to | firewall_protects | upstream_of
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    details: Mapped[dict] = mapped_column(JSON, default=dict)


# ===========================================================================
# Live Network Repositories
# ===========================================================================

class DiscoveredDeviceRepository:
    """CRUD for DiscoveredDeviceRecord."""

    def __init__(self, db: Session) -> None:
        self._db = db

    def upsert(self, host_dict: dict[str, Any]) -> DiscoveredDeviceRecord:
        dev_id = host_dict.get("id") or f"dev-{host_dict['ip'].replace('.', '-')}"
        record = self._db.get(DiscoveredDeviceRecord, dev_id)
        if record is None:
            record = DiscoveredDeviceRecord(
                id=dev_id,
                ip=host_dict.get("ip", ""),
                hostname=host_dict.get("hostname", ""),
                mac_address=host_dict.get("mac_address", ""),
                vendor=host_dict.get("vendor", "Unknown"),
                device_type=host_dict.get("device_type", "Unknown network device"),
                confidence=host_dict.get("confidence", 0.0),
                reachability=host_dict.get("reachability", True),
                status=host_dict.get("status", "DISCOVERED"),
                open_ports=host_dict.get("open_ports", []),
                banners=host_dict.get("banners", {}),
                evidence=host_dict.get("evidence", []),
                is_demo=host_dict.get("is_demo", False),
                last_seen=datetime.now(timezone.utc),
            )
            self._db.add(record)
        else:
            record.hostname = host_dict.get("hostname") or record.hostname
            record.mac_address = host_dict.get("mac_address") or record.mac_address
            record.vendor = host_dict.get("vendor") or record.vendor
            record.device_type = host_dict.get("device_type") or record.device_type
            record.confidence = host_dict.get("confidence", record.confidence)
            record.reachability = host_dict.get("reachability", record.reachability)
            record.open_ports = host_dict.get("open_ports", record.open_ports)
            record.banners = host_dict.get("banners", record.banners)
            record.evidence = host_dict.get("evidence", record.evidence)
            record.is_demo = host_dict.get("is_demo", record.is_demo)
            if "status" in host_dict:
                record.status = host_dict["status"]
            if "raw_config" in host_dict:
                record.raw_config = host_dict["raw_config"]
            if "normalized_config" in host_dict:
                record.normalized_config = host_dict["normalized_config"]
            if "latest_analysis" in host_dict:
                record.latest_analysis = host_dict["latest_analysis"]
            record.last_seen = datetime.now(timezone.utc)
        self._db.flush()
        return record

    def list_all(self, demo_filter: bool | None = None) -> list[DiscoveredDeviceRecord]:
        stmt = select(DiscoveredDeviceRecord)
        if demo_filter is not None:
            stmt = stmt.where(DiscoveredDeviceRecord.is_demo == demo_filter)
        stmt = stmt.order_by(DiscoveredDeviceRecord.last_seen.desc())
        return list(self._db.execute(stmt).scalars())

    def get_by_id(self, device_id: str) -> DiscoveredDeviceRecord | None:
        return self._db.get(DiscoveredDeviceRecord, device_id)

    def update_status(self, device_id: str, status: str) -> bool:
        rec = self.get_by_id(device_id)
        if rec:
            rec.status = status
            self._db.flush()
            return True
        return False

    def clear_demo_devices(self) -> int:
        records = list(
            self._db.execute(
                select(DiscoveredDeviceRecord).where(DiscoveredDeviceRecord.is_demo == True)  # noqa: E712
            ).scalars()
        )
        count = len(records)
        for r in records:
            self._db.delete(r)
        self._db.flush()
        return count


class DiscoveryJobRepository:
    """CRUD for DiscoveryJobRecord."""

    def __init__(self, db: Session) -> None:
        self._db = db

    def create(self, job_id: str, cidr: str, is_demo: bool = False) -> DiscoveryJobRecord:
        job = DiscoveryJobRecord(
            id=job_id,
            cidr=cidr,
            status="RUNNING",
            is_demo=is_demo,
            started_at=datetime.now(timezone.utc),
        )
        self._db.add(job)
        self._db.flush()
        return job

    def complete(self, job_id: str, hosts_found: int) -> DiscoveryJobRecord | None:
        job = self._db.get(DiscoveryJobRecord, job_id)
        if job:
            job.status = "COMPLETED"
            job.hosts_found = hosts_found
            job.completed_at = datetime.now(timezone.utc)
            self._db.flush()
        return job

    def fail(self, job_id: str, error: str) -> DiscoveryJobRecord | None:
        job = self._db.get(DiscoveryJobRecord, job_id)
        if job:
            job.status = "FAILED"
            job.error_message = error
            job.completed_at = datetime.now(timezone.utc)
            self._db.flush()
        return job

    def list_jobs(self, limit: int = 20) -> list[DiscoveryJobRecord]:
        return list(
            self._db.execute(
                select(DiscoveryJobRecord).order_by(DiscoveryJobRecord.started_at.desc()).limit(limit)
            ).scalars()
        )


class DeviceCredentialRepository:
    """CRUD for DeviceCredentialReference."""

    def __init__(self, db: Session) -> None:
        self._db = db

    def record_attempt(
        self, device_id: str, username: str, auth_type: str, port: int, status: str
    ) -> DeviceCredentialReference:
        cred = DeviceCredentialReference(
            device_id=device_id,
            username=username,
            auth_type=auth_type,
            port=port,
            status=status,
            last_tested=datetime.now(timezone.utc),
        )
        self._db.add(cred)
        self._db.flush()
        return cred


class NetworkRelationshipRepository:
    """CRUD for NetworkRelationshipRecord."""

    def __init__(self, db: Session) -> None:
        self._db = db

    def save_relationships(
        self, relationships: list[dict[str, Any]]
    ) -> list[NetworkRelationshipRecord]:
        created = []
        for rel in relationships:
            rec = NetworkRelationshipRecord(
                source_device_id=rel["source_device_id"],
                target_device_id=rel["target_device_id"],
                relationship_type=rel.get("relationship_type", "connected_to"),
                confidence=rel.get("confidence", 1.0),
                details=rel.get("details", {}),
            )
            self._db.add(rec)
            created.append(rec)
        self._db.flush()
        return created

    def list_all(self) -> list[NetworkRelationshipRecord]:
        return list(self._db.execute(select(NetworkRelationshipRecord)).scalars())


# ===========================================================================
# Remediation Audit Trail ORM Models & Repository
# ===========================================================================

class RemediationAuditRecord(Base):
    """Complete immutable audit log of every auto-fix and remediation action."""

    __tablename__ = "remediation_audit_records"

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    device_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    hostname: Mapped[str] = mapped_column(String(255), default="")
    control_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    vendor: Mapped[str] = mapped_column(String(100), default="unknown")
    commands_applied: Mapped[list] = mapped_column(JSON, default=list)
    rollback_commands: Mapped[list] = mapped_column(JSON, default=list)
    backup_snapshot_id: Mapped[str] = mapped_column(String(100), default="")
    backup_config: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_config: Mapped[str | None] = mapped_column(Text, nullable=True)
    diff: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="PROPOSED")  # RESOLVED | VERIFICATION_FAILED | ROLLED_BACK
    resolved: Mapped[bool] = mapped_column(Boolean, default=False)
    before_score: Mapped[float] = mapped_column(Float, default=0.0)
    after_score: Mapped[float] = mapped_column(Float, default=0.0)
    approved_by: Mapped[str] = mapped_column(String(100), default="Admin")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )


class RemediationAuditRepository:
    """CRUD for RemediationAuditRecord."""

    def __init__(self, db: Session) -> None:
        self._db = db

    def record_action(self, action_dict: dict[str, Any]) -> RemediationAuditRecord:
        rec_id = action_dict.get("id") or f"audit-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{action_dict.get('control_id', 'fix').lower()}"
        record = RemediationAuditRecord(
            id=rec_id,
            device_id=action_dict.get("device_id", "unknown"),
            hostname=action_dict.get("hostname", ""),
            control_id=action_dict.get("control_id", ""),
            vendor=action_dict.get("vendor", "unknown"),
            commands_applied=action_dict.get("commands_applied", []),
            rollback_commands=action_dict.get("rollback_commands", []),
            backup_snapshot_id=action_dict.get("backup_snapshot_id", ""),
            backup_config=action_dict.get("backup_config"),
            updated_config=action_dict.get("updated_config"),
            diff=action_dict.get("diff"),
            status=action_dict.get("status", "RESOLVED"),
            resolved=action_dict.get("resolved", False),
            before_score=action_dict.get("before_score", 0.0),
            after_score=action_dict.get("after_score", 0.0),
            approved_by=action_dict.get("approved_by", "Admin"),
            created_at=datetime.now(timezone.utc),
        )
        self._db.add(record)
        self._db.flush()
        return record

    def list_all(self, limit: int = 50) -> list[RemediationAuditRecord]:
        return list(
            self._db.execute(
                select(RemediationAuditRecord).order_by(RemediationAuditRecord.created_at.desc()).limit(limit)
            ).scalars()
        )

    def get_by_id(self, record_id: str) -> RemediationAuditRecord | None:
        return self._db.get(RemediationAuditRecord, record_id)


