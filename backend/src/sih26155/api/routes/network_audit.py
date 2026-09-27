"""
Live Network Audit & Discovery Router.

Endpoints for subnet discovery, device classification, credential testing,
read-only vendor configuration collection, CIS compliance evaluation, and
cross-device attack graph analysis.
"""

from __future__ import annotations

import datetime
from typing import Any
import uuid

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from sih26155.connectors.factory import get_connector
from sih26155.core.pipeline.analyze import analyze_config
from sih26155.discovery.engine import (
    generate_demo_lab_hosts,
    run_discovery_scan,
)
from sih26155.intelligence.cross_device import analyze_cross_device_exposure
from sih26155.storage.database import get_db
from sih26155.storage.repositories import (
    DeviceCredentialRepository,
    DiscoveredDeviceRecord,
    DiscoveredDeviceRepository,
    DiscoveryJobRepository,
)


router = APIRouter(
    prefix="/api/network",
    tags=["network-audit"],
)

# Realistic multi-vendor config fixtures for lab/demo execution
DEMO_CONFIG_FIXTURES: dict[str, str] = {
    "Cisco": """\
! Cisco IOS Configuration - CORE-RTR-01
version 15.6
hostname CORE-RTR-01
service password-encryption
service timestamps log datetime msec
logging buffered 64000
no ip domain lookup
ip domain name enterprise.internal
ip ssh version 2
ip ssh time-out 60
ip ssh authentication-retries 3
!
interface GigabitEthernet0/0
 description WAN-Uplink-Edge
 ip address 192.168.1.1 255.255.255.0
 no shutdown
!
interface GigabitEthernet0/1
 description LAN-Distribution
 ip address 10.10.1.1 255.255.255.0
 no shutdown
!
ip access-list extended EDGE_INBOUND
 permit tcp any host 192.168.1.1 eq 22
 permit tcp any host 192.168.1.1 eq 443
 deny ip any any log
!
line vty 0 4
 transport input ssh
 login local
 exec-timeout 10 0
!
enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0
end
""",
    "Fortinet": """\
#config-version=FG100E-7.2.4-FW-build1396-230309:opmode=0:vdom=0:user=admin
#conf_file_ver=12858591823748291
config system global
    set hostname "EDGE-FW-01"
    set timezone 04
    set admin-sport 443
    set admin-ssh-port 22
    set admin-lockout-threshold 3
    set admin-lockout-duration 300
end
config system interface
    edit "port1"
        set vdom "root"
        set ip 192.168.1.20 255.255.255.0
        set allowaccess ping https ssh
        set type physical
    next
    edit "port2"
        set vdom "root"
        set ip 10.0.0.1 255.255.255.0
        set allowaccess ping ssh
        set type physical
    next
end
config firewall policy
    edit 1
        set name "Trust-to-Untrust"
        set srcintf "port2"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "HTTPS" "SSH"
        set logtraffic all
    next
    edit 2
        set name "Deny-All-Inbound"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set action deny
        set schedule "always"
        set service "ALL"
    next
end
""",
    "MikroTik": """\
# RouterOS 7.12
# software id = 4P4Q-8761
/interface ethernet
set [ find default-name=ether1 ] name=ether1-gateway
set [ find default-name=ether2 ] name=ether2-lan
/ip address
add address=192.168.1.50/24 interface=ether1-gateway network=192.168.1.0
add address=172.16.0.1/24 interface=ether2-lan network=172.16.0.0
/ip service
set telnet disabled=yes
set ftp disabled=yes
set www disabled=yes
set ssh port=22
set www-ssl disabled=no port=443
set api disabled=yes
set api-ssl disabled=no port=8729
/system identity
set name=BRANCH-GW-01
/ip firewall filter
add action=accept chain=input connection-state=established,related
add action=drop chain=input connection-state=invalid
add action=accept chain=input protocol=tcp dst-port=22 src-address=192.168.1.0/24
add action=drop chain=input in-interface=ether1-gateway
""",
    "Linux": """\
# --- cat /etc/hostname ---
MGMT-SRV-01

# --- cat /etc/os-release ---
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"

# --- cat /etc/ssh/sshd_config ---
Port 22
Protocol 2
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
X11Forwarding no
MaxAuthTries 4
ClientAliveInterval 300
ClientAliveCountMax 2

# --- ip addr ---
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0

# --- iptables-save ---
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT
COMMIT
""",
}


# ===========================================================================
# Request & Response Schemas
# ===========================================================================

class DiscoveryScanRequest(BaseModel):
    cidr: str = Field("192.168.1.0/24", description="Authorized subnet CIDR to scan")
    is_demo: bool = Field(False, description="If True, loads realistic simulated lab devices")
    max_hosts: int = Field(64, description="Maximum IP addresses to probe")


class AuthenticateDeviceRequest(BaseModel):
    device_id: str
    username: str
    password: str = ""
    port: int = 22
    auth_type: str = "ssh_password"
    is_demo: bool = False


class AuditDeviceRequest(BaseModel):
    device_id: str
    username: str = "admin"
    password: str = ""
    port: int = 22
    is_demo: bool = False


# ===========================================================================
# Endpoints
# ===========================================================================

@router.post("/discover", summary="Execute safe subnet discovery or simulate lab")
def start_discovery(req: DiscoveryScanRequest):
    job_id = f"job-{uuid.uuid4().hex[:8]}"

    with get_db() as db:
        job_repo = DiscoveryJobRepository(db)
        dev_repo = DiscoveredDeviceRepository(db)
        job_repo.create(job_id=job_id, cidr=req.cidr, is_demo=req.is_demo)

        try:
            if req.is_demo:
                hosts = generate_demo_lab_hosts(subnet_prefix="192.168.1")
            else:
                hosts = run_discovery_scan(cidr=req.cidr, max_hosts=req.max_hosts)

            # Persist discovered hosts to DB
            saved_records = []
            for h in hosts:
                rec = dev_repo.upsert(h.to_dict())
                saved_records.append(rec)

            job_repo.complete(job_id=job_id, hosts_found=len(hosts))

            return {
                "job_id": job_id,
                "status": "COMPLETED",
                "cidr": req.cidr,
                "is_demo": req.is_demo,
                "hosts_found": len(hosts),
                "devices": [
                    {
                        "id": h.id,
                        "ip": h.ip,
                        "hostname": h.hostname or h.ip,
                        "mac_address": h.mac_address,
                        "vendor": h.vendor,
                        "device_type": h.device_type,
                        "confidence": h.confidence,
                        "status": h.status,
                        "open_ports": h.open_ports,
                        "banners": h.banners,
                        "evidence": h.evidence,
                        "is_demo": h.is_demo,
                    }
                    for h in hosts
                ],
            }
        except Exception as exc:
            job_repo.fail(job_id=job_id, error=str(exc))
            raise HTTPException(status_code=400, detail=f"Discovery failed: {exc}")


@router.get("/devices", summary="List all discovered devices in inventory")
def list_devices(demo: bool | None = None):
    with get_db() as db:
        dev_repo = DiscoveredDeviceRepository(db)
        records = dev_repo.list_all(demo_filter=demo)
        return {
            "total": len(records),
            "devices": [
                {
                    "id": r.id,
                    "ip": r.ip,
                    "hostname": r.hostname or r.ip,
                    "mac_address": r.mac_address,
                    "vendor": r.vendor,
                    "device_type": r.device_type,
                    "confidence": r.confidence,
                    "status": r.status,
                    "open_ports": r.open_ports or [],
                    "banners": r.banners or {},
                    "evidence": r.evidence or [],
                    "is_demo": r.is_demo,
                    "has_config": bool(r.raw_config),
                    "latest_analysis": r.latest_analysis,
                    "last_seen": r.last_seen.isoformat() if r.last_seen else None,
                }
                for r in records
            ],
        }


@router.post("/devices/clear-demo", summary="Clear all lab/demo devices")
def clear_demo_devices():
    with get_db() as db:
        dev_repo = DiscoveredDeviceRepository(db)
        count = dev_repo.clear_demo_devices()
        return {"cleared_count": count}


@router.post("/authenticate", summary="Validate live credentials against discovered host")
def authenticate_device(req: AuthenticateDeviceRequest):
    with get_db() as db:
        dev_repo = DiscoveredDeviceRepository(db)
        cred_repo = DeviceCredentialRepository(db)

        dev = dev_repo.get_by_id(req.device_id)
        if not dev:
            raise HTTPException(status_code=404, detail="Device not found")

        auth_success = False
        if req.is_demo or dev.is_demo:
            # Demo verification logic: reject blank credentials, accept demo credentials
            auth_success = bool(req.username.strip())
        else:
            # Real live verification via connector
            try:
                connector = get_connector(
                    vendor=dev.vendor,
                    host=dev.ip,
                    username=req.username,
                    password=req.password,
                    port=req.port,
                    timeout=10,
                )
                auth_success = connector.test_connection()
            except Exception:
                auth_success = False

        status_str = "VALID" if auth_success else "INVALID"
        cred_repo.record_attempt(
            device_id=dev.id,
            username=req.username,
            auth_type=req.auth_type,
            port=req.port,
            status=status_str,
        )

        if auth_success:
            dev_repo.update_status(dev.id, "AUTHENTICATED")
            return {
                "device_id": dev.id,
                "status": "AUTHENTICATED",
                "message": f"Successfully authenticated as {req.username} on {dev.hostname or dev.ip}",
            }
        else:
            return {
                "device_id": dev.id,
                "status": dev.status,
                "message": f"Authentication failed for {req.username} on {dev.hostname or dev.ip}",
            }


@router.post("/collect", summary="Pull raw running config from authenticated device")
def collect_device_config(req: AuditDeviceRequest):
    with get_db() as db:
        dev_repo = DiscoveredDeviceRepository(db)
        dev = dev_repo.get_by_id(req.device_id)
        if not dev:
            raise HTTPException(status_code=404, detail="Device not found")

        raw_config = ""
        if req.is_demo or dev.is_demo:
            raw_config = DEMO_CONFIG_FIXTURES.get(dev.vendor, DEMO_CONFIG_FIXTURES["Cisco"])
        else:
            try:
                connector = get_connector(
                    vendor=dev.vendor,
                    host=dev.ip,
                    username=req.username,
                    password=req.password,
                    port=req.port,
                )
                raw_config = connector.collect_configuration()
            except Exception as exc:
                raise HTTPException(status_code=502, detail=f"Configuration collection failed: {exc}")

        # Normalize config
        connector = get_connector(vendor=dev.vendor, host=dev.ip)
        normalized = connector.normalize_configuration(raw_config)

        dev.raw_config = raw_config
        dev.normalized_config = normalized.to_dict()
        dev.status = "AUTHENTICATED"
        db.flush()

        return {
            "device_id": dev.id,
            "raw_config": raw_config,
            "normalized": normalized.to_dict(),
        }


@router.post("/audit-device", summary="Run compliance pipeline on device configuration")
def audit_device(req: AuditDeviceRequest):
    with get_db() as db:
        dev_repo = DiscoveredDeviceRepository(db)
        dev = dev_repo.get_by_id(req.device_id)
        if not dev:
            raise HTTPException(status_code=404, detail="Device not found")

        # 1. Collect or use existing config
        raw_config = dev.raw_config
        if not raw_config:
            if req.is_demo or dev.is_demo:
                raw_config = DEMO_CONFIG_FIXTURES.get(dev.vendor, DEMO_CONFIG_FIXTURES["Cisco"])
            else:
                try:
                    connector = get_connector(
                        vendor=dev.vendor,
                        host=dev.ip,
                        username=req.username,
                        password=req.password,
                        port=req.port,
                    )
                    raw_config = connector.collect_configuration()
                except Exception as exc:
                    raise HTTPException(status_code=502, detail=f"Config collection failed: {exc}")

        # 2. Run analysis pipeline
        analysis_result = analyze_config(
            config=raw_config,
            source_file=dev.hostname or dev.ip,
        )
        result_dict = analysis_result.to_dict()
        findings_data = result_dict.get("findings", [])
        total = len(findings_data)
        passed = sum(1 for f in findings_data if f.get("status") == "PASS")
        score = round((passed / total * 100) if total else 0.0, 2)
        result_dict["compliance_score"] = score

        # 3. Update device record
        connector = get_connector(vendor=dev.vendor, host=dev.ip)
        normalized = connector.normalize_configuration(raw_config)

        dev.raw_config = raw_config
        dev.normalized_config = normalized.to_dict()
        dev.latest_analysis = result_dict
        dev.status = "AUDITED"
        db.flush()

        return {
            "device_id": dev.id,
            "status": "AUDITED",
            "hostname": dev.hostname or dev.ip,
            "ip": dev.ip,
            "vendor": dev.vendor,
            "device_type": dev.device_type,
            "compliance_score": score,
            "findings_count": len(findings_data),
            "analysis": result_dict,
            "normalized": normalized.to_dict(),
        }


@router.post("/audit-all", summary="Audit all discovered/identified devices in batch")
def audit_all_devices():
    with get_db() as db:
        dev_repo = DiscoveredDeviceRepository(db)
        records = dev_repo.list_all()

        audited_results = []
        for dev in records:
            raw_config = dev.raw_config or DEMO_CONFIG_FIXTURES.get(dev.vendor, DEMO_CONFIG_FIXTURES["Cisco"])
            analysis_result = analyze_config(
                config=raw_config,
                source_file=dev.hostname or dev.ip,
            )
            result_dict = analysis_result.to_dict()
            findings_data = result_dict.get("findings", [])
            total = len(findings_data)
            passed = sum(1 for f in findings_data if f.get("status") == "PASS")
            score = round((passed / total * 100) if total else 0.0, 2)
            result_dict["compliance_score"] = score

            connector = get_connector(vendor=dev.vendor, host=dev.ip)
            normalized = connector.normalize_configuration(raw_config)

            dev.raw_config = raw_config
            dev.normalized_config = normalized.to_dict()
            dev.latest_analysis = result_dict
            dev.status = "AUDITED"

            audited_results.append({
                "device_id": dev.id,
                "hostname": dev.hostname or dev.ip,
                "vendor": dev.vendor,
                "compliance_score": score,
            })
        db.flush()

        return {
            "total_audited": len(audited_results),
            "results": audited_results,
        }


@router.get("/topology", summary="Retrieve network topology graph and cross-device risks")
def get_network_topology():
    with get_db() as db:
        dev_repo = DiscoveredDeviceRepository(db)
        records = dev_repo.list_all()

        device_dicts = [
            {
                "id": r.id,
                "ip": r.ip,
                "hostname": r.hostname or r.ip,
                "vendor": r.vendor,
                "device_type": r.device_type,
                "status": r.status,
                "latest_analysis": r.latest_analysis or {},
            }
            for r in records
        ]

        analysis = analyze_cross_device_exposure(device_dicts)
        return analysis.to_dict()
