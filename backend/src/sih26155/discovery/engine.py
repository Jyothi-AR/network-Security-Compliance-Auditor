"""
Safe Network Discovery Engine.

Performs passive and safe, non-destructive active discovery across an
authorized IP subnet CIDR. Gathers reachability, open management ports,
service banners, and hostnames, and integrates with the device identifier.

Safety Rules:
- No aggressive SYN flood or exploit probes.
- Strict connection timeouts (<= 400ms).
- Max subnet size capped at /24 (256 addresses) per scan job.
- Separate status: DISCOVERED vs IDENTIFIED vs AUTHENTICATED.
"""

from __future__ import annotations

import concurrent.futures
from dataclasses import dataclass, field
import datetime
import ipaddress
import re
import socket
import subprocess
import time
from typing import Any
import uuid

from sih26155.discovery.identifier import DeviceIdentification, identify_device

# Standard management ports inspected during non-destructive discovery
MANAGEMENT_PORTS = [22, 80, 443, 830, 8728]


@dataclass
class DiscoveredHost:
    id: str
    ip: str
    reachability: bool
    status: str                         # DISCOVERED | IDENTIFIED | AUTHENTICATED
    hostname: str = ""
    mac_address: str = ""
    open_ports: list[int] = field(default_factory=list)
    banners: dict[int, str] = field(default_factory=dict)
    vendor: str = "Unknown"
    device_type: str = "Unknown network device"
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)
    snmp_sysdescr: str = ""
    is_demo: bool = False
    discovered_at: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "ip": self.ip,
            "reachability": self.reachability,
            "status": self.status,
            "hostname": self.hostname or self.ip,
            "mac_address": self.mac_address,
            "open_ports": self.open_ports,
            "banners": self.banners,
            "vendor": self.vendor,
            "device_type": self.device_type,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "is_demo": self.is_demo,
            "discovered_at": self.discovered_at,
        }


def read_local_arp_table() -> dict[str, str]:
    """Reads OS ARP cache to quickly identify MAC addresses without extra network packets."""
    arp_map: dict[str, str] = {}
    try:
        res = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=3)
        for line in res.stdout.splitlines():
            line_str = line.strip()
            # Match IPv4 and MAC: e.g. 192.168.1.1  00-11-22-33-44-55  dynamic
            match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F[:-]{17})", line_str)
            if match:
                ip = match.group(1)
                mac = match.group(2).replace("-", ":").lower()
                arp_map[ip] = mac
    except Exception:
        pass
    return arp_map


def probe_host(
    ip: str,
    arp_cache: dict[str, str],
    timeout: float = 0.35,
) -> DiscoveredHost | None:
    """
    Safely probes an individual IP address for open management services.
    Returns DiscoveredHost if reachable, or None if host is silent.
    """
    open_ports: list[int] = []
    banners: dict[int, str] = {}

    for port in MANAGEMENT_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
                # If SSH port 22, safely receive the protocol identification banner
                if port == 22:
                    try:
                        sock.settimeout(0.4)
                        banner_bytes = sock.recv(256)
                        if banner_bytes:
                            banner_str = banner_bytes.decode("utf-8", errors="ignore").strip()
                            banners[22] = banner_str
                    except Exception:
                        pass
        except Exception:
            pass
        finally:
            sock.close()

    # If no management ports open, check ICMP reachability via OS ping (1 packet)
    reachability = len(open_ports) > 0
    if not reachability:
        try:
            # Windows: -n 1 -w 300, Linux: -c 1 -W 1
            cmd = ["ping", "-n", "1", "-w", "300", ip] if subprocess.os.name == "nt" else ["ping", "-c", "1", "-W", "1", ip]
            res = subprocess.run(cmd, capture_output=True, timeout=1)
            reachability = (res.returncode == 0)
        except Exception:
            reachability = False

    if not reachability:
        return None

    # Reverse DNS resolution (if available)
    hostname = ""
    try:
        host_info = socket.gethostbyaddr(ip)
        hostname = host_info[0]
    except Exception:
        hostname = ""

    mac = arp_cache.get(ip, "")

    # Classify device
    ident = identify_device(
        ip=ip,
        hostname=hostname,
        open_ports=open_ports,
        banners=banners,
        mac_address=mac,
    )

    # Clearly distinguish DISCOVERED vs IDENTIFIED
    status = "IDENTIFIED" if ident.vendor != "Unknown" or ident.device_type != "Unknown network device" else "DISCOVERED"

    return DiscoveredHost(
        id=f"dev-{ip.replace('.', '-')}",
        ip=ip,
        reachability=True,
        status=status,
        hostname=hostname or ip,
        mac_address=mac,
        open_ports=open_ports,
        banners=banners,
        vendor=ident.vendor,
        device_type=ident.device_type,
        confidence=ident.confidence,
        evidence=ident.evidence,
    )


def run_discovery_scan(
    cidr: str,
    max_hosts: int = 64,
) -> list[DiscoveredHost]:
    """
    Executes concurrent non-destructive discovery over an authorized subnet.
    """
    try:
        network = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid network CIDR: {exc}")

    # Safety guard: Limit scan space to prevent WAN denial of service
    hosts = list(network.hosts())[:max_hosts]
    arp_cache = read_local_arp_table()

    discovered: list[DiscoveredHost] = []

    # Safe concurrency pool (max 20 concurrent threads)
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_ip = {
            executor.submit(probe_host, str(ip), arp_cache): str(ip)
            for ip in hosts
        }
        for future in concurrent.futures.as_completed(future_to_ip):
            try:
                res = future.result()
                if res is not None:
                    discovered.append(res)
            except Exception:
                pass

    # Sort deterministically by IP
    discovered.sort(key=lambda d: ipaddress.ip_address(d.ip))
    return discovered


def generate_demo_lab_hosts(subnet_prefix: str = "192.168.1") -> list[DiscoveredHost]:
    """
    Generates realistic multi-vendor lab topology for offline testing and demos.
    Clearly marked with is_demo=True and distinct status badges.
    """
    return [
        DiscoveredHost(
            id="dev-demo-rtr-01",
            ip=f"{subnet_prefix}.1",
            reachability=True,
            status="IDENTIFIED",
            hostname="CORE-RTR-01",
            mac_address="00:00:0c:4a:12:90",
            open_ports=[22, 443],
            banners={22: "SSH-2.0-Cisco-1.25"},
            vendor="Cisco",
            device_type="Router",
            confidence=0.95,
            evidence=["Port 22 banner 'SSH-2.0-Cisco-1.25'", "MAC OUI matches Cisco Systems", "Hostname matches router convention"],
            is_demo=True,
        ),
        DiscoveredHost(
            id="dev-demo-fw-01",
            ip=f"{subnet_prefix}.20",
            reachability=True,
            status="IDENTIFIED",
            hostname="EDGE-FW-01",
            mac_address="00:09:0f:7a:55:01",
            open_ports=[22, 443, 80],
            banners={22: "SSH-2.0-FortiSSH_7.2", 443: "FortiOS HTTPS"},
            vendor="Fortinet",
            device_type="Firewall",
            confidence=0.92,
            evidence=["Port 22 banner matches Fortinet FortiSSH 7.2", "HTTPS Admin Console detected", "MAC OUI matches Fortinet hardware"],
            is_demo=True,
        ),
        DiscoveredHost(
            id="dev-demo-sw-01",
            ip=f"{subnet_prefix}.10",
            reachability=True,
            status="IDENTIFIED",
            hostname="DIST-SW-01",
            mac_address="00:01:c7:33:bb:42",
            open_ports=[22, 80],
            banners={22: "SSH-2.0-Cisco-1.20"},
            vendor="Cisco",
            device_type="Switch",
            confidence=0.90,
            evidence=["Port 22 banner 'SSH-2.0-Cisco-1.20'", "VLAN 10/20 management ports active", "MAC OUI registered to Cisco"],
            is_demo=True,
        ),
        DiscoveredHost(
            id="dev-demo-mt-01",
            ip=f"{subnet_prefix}.50",
            reachability=True,
            status="IDENTIFIED",
            hostname="BRANCH-GW-01",
            mac_address="48:8f:5a:11:89:ef",
            open_ports=[22, 8728, 80],
            banners={22: "SSH-2.0-ROUTEROS", 8728: "MikroTik API v1"},
            vendor="MikroTik",
            device_type="Router",
            confidence=0.94,
            evidence=["Port 8728 MikroTik RouterOS API active", "SSH banner matches RouterOS", "MAC OUI registered to MikroTik"],
            is_demo=True,
        ),
        DiscoveredHost(
            id="dev-demo-srv-01",
            ip=f"{subnet_prefix}.100",
            reachability=True,
            status="IDENTIFIED",
            hostname="MGMT-SRV-01",
            mac_address="00:50:56:bf:02:11",
            open_ports=[22, 443],
            banners={22: "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2"},
            vendor="Linux",
            device_type="Linux/Network Server",
            confidence=0.88,
            evidence=["OpenSSH banner identifies Debian Linux server", "Port 443 management dashboard open"],
            is_demo=True,
        ),
        DiscoveredHost(
            id="dev-demo-unk-01",
            ip=f"{subnet_prefix}.145",
            reachability=True,
            status="DISCOVERED",
            hostname=f"{subnet_prefix}.145",
            mac_address="fa:16:3e:82:99:a1",
            open_ports=[80],
            banners={},
            vendor="Unknown",
            device_type="Unknown network device",
            confidence=0.20,
            evidence=["Only port 80 HTTP responds", "No identifying vendor signatures in headers or banners"],
            is_demo=True,
        ),
    ]
