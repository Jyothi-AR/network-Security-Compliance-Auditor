"""
Cross-Device Exposure & Multi-Hop Risk Analysis Engine.

Analyzes topology relationships and individual device compliance findings
to discover compound, multi-hop attack paths and systemic exposures spanning
multiple network layers (Edge Firewall -> Core Router -> Switch -> Internal Server).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ExposureVector:
    vector_id: str
    title: str
    severity: str                       # CRITICAL | HIGH | MEDIUM | LOW
    source_device: str
    target_device: str
    path: list[str]
    description: str
    risk_multiplication_factor: float
    remediation_summary: str


@dataclass
class TopologyNode:
    id: str
    label: str
    ip: str
    device_type: str
    vendor: str
    compliance_score: float
    critical_findings_count: int
    status: str
    layer: str                          # Perimeter | Core | Access | Workload


@dataclass
class TopologyEdge:
    source: str
    target: str
    relationship: str
    has_exposure: bool = False
    exposure_details: str = ""


@dataclass
class CrossDeviceAnalysisResult:
    nodes: list[TopologyNode] = field(default_factory=list)
    edges: list[TopologyEdge] = field(default_factory=list)
    exposure_vectors: list[ExposureVector] = field(default_factory=list)
    systemic_risk_score: float = 0.0    # 0 - 100
    perimeter_defense_rating: str = "GOOD"  # STRONG | MODERATE | AT_RISK | COMPROMISED

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [n.__dict__ for n in self.nodes],
            "edges": [e.__dict__ for e in self.edges],
            "exposure_vectors": [v.__dict__ for v in self.exposure_vectors],
            "systemic_risk_score": self.systemic_risk_score,
            "perimeter_defense_rating": self.perimeter_defense_rating,
        }


def _classify_layer(device_type: str) -> str:
    dt = device_type.lower()
    if "firewall" in dt or "security" in dt or "gateway" in dt:
        return "Perimeter"
    if "router" in dt or "core" in dt:
        return "Core"
    if "switch" in dt:
        return "Access"
    return "Workload"


def analyze_cross_device_exposure(
    devices: list[dict[str, Any]],
) -> CrossDeviceAnalysisResult:
    """
    Constructs multi-device graph and discovers compound multi-hop exposures.
    """
    nodes: list[TopologyNode] = []
    edges: list[TopologyEdge] = []
    exposure_vectors: list[ExposureVector] = []

    # Map by layer for path construction
    layers: dict[str, list[dict[str, Any]]] = {
        "Perimeter": [],
        "Core": [],
        "Access": [],
        "Workload": [],
    }

    for d in devices:
        layer = _classify_layer(d.get("device_type", "Unknown"))
        layers[layer].append(d)

        # Calculate device compliance score and critical finding count
        latest_analysis = d.get("latest_analysis") or {}
        score = float(latest_analysis.get("compliance_score", 85.0 if d.get("status") == "AUTHENTICATED" else 50.0))
        findings = latest_analysis.get("findings", [])
        crit_count = sum(1 for f in findings if f.get("status") == "FAIL" and f.get("severity") in ("critical", "high"))

        nodes.append(
            TopologyNode(
                id=d.get("id", f"dev-{d.get('ip')}"),
                label=d.get("hostname") or d.get("ip", "Device"),
                ip=d.get("ip", ""),
                device_type=d.get("device_type", "Unknown"),
                vendor=d.get("vendor", "Unknown"),
                compliance_score=score,
                critical_findings_count=crit_count,
                status=d.get("status", "DISCOVERED"),
                layer=layer,
            )
        )

    # Build logical dataflow edges (Perimeter -> Core -> Access -> Workload)
    fw_nodes = layers["Perimeter"]
    router_nodes = layers["Core"]
    switch_nodes = layers["Access"]
    server_nodes = layers["Workload"]

    # Connect Perimeter to Core
    for fw in fw_nodes:
        for rtr in router_nodes:
            edges.append(
                TopologyEdge(
                    source=fw.get("id", fw.get("ip")),
                    target=rtr.get("id", rtr.get("ip")),
                    relationship="filters_traffic_for",
                )
            )

    # Connect Core to Access
    for rtr in router_nodes:
        for sw in switch_nodes:
            edges.append(
                TopologyEdge(
                    source=rtr.get("id", rtr.get("ip")),
                    target=sw.get("id", sw.get("ip")),
                    relationship="routes_to",
                )
            )

    # Connect Access to Servers
    for sw in switch_nodes:
        for srv in server_nodes:
            edges.append(
                TopologyEdge(
                    source=sw.get("id", sw.get("ip")),
                    target=srv.get("id", srv.get("ip")),
                    relationship="switches_to",
                )
            )

    # If no core router exists, connect Perimeter directly to Access or Servers
    if not router_nodes:
        for fw in fw_nodes:
            for sw in switch_nodes or server_nodes:
                edges.append(
                    TopologyEdge(
                        source=fw.get("id", fw.get("ip")),
                        target=sw.get("id", sw.get("ip")),
                        relationship="protects",
                    )
                )

    # COMPOUND RISK DETECTION ALGORITHMS
    # 1. Unencrypted Management + Unsegmented Internal Access
    for fw in fw_nodes:
        fw_analysis = fw.get("latest_analysis") or {}
        fw_failed_ids = {f.get("control_id") for f in fw_analysis.get("findings", []) if f.get("status") == "FAIL"}
        
        for sw in switch_nodes:
            sw_analysis = sw.get("latest_analysis") or {}
            sw_failed_ids = {f.get("control_id") for f in sw_analysis.get("findings", []) if f.get("status") == "FAIL"}

            # Compound vector: Perimeter weak rules + Switch unencrypted telnet/http
            if any("http" in fid.lower() or "telnet" in fid.lower() or "ssh" in fid.lower() for fid in sw_failed_ids):
                exposure_vectors.append(
                    ExposureVector(
                        vector_id=f"EXP-{fw.get('hostname')}-{sw.get('hostname')}-MGMT",
                        title="Compound Perimeter-to-Access Management Exposure",
                        severity="HIGH",
                        source_device=fw.get("hostname", fw.get("ip")),
                        target_device=sw.get("hostname", sw.get("ip")),
                        path=[fw.get("hostname", fw.get("ip")), sw.get("hostname", sw.get("ip"))],
                        description=(
                            f"Edge firewall '{fw.get('hostname')}' allows inbound transit to internal switch '{sw.get('hostname')}' "
                            f"which has unencrypted management protocols enabled (CIS Control 4.1)."
                        ),
                        risk_multiplication_factor=1.8,
                        remediation_summary="Enforce SSH v2 only on internal switch and drop management traffic on edge firewall.",
                    )
                )

    # 2. Multi-hop Server Lateral Movement Exposure
    for rtr in router_nodes:
        for srv in server_nodes:
            exposure_vectors.append(
                ExposureVector(
                    vector_id=f"EXP-{rtr.get('hostname')}-{srv.get('hostname')}-LATERAL",
                    title="Cross-Subnet Lateral Movement Pathway",
                    severity="MEDIUM",
                    source_device=rtr.get("hostname", rtr.get("ip")),
                    target_device=srv.get("hostname", srv.get("ip")),
                    path=[rtr.get("hostname", rtr.get("ip")), srv.get("hostname", srv.get("ip"))],
                    description=(
                        f"Core router '{rtr.get('hostname')}' routes inter-VLAN traffic to workload '{srv.get('hostname')}' "
                        f"without micro-segmentation ACLs or inspection."
                    ),
                    risk_multiplication_factor=1.4,
                    remediation_summary="Implement stateful ACLs or firewall zone inspection between VLAN subnets.",
                )
            )

    # Calculate overall systemic risk score (0-100 where 100 is high risk)
    avg_score = (sum(n.compliance_score for n in nodes) / len(nodes)) if nodes else 80.0
    systemic_risk = max(0.0, min(100.0, round(100.0 - avg_score + (len(exposure_vectors) * 4.5), 1)))

    rating = "STRONG"
    if systemic_risk > 50:
        rating = "AT_RISK"
    elif systemic_risk > 25:
        rating = "MODERATE"

    return CrossDeviceAnalysisResult(
        nodes=nodes,
        edges=edges,
        exposure_vectors=exposure_vectors,
        systemic_risk_score=systemic_risk,
        perimeter_defense_rating=rating,
    )
