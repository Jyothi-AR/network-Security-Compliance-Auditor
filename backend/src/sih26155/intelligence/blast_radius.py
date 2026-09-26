"""
Blast-Radius Analysis.

Given a security issue (a finding or a set of control failures) on a
device, determines which other devices and network segments could be
affected if an attacker exploits that issue.

The analysis is topology-aware: devices that share a segment with the
affected device and have insufficient isolation (no ACL / zone policy)
are considered within the blast radius.

Topology is described by the caller as a simple dict of
device -> list[segment] mappings. No external database required.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class DeviceTopology:
    """
    Describes the network topology for blast-radius analysis.

    Attributes:
        device_segments: Mapping of device_name -> list of segment names
                         the device is connected to.
        device_acl_status: Mapping of device_name -> bool indicating
                           whether the device has ACL/zone policies.
    """
    device_segments: dict[str, list[str]] = field(default_factory=dict)
    device_acl_status: dict[str, bool] = field(default_factory=dict)


@dataclass
class BlastRadiusResult:
    """Result of a blast-radius analysis for one affected device."""

    source_device: str
    affected_segments: list[str]
    exposed_devices: list[str]          # Devices reachable without ACL
    partially_exposed_devices: list[str] # Devices with ACL but on same segment
    risk_score: float                   # 0-10
    summary: str


class BlastRadiusAnalyser:
    """
    Analyses the blast radius of a security event on a device.

    Usage::

        topo = DeviceTopology(
            device_segments={"fw-1": ["dmz", "lan"], "router-1": ["lan", "wan"]},
            device_acl_status={"fw-1": True, "router-1": False},
        )
        analyser = BlastRadiusAnalyser(topology=topo)
        result = analyser.analyse(source_device="fw-1")
    """

    def __init__(self, topology: DeviceTopology) -> None:
        self._topo = topology

    def analyse(self, source_device: str) -> BlastRadiusResult:
        """
        Calculate the blast radius originating from ``source_device``.

        Returns:
            BlastRadiusResult with affected segments and devices.
        """
        source_segments = self._topo.device_segments.get(source_device, [])

        # Find all other devices that share at least one segment
        co_resident: dict[str, list[str]] = {}
        for device, segs in self._topo.device_segments.items():
            if device == source_device:
                continue
            shared = [s for s in segs if s in source_segments]
            if shared:
                co_resident[device] = shared

        exposed = [
            d for d, _ in co_resident.items()
            if not self._topo.device_acl_status.get(d, False)
        ]
        partial = [
            d for d, _ in co_resident.items()
            if self._topo.device_acl_status.get(d, False)
        ]

        # Risk score: more exposed neighbours + more shared segments = higher score
        base = len(exposed) * 3 + len(partial) * 1 + len(source_segments) * 0.5
        risk_score = min(base, 10.0)

        summary_parts = [
            f"Source: {source_device}",
            f"Affected segments: {source_segments or ['unknown']}",
            f"Fully exposed devices: {exposed or ['none']}",
        ]
        if partial:
            summary_parts.append(f"Partially exposed (ACL present): {partial}")

        return BlastRadiusResult(
            source_device=source_device,
            affected_segments=source_segments,
            exposed_devices=exposed,
            partially_exposed_devices=partial,
            risk_score=round(risk_score, 2),
            summary=". ".join(summary_parts),
        )

    def analyse_multi(
        self,
        source_devices: list[str],
    ) -> list[BlastRadiusResult]:
        """Analyse blast radius for multiple source devices."""
        return [self.analyse(d) for d in source_devices]
