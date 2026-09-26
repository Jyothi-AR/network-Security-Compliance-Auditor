"""
Unified live-config fetcher facade.

Provides a single entry-point that selects the appropriate collector
(Netmiko SSH or NAPALM) based on the requested transport.  The returned
raw config string is passed straight into the existing analyze_config()
pipeline, so vendor detection and compliance evaluation happen
automatically regardless of the source device.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Literal


class Transport(str, Enum):
    """Supported transport protocols for live config collection."""
    SSH = "ssh"       # Netmiko – any device type Netmiko supports
    NAPALM = "napalm" # NAPALM – vendor-neutral get_config()


@dataclass
class LiveFetchConfig:
    """
    Parameters for a live configuration fetch.

    The ``device_type`` field is forwarded directly to the underlying
    library (Netmiko device_type or NAPALM driver name), so you can use
    any value those libraries support – not just Cisco.

    Examples
    --------
    Cisco IOS over SSH::

        LiveFetchConfig(
            host="192.168.1.1",
            username="admin",
            password="s3cr3t",
            device_type="cisco_ios",
            transport=Transport.SSH,
        )

    Juniper JunOS over SSH::

        LiveFetchConfig(
            host="10.0.0.5",
            username="netops",
            password="pass",
            device_type="juniper_junos",
            transport=Transport.SSH,
        )

    Palo Alto PAN-OS over SSH::

        LiveFetchConfig(
            host="172.16.0.1",
            username="admin",
            password="pass",
            device_type="paloalto_panos",
            transport=Transport.SSH,
        )

    Arista EOS via NAPALM::

        LiveFetchConfig(
            host="10.10.0.2",
            username="admin",
            password="pass",
            device_type="eos",
            transport=Transport.NAPALM,
        )
    """

    host: str
    username: str
    password: str
    device_type: str             # Netmiko device_type OR NAPALM driver name
    transport: Transport = Transport.SSH
    port: int = 22
    secret: str = ""             # Cisco enable secret (SSH only)
    timeout: int = 30
    session_timeout: int = 60
    optional_args: dict = field(default_factory=dict)  # NAPALM optional_args


class LiveFetchError(Exception):
    """Raised when live configuration fetching fails."""


def fetch_live_config(cfg: LiveFetchConfig) -> str:
    """
    Fetch the running configuration from a live device.

    Delegates to the appropriate collector based on ``cfg.transport``
    and returns the raw configuration text.

    Args:
        cfg: Connection and transport parameters.

    Returns:
        Raw running-configuration text (plain string).

    Raises:
        LiveFetchError: If the fetch fails for any reason.
        ValueError: If an unsupported transport is requested.
    """
    try:
        if cfg.transport == Transport.SSH:
            return _fetch_via_netmiko(cfg)
        elif cfg.transport == Transport.NAPALM:
            return _fetch_via_napalm(cfg)
        else:
            raise ValueError(f"Unsupported transport: {cfg.transport!r}")
    except (ValueError, LiveFetchError):
        raise
    except Exception as exc:
        raise LiveFetchError(str(exc)) from exc


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _fetch_via_netmiko(cfg: LiveFetchConfig) -> str:
    from sih26155.ingestion.collectors.netmiko_collector import (
        NetmikoCollectorConfig,
        NetmikoCollectionError,
        fetch_running_config as _fetch,
    )
    try:
        return _fetch(
            NetmikoCollectorConfig(
                host=cfg.host,
                username=cfg.username,
                password=cfg.password,
                device_type=cfg.device_type,
                port=cfg.port,
                secret=cfg.secret,
                timeout=cfg.timeout,
                session_timeout=cfg.session_timeout,
                extra_params=cfg.optional_args,
            )
        )
    except NetmikoCollectionError as exc:
        raise LiveFetchError(str(exc)) from exc


def _fetch_via_napalm(cfg: LiveFetchConfig) -> str:
    from sih26155.ingestion.collectors.napalm_collector import (
        NapalmCollectorConfig,
        NapalmCollectionError,
        fetch_running_config as _fetch,
    )
    try:
        return _fetch(
            NapalmCollectorConfig(
                driver=cfg.device_type,
                host=cfg.host,
                username=cfg.username,
                password=cfg.password,
                timeout=cfg.timeout,
                optional_args=cfg.optional_args,
            )
        )
    except NapalmCollectionError as exc:
        raise LiveFetchError(str(exc)) from exc
