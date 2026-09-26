"""
NAPALM-based live configuration collector.

Uses the NAPALM library (Network Automation and Programmability Abstraction
Layer with Multivendor support) to retrieve the running configuration from
any NAPALM-supported device in a vendor-neutral way.

Supported NAPALM drivers (built-in):
    eos      - Arista EOS
    junos    - Juniper JunOS
    iosxr    - Cisco IOS-XR
    nxos     - Cisco NX-OS (NX-API)
    nxos_ssh - Cisco NX-OS (SSH)
    ios      - Cisco IOS / IOS-XE

Community drivers (installed separately) extend this list further.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class NapalmCollectorConfig:
    """Connection parameters for a NAPALM driver session."""

    driver: str                     # e.g. "ios", "junos", "eos", "iosxr"
    host: str
    username: str
    password: str
    optional_args: dict = field(default_factory=dict)
    timeout: int = 60


class NapalmCollectionError(Exception):
    """Raised when live config collection via NAPALM fails."""


def fetch_running_config(cfg: NapalmCollectorConfig) -> str:
    """
    Connect via NAPALM and return the running configuration as a string.

    Args:
        cfg: NAPALM connection parameters.

    Returns:
        Raw running-configuration text.

    Raises:
        NapalmCollectionError: On any connection or driver failure.
        ImportError: If napalm is not installed.
    """
    try:
        import napalm
    except ImportError as exc:
        raise ImportError(
            "napalm is required for NAPALM-based collection. "
            "Install it with: pip install napalm"
        ) from exc

    try:
        driver_cls = napalm.get_network_driver(cfg.driver)
    except ModuleNotFoundError as exc:
        raise NapalmCollectionError(
            f"NAPALM driver '{cfg.driver}' not found: {exc}. "
            "Check https://napalm.readthedocs.io/en/latest/support/ for available drivers."
        ) from exc

    device = driver_cls(
        hostname=cfg.host,
        username=cfg.username,
        password=cfg.password,
        timeout=cfg.timeout,
        optional_args=cfg.optional_args,
    )

    try:
        device.open()
        config_dict = device.get_config(retrieve="running")
        return config_dict.get("running", "").strip()
    except Exception as exc:
        raise NapalmCollectionError(
            f"Failed to retrieve config from {cfg.host} via NAPALM: {exc}"
        ) from exc
    finally:
        try:
            device.close()
        except Exception:
            pass
