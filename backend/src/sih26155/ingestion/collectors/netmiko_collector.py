"""
Netmiko-based live configuration collector.

Connects to ANY device supported by Netmiko over SSH and retrieves
the running configuration as a raw text string. No vendor-specific
logic lives here; vendor detection is handled downstream.

Supported device_types (selection):
    cisco_ios, cisco_xr, cisco_nxos, cisco_asa, cisco_xe,
    juniper_junos, paloalto_panos, arista_eos, fortinet,
    hp_procurve, huawei, mikrotik_routeros ...
    (full list: https://ktbyers.github.io/netmiko/docs/netmiko/)
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class NetmikoCollectorConfig:
    """Connection parameters for a Netmiko SSH session."""

    host: str
    username: str
    password: str
    device_type: str                # e.g. "cisco_ios", "juniper_junos"
    port: int = 22
    secret: str = ""                # enable secret (Cisco / optional)
    timeout: int = 30               # connect timeout in seconds
    session_timeout: int = 60       # command timeout in seconds
    extra_params: dict = field(default_factory=dict)  # forwarded to Netmiko


class NetmikoCollectionError(Exception):
    """Raised when live config collection via Netmiko fails."""


def fetch_running_config(cfg: NetmikoCollectorConfig) -> str:
    """
    Open an SSH session, retrieve the running configuration, and return
    it as a plain string.

    Args:
        cfg: Connection parameters.

    Returns:
        Raw running-configuration text.

    Raises:
        NetmikoCollectionError: On any connection or command failure.
        ImportError: If netmiko is not installed.
    """
    try:
        from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException
    except ImportError as exc:
        raise ImportError(
            "netmiko is required for live SSH collection. "
            "Install it with: pip install netmiko"
        ) from exc

    connect_kwargs = {
        "device_type": cfg.device_type,
        "host": cfg.host,
        "username": cfg.username,
        "password": cfg.password,
        "port": cfg.port,
        "secret": cfg.secret,
        "timeout": cfg.timeout,
        "session_timeout": cfg.session_timeout,
        **cfg.extra_params,
    }

    # Determine the appropriate command to display running configuration for this vendor
    cmd_map = {
        "juniper": "show configuration",
        "juniper_junos": "show configuration",
        "paloalto_panos": "show config running",
        "paloalto": "show config running",
        "fortinet": "show full-configuration",
        "fortinet_ssh": "show full-configuration",
        "vyos": "show configuration commands",
        "vyatta": "show configuration",
        "checkpoint_gaia": "show configuration",
        "huawei": "display current-configuration",
        "huawei_vrp": "display current-configuration",
        "hp_procurve": "show running-config",
        "cisco_ios": "show running-config",
        "cisco_xe": "show running-config",
        "cisco_nxos": "show running-config",
        "cisco_xr": "show running-config",
        "arista_eos": "show running-config",
    }
    config_cmd = cfg.extra_params.get("config_command") or cmd_map.get(cfg.device_type.lower(), "show running-config")

    try:
        with ConnectHandler(**connect_kwargs) as conn:
            if cfg.secret:
                conn.enable()
            raw = conn.send_command(config_cmd, read_timeout=cfg.session_timeout)
            return raw.strip()

    except NetmikoAuthenticationException as exc:
        raise NetmikoCollectionError(
            f"Authentication failed for {cfg.host}: {exc}"
        ) from exc
    except NetmikoTimeoutException as exc:
        raise NetmikoCollectionError(
            f"Connection to {cfg.host} timed out: {exc}"
        ) from exc
    except Exception as exc:
        raise NetmikoCollectionError(
            f"Failed to retrieve config from {cfg.host}: {exc}"
        ) from exc
