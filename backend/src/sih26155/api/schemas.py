from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


class AnalysisRequest(BaseModel):
    config: str = Field(min_length=1)
    source_file: str = Field(default="uploaded-config.cfg")


class AnalysisResponse(BaseModel):
    vendor: dict[str, Any]
    facts: list[dict[str, Any]]
    evidence: list[dict[str, Any]]
    baseline: dict[str, Any]
    findings: list[dict[str, Any]]
    remediations: list[dict[str, Any]]


class ReportRequest(BaseModel):
    source_file: str = Field(default="uploaded-config.cfg")
    analysis: AnalysisResponse


class LiveFetchRequest(BaseModel):
    """Connection details for pulling a live device configuration."""

    host: str = Field(description="Device hostname or IP address")
    username: str = Field(description="SSH / API username")
    password: str = Field(description="SSH / API password")
    device_type: str = Field(
        description=(
            "Transport-specific device identifier. "
            "For SSH (Netmiko): e.g. 'cisco_ios', 'juniper_junos', 'paloalto_panos', 'arista_eos'. "
            "For NAPALM: e.g. 'ios', 'junos', 'eos', 'iosxr'."
        )
    )
    transport: Literal["ssh", "napalm"] = Field(
        default="ssh",
        description="Collector transport: 'ssh' uses Netmiko, 'napalm' uses NAPALM.",
    )
    port: int = Field(default=22, description="TCP port")
    secret: Optional[str] = Field(default="", description="Enable secret (Cisco SSH only)")
    timeout: int = Field(default=30, description="Connection timeout in seconds")
    session_timeout: int = Field(default=60, description="Command read timeout in seconds")
    optional_args: dict[str, Any] = Field(
        default_factory=dict,
        description="Extra driver options forwarded to Netmiko/NAPALM",
    )


class LiveFetchResponse(BaseModel):
    """Result of a live config fetch + compliance analysis."""

    host: str
    device_type: str
    transport: str
    raw_config: str = Field(description="Raw configuration text pulled from the device")
    analysis: AnalysisResponse
