import socket
from fastapi import APIRouter, HTTPException

from sih26155.api.routes.analysis import _save_to_db
from sih26155.api.schemas import AnalysisResponse, LiveFetchRequest, LiveFetchResponse
from sih26155.core.pipeline.analyze import analyze_config
from sih26155.ingestion.collectors.local_collector import (
    collect_local_device_info,
    generate_local_device_config,
)
from sih26155.ingestion.live_fetch import LiveFetchConfig, LiveFetchError, Transport, fetch_live_config


router = APIRouter(
    prefix="/api",
    tags=["live-fetch"],
)


@router.get(
    "/live-device/local",
    summary="Get current host machine live information and synthesized configuration",
)
def get_local_device():
    """Captures live network interfaces, firewall, listening ports, and config of this PC."""
    info = collect_local_device_info()
    config = generate_local_device_config(info)
    return {
        "info": info,
        "config": config,
    }


@router.post(
    "/live-device/local-audit",
    response_model=LiveFetchResponse,
    summary="Audit the current host machine (this PC) for compliance",
)
def audit_local_device():
    """Captures live config of this machine and runs compliance analysis."""
    info = collect_local_device_info()
    raw_config = generate_local_device_config(info)
    source_label = f"localhost:{info['hostname']}"

    analysis_result = analyze_config(
        config=raw_config,
        source_file=source_label,
    )
    result_dict = analysis_result.to_dict()

    _save_to_db(
        hostname=info["hostname"],
        raw_config=raw_config,
        source="local_host",
        result_dict=result_dict,
    )

    return LiveFetchResponse(
        host=info["hostname"],
        device_type="local_host",
        transport="local_collector",
        raw_config=raw_config,
        analysis=AnalysisResponse(**result_dict),
    )


@router.post(
    "/live-fetch",
    response_model=LiveFetchResponse,
    summary="Fetch live device config and run compliance analysis",
    description=(
        "Connect to a live network device via SSH (Netmiko) or NAPALM, "
        "pull its running configuration, auto-detect the vendor, and return "
        "the full compliance analysis with remediations. "
        "Compatible with Cisco, Juniper, Palo Alto, Arista, Fortinet, Huawei, "
        "Localhost / Current PC, and any device supported by the transport."
    ),
)
def live_fetch_and_analyze(request: LiveFetchRequest) -> LiveFetchResponse:
    """
    Fetch a live device config and analyze it for compliance.

    Steps:
      1. Connect to the device using the specified transport (SSH or NAPALM) or local collector.
      2. Retrieve the running configuration as plain text.
      3. Pass the raw config into the standard analyze_config() pipeline.
      4. Return the raw config + full analysis result.
    """
    local_hostnames = {
        "127.0.0.1",
        "localhost",
        "this_device",
        "my_device",
        "local",
        socket.gethostname().lower(),
    }
    is_local = (
        request.host.lower() in local_hostnames
        or request.device_type.lower() in ("localhost", "local_host", "windows", "host", "pc", "laptop")
    )

    if is_local:
        info = collect_local_device_info()
        raw_config = generate_local_device_config(info)
        source_label = f"live:{info['hostname']}:localhost"
    else:
        fetch_cfg = LiveFetchConfig(
            host=request.host,
            username=request.username,
            password=request.password,
            device_type=request.device_type,
            transport=Transport(request.transport),
            port=request.port,
            secret=request.secret or "",
            timeout=request.timeout,
            session_timeout=request.session_timeout,
            optional_args=request.optional_args,
        )

        try:
            raw_config = fetch_live_config(fetch_cfg)
        except LiveFetchError as exc:
            raise HTTPException(
                status_code=502,
                detail=f"Failed to retrieve configuration from device: {exc}",
            )
        except ImportError as exc:
            raise HTTPException(
                status_code=500,
                detail=str(exc),
            )

        source_label = f"live:{request.host}:{request.device_type}"

    analysis_result = analyze_config(
        config=raw_config,
        source_file=source_label,
    )
    result_dict = analysis_result.to_dict()

    # Persist to database (best-effort)
    _save_to_db(
        hostname=request.host,
        raw_config=raw_config,
        source=f"live_{request.transport}" if not is_local else "local_host",
        result_dict=result_dict,
    )

    return LiveFetchResponse(
        host=request.host,
        device_type=request.device_type,
        transport=request.transport if not is_local else "local_collector",
        raw_config=raw_config,
        analysis=AnalysisResponse(**result_dict),
    )

