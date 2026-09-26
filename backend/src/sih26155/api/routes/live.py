"""
Live configuration fetch endpoint.

POST /api/live-fetch
    Connects to a live network device, retrieves its running
    configuration, auto-detects the vendor, and runs the full
    compliance + remediation pipeline.  Works with any device type
    supported by Netmiko (SSH) or NAPALM.
"""

from fastapi import APIRouter, HTTPException

from sih26155.api.routes.analysis import _save_to_db
from sih26155.api.schemas import AnalysisResponse, LiveFetchRequest, LiveFetchResponse
from sih26155.core.pipeline.analyze import analyze_config
from sih26155.ingestion.live_fetch import LiveFetchConfig, LiveFetchError, Transport, fetch_live_config


router = APIRouter(
    prefix="/api",
    tags=["live-fetch"],
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
        "and any other device type supported by the chosen transport library."
    ),
)
def live_fetch_and_analyze(request: LiveFetchRequest) -> LiveFetchResponse:
    """
    Fetch a live device config and analyze it for compliance.

    Steps:
      1. Connect to the device using the specified transport (SSH or NAPALM).
      2. Retrieve the running configuration as plain text.
      3. Pass the raw config into the standard analyze_config() pipeline
         (vendor detection -> parsing -> normalization -> evaluation -> remediation).
      4. Return the raw config + full analysis result.
    """
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

    # Source file label shown in reports
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
        source=f"live_{request.transport}",
        result_dict=result_dict,
    )

    return LiveFetchResponse(
        host=request.host,
        device_type=request.device_type,
        transport=request.transport,
        raw_config=raw_config,
        analysis=AnalysisResponse(**result_dict),
    )
