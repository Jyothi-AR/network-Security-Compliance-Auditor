from fastapi import APIRouter

from sih26155.api.schemas import AnalysisRequest, AnalysisResponse
from sih26155.core.pipeline.analyze import analyze_config


router = APIRouter(
    prefix="/api",
    tags=["analysis"],
)


@router.post(
    "/analysis",
    response_model=AnalysisResponse,
)
def analyze(request: AnalysisRequest) -> AnalysisResponse:
    result = analyze_config(
        config=request.config,
        source_file=request.source_file,
    )
    result_dict = result.to_dict()

    # Persist to database (best-effort -- never fail the API response)
    _save_to_db(
        hostname=request.source_file,
        raw_config=request.config,
        source="upload",
        result_dict=result_dict,
    )

    return AnalysisResponse(**result_dict)


def _save_to_db(hostname: str, raw_config: str, source: str, result_dict: dict) -> None:
    """Persist analysis + config snapshot to PostgreSQL. Silently skips on error."""
    try:
        from sih26155.storage.database import get_db
        from sih26155.storage.repositories import (
            AnalysisRepository,
            ConfigSnapshotRepository,
            DeviceRepository,
        )
        vendor = result_dict.get("vendor", {}).get("name", "unknown")
        with get_db() as db:
            device = DeviceRepository(db).get_or_create(hostname=hostname, vendor=vendor)
            snap = ConfigSnapshotRepository(db).save(
                device_id=device.id, raw_config=raw_config, source=source
            )
            AnalysisRepository(db).save(
                device_id=device.id,
                snapshot_id=snap.id,
                result_dict=result_dict,
            )
    except Exception:
        pass  # DB unavailable -- degrade gracefully
