"""
Adaptive Learning API routes.

POST /api/learning/vendors          - Register a new vendor format
GET  /api/learning/vendors          - List all learned vendors
GET  /api/learning/vendors/{id}     - Get a specific vendor
DELETE /api/learning/vendors/{id}   - Remove a learned vendor
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from sih26155.ai.learning.mapping_store import (
    MappingStoreError,
    delete_vendor,
    get_vendor,
    list_vendors,
    register_vendor,
)

router = APIRouter(prefix="/api/learning", tags=["adaptive-learning"])


class VendorRegistrationRequest(BaseModel):
    vendor_id: str = Field(description="Unique slug e.g. 'sonic_os', 'vyos'")
    display_name: str = Field(description="Human-readable vendor name")
    signatures: list[str] = Field(
        description="Config text patterns that uniquely identify this vendor"
    )
    field_mappings: dict[str, str] = Field(
        default_factory=dict,
        description="Semantic field -> regex pattern for value extraction",
    )


@router.post("/vendors", summary="Register a new vendor format (adaptive learning)")
def register_vendor_endpoint(body: VendorRegistrationRequest) -> dict[str, Any]:
    try:
        register_vendor(
            vendor_id=body.vendor_id,
            display_name=body.display_name,
            signatures=body.signatures,
            field_mappings=body.field_mappings,
            added_by="user",
        )
    except MappingStoreError as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    return {"status": "registered", "vendor_id": body.vendor_id}


@router.get("/vendors", summary="List all learned vendor formats")
def list_vendors_endpoint() -> dict[str, Any]:
    return {"vendors": list_vendors()}


@router.get("/vendors/{vendor_id}", summary="Get a specific learned vendor")
def get_vendor_endpoint(vendor_id: str) -> dict[str, Any]:
    entry = get_vendor(vendor_id)
    if entry is None:
        raise HTTPException(status_code=404, detail=f"Vendor '{vendor_id}' not found.")
    return {"vendor_id": vendor_id, **entry}


@router.delete("/vendors/{vendor_id}", summary="Remove a learned vendor")
def delete_vendor_endpoint(vendor_id: str) -> dict[str, Any]:
    deleted = delete_vendor(vendor_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Vendor '{vendor_id}' not found.")
    return {"status": "deleted", "vendor_id": vendor_id}
