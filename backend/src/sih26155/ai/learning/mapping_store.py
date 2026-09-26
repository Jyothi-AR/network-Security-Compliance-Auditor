"""
Adaptive Learning — Mapping Store.

Persists learned vendor signature and field mapping patterns to a JSON
file on disk so the engine can recognise new vendors and formats without
any code redeployment.

Schema of the store file (mappings_store.json):
{
  "vendors": {
    "<vendor_id>": {
      "display_name": "...",
      "signatures": ["...", "..."],
      "field_mappings": {
        "<semantic_field>": "<regex_pattern>"
      },
      "added_by": "user | system",
      "created_at": "ISO-8601"
    }
  }
}
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_DEFAULT_STORE_PATH = Path("data/mappings/learned_vendors.json")
_lock = threading.Lock()


class MappingStoreError(Exception):
    """Raised when the mapping store cannot be read or written."""


def _load(store_path: Path) -> dict[str, Any]:
    if not store_path.exists():
        return {"vendors": {}}
    try:
        return json.loads(store_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise MappingStoreError(f"Corrupt mapping store at {store_path}: {exc}") from exc


def _save(data: dict[str, Any], store_path: Path) -> None:
    store_path.parent.mkdir(parents=True, exist_ok=True)
    store_path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def register_vendor(
    vendor_id: str,
    display_name: str,
    signatures: list[str],
    field_mappings: dict[str, str],
    added_by: str = "user",
    store_path: Path = _DEFAULT_STORE_PATH,
) -> None:
    """
    Register a new vendor pattern or overwrite an existing one.

    Args:
        vendor_id:      Unique slug (e.g. ``"sonic_os"``).
        display_name:   Human-readable name shown in reports.
        signatures:     List of config text patterns that uniquely identify
                        this vendor (same format as VENDOR_SIGNATURES).
        field_mappings: Dict mapping semantic fields (e.g. ``"ssh_enabled"``)
                        to regex patterns that extract their values.
        added_by:       ``"user"`` or ``"system"``.
        store_path:     Path to the persistent JSON store.
    """
    with _lock:
        data = _load(store_path)
        data["vendors"][vendor_id] = {
            "display_name": display_name,
            "signatures": signatures,
            "field_mappings": field_mappings,
            "added_by": added_by,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        _save(data, store_path)


def list_vendors(
    store_path: Path = _DEFAULT_STORE_PATH,
) -> list[dict[str, Any]]:
    """Return all learned vendor entries."""
    with _lock:
        data = _load(store_path)
    return [
        {"vendor_id": vid, **info}
        for vid, info in data.get("vendors", {}).items()
    ]


def get_vendor(
    vendor_id: str,
    store_path: Path = _DEFAULT_STORE_PATH,
) -> dict[str, Any] | None:
    """Return a single vendor entry or None if not found."""
    with _lock:
        data = _load(store_path)
    return data.get("vendors", {}).get(vendor_id)


def delete_vendor(
    vendor_id: str,
    store_path: Path = _DEFAULT_STORE_PATH,
) -> bool:
    """
    Remove a learned vendor. Returns True if deleted, False if not found.
    """
    with _lock:
        data = _load(store_path)
        if vendor_id not in data.get("vendors", {}):
            return False
        del data["vendors"][vendor_id]
        _save(data, store_path)
    return True


def get_learned_signatures(
    store_path: Path = _DEFAULT_STORE_PATH,
) -> dict[str, tuple[str, ...]]:
    """
    Return a dict keyed by vendor_id with signature tuples, ready to be
    merged into VENDOR_SIGNATURES for runtime detection.
    """
    with _lock:
        data = _load(store_path)
    return {
        vid: tuple(info["signatures"])
        for vid, info in data.get("vendors", {}).items()
    }
