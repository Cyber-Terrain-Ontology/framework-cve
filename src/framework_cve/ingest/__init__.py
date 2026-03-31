"""
Ingestion entry point.  Detects schema version and delegates to the
appropriate mapper.

Usage::

    import json
    from framework_cve import ingest

    with open("CVE-2021-44228.json") as f:
        record = ingest(json.load(f))
"""

from __future__ import annotations

from typing import Any

from ..models import CveRecord
from .v2 import from_v2
from .v5 import from_v5


def detect_version(raw: dict[str, Any]) -> str:
    """Return ``'v2'`` or ``'v5'`` based on the raw record's shape."""
    # v5 records always have a top-level 'dataType' == 'CVE_RECORD' and
    # a 'dataVersion' starting with '5.'
    if raw.get("dataType") == "CVE_RECORD":
        return "v5"
    dv = str(raw.get("dataVersion", raw.get("DATA_VERSION", "")))
    if dv.startswith("5"):
        return "v5"
    if dv.startswith("2"):
        return "v2"
    # Heuristic: v2 uses ALL_CAPS keys at the root
    if "CVE_ID" in raw or "DWF" in raw:
        return "v2"
    # v5 uses camelCase keys
    if "cveMetadata" in raw or "containers" in raw:
        return "v5"
    raise ValueError(f"Cannot detect CVE schema version from record keys: {list(raw)[:8]}")


def ingest(raw: dict[str, Any]) -> CveRecord:
    """Parse *raw* (already-decoded JSON dict) into a unified :class:`CveRecord`."""
    version = detect_version(raw)
    if version == "v2":
        return from_v2(raw)
    return from_v5(raw)
