"""
Mapper: CVE JSON 2.x (DWF/legacy) → unified CveRecord.

The v2 format uses ALL_CAPS field names and stores multilingual text as
``{"eng": "...", "ger": "...", …}`` dicts rather than arrays.
Numeric data (CVSS scores) are broken into BM/TM/EM sub-objects with
single-letter abbreviated keys.
"""

from __future__ import annotations

import re
from typing import Any

from ..models import (
    AffectedProduct,
    Credit,
    CveRecord,
    CveState,
    CvssMetric,
    CvssVersion,
    LocalizedText,
    ProblemType,
    Reference,
    TimelineEntry,
    VersionRange,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_STATE_MAP: dict[str, CveState] = {
    "PUBLIC":    CveState.PUBLISHED,
    "PUBLISHED": CveState.PUBLISHED,
    "REJECT":    CveState.REJECTED,
    "REJECTED":  CveState.REJECTED,
    "RESERVED":  CveState.RESERVED,
}

# Pattern for v2 version strings with leading comparison operators
_VERSION_OP_RE = re.compile(r"^(>=|<=|>|<)\s*(.+)$")


def _localized(obj: Any) -> list[LocalizedText]:
    """Convert a v2 lang-keyed dict to a list of LocalizedText."""
    if not isinstance(obj, dict):
        return []
    return [
        LocalizedText(lang=lang, value=text)
        for lang, text in obj.items()
        if lang != "DATA_VERSION" and isinstance(text, str)
    ]


def _parse_version_string(v: str) -> VersionRange:
    """
    Turn a v2 version string (possibly with a leading operator) into a
    VersionRange.  Examples: ``"1.0"``, ``">=2.0"``, ``"<3.5"``.
    """
    m = _VERSION_OP_RE.match(v.strip())
    if not m:
        return VersionRange(version=v.strip())
    op, ver = m.group(1), m.group(2).strip()
    if op == ">=":
        return VersionRange(greater_equal=ver)
    if op == ">":
        return VersionRange(greater_than=ver)
    if op == "<=":
        return VersionRange(less_equal=ver)
    # op == "<"
    return VersionRange(less_than=ver)


def _cvss2_vector(bm: dict) -> str | None:
    """Reconstruct a CVSSv2 vector string from BM components."""
    keys = [("AV", "AV"), ("AC", "AC"), ("Au", "AU"), ("C", "C"), ("I", "I"), ("A", "A")]
    parts = [f"{label}:{bm[src]}" for label, src in keys if bm.get(src)]
    return "/".join(parts) if parts else None


def _cvss3_vector(bm: dict) -> str | None:
    """Reconstruct a CVSSv3 vector string from BM components (without prefix)."""
    keys = [
        ("AV", "AV"), ("AC", "AC"), ("PR", "PR"), ("UI", "UI"),
        ("S", "S"), ("C", "C"), ("I", "I"), ("A", "A"),
    ]
    parts = [f"{label}:{bm[src]}" for label, src in keys if bm.get(src)]
    return "CVSS:3.x/" + "/".join(parts) if parts else None


def _parse_cvss2(obj: dict) -> CvssMetric:
    bm = obj.get("BM", {})
    tm = obj.get("TM", {})
    return CvssMetric(
        version=CvssVersion.V2,
        vector_string=_cvss2_vector(bm),
        base_score=_float(bm.get("SCORE")),
        temporal_score=_float(tm.get("SCORE")),
        raw=obj,
    )


def _parse_cvss3(obj: dict) -> CvssMetric:
    bm = obj.get("BM", {})
    tm = obj.get("TM", {})
    return CvssMetric(
        version=CvssVersion.V3_1,   # v2 spec predates 3.1 distinction; treat as 3.x
        vector_string=_cvss3_vector(bm),
        base_score=_float(bm.get("SCORE")),
        temporal_score=_float(tm.get("SCORE")),
        raw=obj,
    )


def _float(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Sub-section parsers
# ---------------------------------------------------------------------------

def _parse_problem_type(pt: dict) -> list[ProblemType]:
    """Parse DWF.PROBLEM_TYPE — a single object (not an array) in v2."""
    if not isinstance(pt, dict):
        return []
    return [ProblemType(
        cwe_id=pt.get("CWE") or None,
        owasp_id=pt.get("OWASP") or None,
        description=_localized(pt.get("DESCRIPTION", {})),
    )]


def _parse_affects(affects: list) -> list[AffectedProduct]:
    out: list[AffectedProduct] = []
    for entry in affects or []:
        if not isinstance(entry, dict):
            continue
        versions: list[VersionRange] = []
        for v in entry.get("AFFECTED", []):
            vr = _parse_version_string(str(v))
            vr.status = "affected"
            versions.append(vr)
        for v in entry.get("FIXEDIN", []):
            vr = _parse_version_string(str(v))
            vr.status = "unaffected"
            versions.append(vr)
        out.append(AffectedProduct(
            vendor=entry.get("VENDOR"),
            product=entry.get("PRODUCT"),
            cpe=entry.get("CPE"),
            swid=entry.get("SWID"),
            product_url=entry.get("URL"),
            versions=versions,
        ))
    return out


def _parse_references(refs: list) -> list[Reference]:
    out: list[Reference] = []
    for ref in refs or []:
        if not isinstance(ref, dict):
            continue
        desc = _localized(ref.get("DESCRIPTION", {}))
        ref_type = ref.get("TYPE")
        name = ref.get("NAME")
        for f in ref.get("FILES", []):
            url = f.get("URL", "")
            if url:
                out.append(Reference(
                    url=url,
                    name=name,
                    ref_type=ref_type,
                    description=desc,
                ))
    return out


def _parse_credits(credits: list) -> list[Credit]:
    out: list[Credit] = []
    for entry in credits or []:
        if not isinstance(entry, dict):
            continue
        identifiers = {k: v for k, v in (entry.get("ID") or {}).items()
                       if isinstance(v, str)}
        roles = entry.get("ROLE", [])
        out.append(Credit(identifiers=identifiers, roles=roles))
    return out


def _parse_timeline(timeline: list) -> list[TimelineEntry]:
    out: list[TimelineEntry] = []
    for entry in timeline or []:
        if not isinstance(entry, dict):
            continue
        text_obj = entry.get("TEXT", {})
        lang = next((k for k in text_obj if k != "DATA_VERSION"), None)
        value = text_obj.get(lang, "") if lang else ""
        out.append(TimelineEntry(
            timestamp=entry.get("TIMESTAMP"),
            lang=lang,
            value=value,
        ))
    return out


def _parse_metrics(dwf: dict) -> list[CvssMetric]:
    metrics: list[CvssMetric] = []
    if "CVSSv2" in dwf and isinstance(dwf["CVSSv2"], dict):
        metrics.append(_parse_cvss2(dwf["CVSSv2"]))
    if "CVSSv3" in dwf and isinstance(dwf["CVSSv3"], dict):
        metrics.append(_parse_cvss3(dwf["CVSSv3"]))
    return metrics


# ---------------------------------------------------------------------------
# Top-level mapper
# ---------------------------------------------------------------------------

def from_v2(raw: dict[str, Any]) -> CveRecord:
    """Convert a decoded CVE JSON 2.x dict into a unified CveRecord."""
    dwf: dict = raw.get("DWF", {})

    state_str = str(raw.get("STATE", "")).upper()
    state = _STATE_MAP.get(state_str, CveState.UNKNOWN)

    descriptions = _localized(dwf.get("DESCRIPTION", {}))
    impact       = _localized(dwf.get("IMPACT", {}))
    workarounds  = _localized(dwf.get("WORKAROUND", {}))
    exploits     = _localized(dwf.get("EXPLOITATION", {}))
    notes        = _localized(raw.get("NOTES", {}))

    return CveRecord(
        cve_id=raw.get("CVE_ID", ""),
        state=state,
        title=raw.get("TITLE"),
        replaced_by=[raw["REPLACED_BY"]] if raw.get("REPLACED_BY") else [],
        date_public=raw.get("DATE_PUBLIC"),
        date_assigned=raw.get("DATE_ASSIGNED"),
        date_requested=raw.get("DATE_REQUESTED"),
        date_updated=raw.get("UPDATED"),
        assigner=raw.get("ASSIGNER"),
        requester=raw.get("REQUESTER"),
        descriptions=descriptions,
        problem_types=_parse_problem_type(dwf.get("PROBLEM_TYPE", {})),
        affected=_parse_affects(dwf.get("AFFECTS", [])),
        references=_parse_references(dwf.get("REFERENCES", [])),
        metrics=_parse_metrics(dwf),
        credits=_parse_credits(dwf.get("CREDITS", [])),
        timeline=_parse_timeline(dwf.get("TIMELINE", [])),
        workarounds=workarounds,
        exploits=exploits,
        impact=impact,
        notes=notes,
        source_schema="v2",
        raw=raw,
    )
