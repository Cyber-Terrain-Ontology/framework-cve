"""
Mapper: CVE JSON 5.x (CNA format, versions 5.0 – 5.2+) → unified CveRecord.

v5 records have a ``dataType == "CVE_RECORD"`` root with two top-level keys:

* ``cveMetadata``  — identity, lifecycle, dates, assigner
* ``containers``   — ``cna`` (authoritative) and zero or more ``adp``
                     (additional data providers)

We read from the ``cna`` container (canonical authority) and fall back to the
first ``adp`` container when a field is absent.
"""

from __future__ import annotations

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
    "PUBLISHED": CveState.PUBLISHED,
    "REJECTED":  CveState.REJECTED,
    "RESERVED":  CveState.RESERVED,
}

_CVSS_VERSION_MAP: dict[str, CvssVersion] = {
    "cvssV2_0": CvssVersion.V2,
    "cvssV3_0": CvssVersion.V3_0,
    "cvssV3_1": CvssVersion.V3_1,
    "cvssV4_0": CvssVersion.V4_0,
}


def _localized(arr: list[dict]) -> list[LocalizedText]:
    """Convert a v5 descriptions/workarounds/etc. array to LocalizedText list."""
    out: list[LocalizedText] = []
    for item in arr or []:
        lang  = item.get("lang", "en")
        value = item.get("value", item.get("supportingMedia", ""))
        if isinstance(value, str) and value:
            out.append(LocalizedText(lang=lang, value=value))
    return out


def _float(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Sub-section parsers
# ---------------------------------------------------------------------------

def _parse_problem_types(pt_list: list) -> list[ProblemType]:
    out: list[ProblemType] = []
    for group in pt_list or []:
        for desc in group.get("descriptions", []):
            cwe_id = desc.get("cweId")
            owasp  = None  # v5 does not have a dedicated OWASP field
            out.append(ProblemType(
                cwe_id=cwe_id,
                owasp_id=owasp,
                description=[LocalizedText(lang=desc.get("lang", "en"), value=desc.get("description", ""))]
                            if desc.get("description") else [],
                type=desc.get("type"),
            ))
    return out


def _parse_versions(ver_list: list) -> list[VersionRange]:
    out: list[VersionRange] = []
    for v in ver_list or []:
        status = v.get("status", "affected")
        out.append(VersionRange(
            version=v.get("version"),
            version_type=v.get("versionType"),
            less_than=v.get("lessThan"),
            less_equal=v.get("lessThanOrEqual"),
            status=status,
        ))
    return out


def _parse_affected(affected_list: list) -> list[AffectedProduct]:
    out: list[AffectedProduct] = []
    for entry in affected_list or []:
        out.append(AffectedProduct(
            vendor=entry.get("vendor"),
            product=entry.get("product"),
            collection_url=entry.get("collectionURL"),
            package_name=entry.get("packageName"),
            purl=entry.get("packageURL") or entry.get("purl"),
            cpe=entry.get("cpe"),
            versions=_parse_versions(entry.get("versions", [])),
            default_status=entry.get("defaultStatus"),
        ))
    return out


def _parse_references(refs: list) -> list[Reference]:
    return [
        Reference(
            url=r["url"],
            name=r.get("name"),
            tags=r.get("tags", []),
        )
        for r in refs or []
        if r.get("url")
    ]


def _parse_metrics(metrics_list: list) -> list[CvssMetric]:
    out: list[CvssMetric] = []
    for m in metrics_list or []:
        for key, cvss_version in _CVSS_VERSION_MAP.items():
            obj = m.get(key)
            if not isinstance(obj, dict):
                continue
            out.append(CvssMetric(
                version=cvss_version,
                vector_string=obj.get("vectorString"),
                base_score=_float(obj.get("baseScore")),
                base_severity=obj.get("baseSeverity"),
                raw=obj,
            ))
        # v5 also allows format-agnostic "other" metrics — skip for now
    return out


def _parse_credits(credits_list: list) -> list[Credit]:
    out: list[Credit] = []
    for c in credits_list or []:
        out.append(Credit(
            name=c.get("value"),
            lang=c.get("lang"),
            roles=[c["type"]] if c.get("type") else [],
        ))
    return out


def _parse_timeline(timeline_list: list) -> list[TimelineEntry]:
    out: list[TimelineEntry] = []
    for entry in timeline_list or []:
        out.append(TimelineEntry(
            timestamp=entry.get("time"),
            lang=entry.get("lang"),
            value=entry.get("value"),
        ))
    return out


def _localized_container(items: list) -> list[LocalizedText]:
    """Generic mapper for v5 arrays of {lang, value} objects."""
    return _localized(items)


# ---------------------------------------------------------------------------
# Top-level mapper
# ---------------------------------------------------------------------------

def from_v5(raw: dict[str, Any]) -> CveRecord:
    """Convert a decoded CVE JSON 5.x dict into a unified CveRecord."""
    meta: dict       = raw.get("cveMetadata", {})
    containers: dict = raw.get("containers", {})
    cna: dict        = containers.get("cna", {})

    state_str = str(meta.get("state", "")).upper()
    state = _STATE_MAP.get(state_str, CveState.UNKNOWN)

    # Assigner: prefer shortName, fall back to orgId UUID
    assigner = meta.get("assignerShortName") or meta.get("assignerOrgId")

    # Merge ADP containers as supplementary data (de-duplicated in practice
    # by keeping cna as canonical and appending adp extras).
    adp_list: list[dict] = containers.get("adp", [])

    def _from_cna_or_adp(field: str, default: Any = None) -> Any:
        val = cna.get(field)
        if val:
            return val
        for adp in adp_list:
            val = adp.get(field)
            if val:
                return val
        return default

    descriptions = _localized(_from_cna_or_adp("descriptions", []))
    workarounds  = _localized(_from_cna_or_adp("workarounds", []))
    exploits     = _localized(_from_cna_or_adp("exploits", []))
    solutions    = _localized(_from_cna_or_adp("solutions", []))
    impact       = _localized(_from_cna_or_adp("impacts", []))

    # replacedBy is an array of CVE IDs in v5
    replaced_by_raw = meta.get("replacedBy", [])
    replaced_by = replaced_by_raw if isinstance(replaced_by_raw, list) else [replaced_by_raw]

    return CveRecord(
        cve_id=meta.get("cveId", ""),
        state=state,
        title=cna.get("title"),
        replaced_by=replaced_by,
        date_public=meta.get("datePublished"),
        date_assigned=meta.get("dateReserved"),
        date_updated=meta.get("dateUpdated"),
        assigner=assigner,
        descriptions=descriptions,
        problem_types=_parse_problem_types(_from_cna_or_adp("problemTypes", [])),
        affected=_parse_affected(_from_cna_or_adp("affected", [])),
        references=_parse_references(_from_cna_or_adp("references", [])),
        metrics=_parse_metrics(_from_cna_or_adp("metrics", [])),
        credits=_parse_credits(_from_cna_or_adp("credits", [])),
        timeline=_parse_timeline(_from_cna_or_adp("timeline", [])),
        workarounds=workarounds,
        exploits=exploits,
        solutions=solutions,
        impact=impact,
        source_schema="v5",
        raw=raw,
    )
