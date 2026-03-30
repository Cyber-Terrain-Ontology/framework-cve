"""
Merge two CveRecord instances for the same CVE into one unified record.

Strategy
--------
* The v5 record is always *primary* (more structured, canonical CNA data).
  If both records share the same schema, r1 is primary.
* Scalar fields: primary wins; secondary fills any gap where primary is None.
* List fields: keyed deduplication — primary's entry wins on key collision,
  secondary contributes entries with keys absent from primary.
* Credits and timeline entries: concatenated (no reliable deduplication key).
* raw: stored as {"v2": <raw>, "v5": <raw>} for downstream provenance use.
"""

from __future__ import annotations

# ISO 639-2 (three-letter) → BCP-47 (two-letter) normalisation map.
# v2 records use ISO 639-2 keys ("eng", "ger"); v5 uses BCP-47 ("en", "de").
# Normalising before keying prevents the same-language content from surviving
# deduplication as two separate entries.
_ISO639_2_TO_BCP47: dict[str, str] = {
    "eng": "en", "ger": "de", "deu": "de", "fra": "fr", "fre": "fr",
    "spa": "es", "por": "pt", "ita": "it", "jpn": "ja", "zho": "zh",
    "chi": "zh", "kor": "ko", "ara": "ar", "rus": "ru", "nld": "nl",
    "dut": "nl", "pol": "pl", "swe": "sv", "dan": "da", "nor": "no",
    "fin": "fi", "hun": "hu", "ces": "cs", "cze": "cs", "slk": "sk",
    "ron": "ro", "rum": "ro", "bul": "bg", "hrv": "hr", "srp": "sr",
    "ukr": "uk", "heb": "he", "tur": "tr", "vie": "vi", "tha": "th",
    "ind": "id", "msa": "ms", "may": "ms",
}


def _normalize_lang(lang: str) -> str:
    """Normalise an ISO 639-2 or BCP-47 language tag to its BCP-47 form."""
    return _ISO639_2_TO_BCP47.get(lang.lower(), lang.lower())


from ..models import (
    AffectedProduct,
    CveRecord,
    CveState,
    CvssMetric,
    LocalizedText,
    ProblemType,
    Reference,
    VersionRange,
)


# ---------------------------------------------------------------------------
# List union helpers — each keyed on a natural identifier
# ---------------------------------------------------------------------------

def _union_by_lang(
    primary: list[LocalizedText],
    secondary: list[LocalizedText],
) -> list[LocalizedText]:
    """
    Union localised text lists by normalised language tag; primary wins on collision.

    Language tags are normalised to BCP-47 before keying so that ISO 639-2
    "eng" (v2) and BCP-47 "en" (v5) are treated as the same language.
    The winning entry's original ``lang`` value is preserved.
    """
    merged: dict[str, LocalizedText] = {_normalize_lang(lt.lang): lt for lt in secondary}
    merged.update({_normalize_lang(lt.lang): lt for lt in primary})
    return list(merged.values())


def _union_version_ranges(
    primary: list[VersionRange],
    secondary: list[VersionRange],
) -> list[VersionRange]:
    """Deduplicate version ranges by their full constraint signature."""
    def _key(vr: VersionRange) -> str:
        return "|".join([
            vr.version or "",
            vr.less_than or "",
            vr.less_equal or "",
            vr.greater_equal or "",
            vr.greater_than or "",
            vr.status,
        ])
    merged: dict[str, VersionRange] = {_key(vr): vr for vr in secondary}
    merged.update({_key(vr): vr for vr in primary})
    return list(merged.values())


def _union_affected(
    primary: list[AffectedProduct],
    secondary: list[AffectedProduct],
) -> list[AffectedProduct]:
    """
    Union affected-product lists by (vendor, product) key.

    When both records describe the same product, primary wins for all scalar
    fields but version ranges are merged.  v5 typically adds purl/collectionURL
    while v2 may add CPE/SWID — so absent fields are backfilled from secondary.
    """
    def _key(p: AffectedProduct) -> tuple[str, str]:
        return (p.vendor or "", p.product or "")

    sec_map: dict[tuple, AffectedProduct] = {_key(p): p for p in secondary}
    result: list[AffectedProduct] = []

    for p in primary:
        k = _key(p)
        if k in sec_map:
            sec = sec_map.pop(k)
            result.append(p.model_copy(update={
                # primary wins for identity/metadata scalars
                "cpe":            p.cpe            or sec.cpe,
                "purl":           p.purl           or sec.purl,
                "swid":           p.swid           or sec.swid,
                "product_url":    p.product_url    or sec.product_url,
                "collection_url": p.collection_url or sec.collection_url,
                "package_name":   p.package_name   or sec.package_name,
                "versions":       _union_version_ranges(p.versions, sec.versions),
            }))
        else:
            result.append(p)

    # append any products present only in secondary
    result.extend(sec_map.values())
    return result


def _union_references(
    primary: list[Reference],
    secondary: list[Reference],
) -> list[Reference]:
    """Union references by URL; primary wins for name/type, tags are merged."""
    sec_map: dict[str, Reference] = {r.url: r for r in secondary}
    result: list[Reference] = []

    for r in primary:
        if r.url in sec_map:
            sec = sec_map.pop(r.url)
            result.append(r.model_copy(update={
                "name":        r.name     or sec.name,
                "ref_type":    r.ref_type or sec.ref_type,
                "tags":        sorted({*r.tags, *sec.tags}),
                "description": _union_by_lang(r.description, sec.description),
            }))
        else:
            result.append(r)

    result.extend(sec_map.values())
    return result


def _union_metrics(
    primary: list[CvssMetric],
    secondary: list[CvssMetric],
) -> list[CvssMetric]:
    """Union CVSS metrics by version; primary wins on version collision."""
    merged: dict = {m.version: m for m in secondary}
    merged.update({m.version: m for m in primary})
    return list(merged.values())


def _union_problem_types(
    primary: list[ProblemType],
    secondary: list[ProblemType],
) -> list[ProblemType]:
    """
    Union problem types, matching on CWE ID first, then OWASP, then description text.

    Keying on CWE alone (not the combination of CWE+OWASP) ensures that a v5
    entry with only CWE-917 correctly merges with a v2 entry carrying
    CWE-917 + OWASP A1, rather than being treated as two distinct problems.
    """
    def _key(pt: ProblemType) -> str:
        if pt.cwe_id:
            return f"cwe:{pt.cwe_id}"
        if pt.owasp_id:
            return f"owasp:{pt.owasp_id}"
        if pt.description:
            return f"desc:{pt.description[0].value[:80]}"
        return ""

    sec_map: dict[tuple, ProblemType] = {_key(pt): pt for pt in secondary}
    result: list[ProblemType] = []

    for pt in primary:
        k = _key(pt)
        if k in sec_map:
            sec = sec_map.pop(k)
            result.append(pt.model_copy(update={
                "owasp_id":    pt.owasp_id    or sec.owasp_id,
                "description": _union_by_lang(pt.description, sec.description),
            }))
        else:
            result.append(pt)

    result.extend(sec_map.values())
    return result


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def merge(r1: CveRecord, r2: CveRecord) -> CveRecord:
    """
    Merge two :class:`CveRecord` instances for the same CVE.

    Parameters
    ----------
    r1, r2:
        Records to merge.  They must share the same ``cve_id``.

    Returns
    -------
    CveRecord
        A single record with ``source_schema == "v2+v5"``.  The ``raw``
        field is ``{"v2": <original raw>, "v5": <original raw>}`` for
        downstream provenance use.

    Raises
    ------
    ValueError
        If ``r1.cve_id != r2.cve_id``.
    """
    if r1.cve_id != r2.cve_id:
        raise ValueError(
            f"Cannot merge records for different CVEs: {r1.cve_id!r} vs {r2.cve_id!r}"
        )

    # v5 is canonical — always use it as the primary source
    if r2.source_schema == "v5" and r1.source_schema != "v5":
        primary, secondary = r2, r1
    else:
        primary, secondary = r1, r2

    return CveRecord(
        # --- Identity & lifecycle -------------------------------------------
        cve_id=primary.cve_id,
        state=(primary.state
               if primary.state != CveState.UNKNOWN
               else secondary.state),
        title=primary.title or secondary.title,
        replaced_by=sorted({*primary.replaced_by, *secondary.replaced_by}),

        # --- Dates -----------------------------------------------------------
        date_public=primary.date_public       or secondary.date_public,
        date_assigned=primary.date_assigned   or secondary.date_assigned,
        date_requested=primary.date_requested or secondary.date_requested,
        date_updated=primary.date_updated     or secondary.date_updated,

        # --- Attribution -----------------------------------------------------
        assigner=primary.assigner   or secondary.assigner,
        requester=primary.requester or secondary.requester,

        # --- Core data -------------------------------------------------------
        descriptions=_union_by_lang(primary.descriptions,   secondary.descriptions),
        problem_types=_union_problem_types(primary.problem_types, secondary.problem_types),
        affected=_union_affected(primary.affected, secondary.affected),
        references=_union_references(primary.references, secondary.references),
        metrics=_union_metrics(primary.metrics, secondary.metrics),

        # --- Supplementary ---------------------------------------------------
        # Credits and timeline have no reliable dedup key — concatenate.
        credits=[*primary.credits, *secondary.credits],
        timeline=sorted(
            [*primary.timeline, *secondary.timeline],
            key=lambda t: str(t.timestamp or ""),
        ),
        workarounds=_union_by_lang(primary.workarounds, secondary.workarounds),
        exploits=_union_by_lang(primary.exploits,   secondary.exploits),
        solutions=_union_by_lang(primary.solutions,  secondary.solutions),
        impact=_union_by_lang(primary.impact,     secondary.impact),
        notes=_union_by_lang(primary.notes,      secondary.notes),

        # --- Provenance ------------------------------------------------------
        source_schema="v2+v5",
        raw={
            primary.source_schema:   primary.raw,
            secondary.source_schema: secondary.raw,
        },
    )
