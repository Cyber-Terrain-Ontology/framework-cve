"""
Instance Turtle serializer — writes a single CveRecord as OWL-compliant RDF.

This is distinct from ``generator.py``, which produces the *schema* (TBox).
This module produces *instance data* (ABox): one named individual per CVE
record, with sub-objects as related named individuals linked by object
properties declared in the ontology.

IRI scheme
----------
Record:       <https://cve.org/CVERecord/{CVE-ID}>
Sub-objects:  <https://cve.org/CVERecord/{CVE-ID}#{type}_{key}>

    e.g. https://cve.org/CVERecord/CVE-2021-44228#desc_en
         https://cve.org/CVERecord/CVE-2021-44228#affected_0
         https://cve.org/CVERecord/CVE-2021-44228#metric_3_1

Provenance
----------
When ``source_schema == "v2+v5"`` the serializer emits PROV-O triples
linking the merged individual back to two source-record entities, one per
contributing schema version.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..models import (
    AffectedProduct,
    Credit,
    CveRecord,
    CvssMetric,
    LocalizedText,
    ProblemType,
    Reference,
    TimelineEntry,
    VersionRange,
)

# ---------------------------------------------------------------------------
# Namespace constants
# ---------------------------------------------------------------------------

CVE_RECORD_BASE  = "https://cve.org/CVERecord/"
ONTOLOGY_IRI     = "https://cyberterrain.org/ns/frameworks/cve"
CVE_NS           = "https://cyberterrain.org/ns/frameworks/cve#"

PREFIXES = """\
@prefix cve:  <https://cyberterrain.org/ns/frameworks/cve#> .
@prefix cveid: <https://cve.org/CVERecord/> .
@prefix owl:  <http://www.w3.org/2002/07/owl#> .
@prefix rdf:  <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix xsd:  <http://www.w3.org/2001/XMLSchema#> .
@prefix prov: <http://www.w3.org/ns/prov#> .
"""


# ---------------------------------------------------------------------------
# Low-level formatting helpers
# ---------------------------------------------------------------------------

def _esc(s: str) -> str:
    """Escape a string for use inside a Turtle double-quoted literal."""
    return (s.replace("\\", "\\\\")
             .replace('"',  '\\"')
             .replace("\n", "\\n")
             .replace("\r", "\\r"))


def _lit(value: Any, datatype: str | None = None, lang: str | None = None) -> str:
    """Format a Turtle literal."""
    s = _esc(str(value))
    if lang:
        return f'"{s}"@{lang}'
    if datatype:
        return f'"{s}"^^{datatype}'
    return f'"{s}"'


def _iri(cve_id: str, fragment: str | None = None) -> str:
    """Build a prefixed IRI for a CVE record or one of its sub-objects."""
    slug = cve_id  # e.g. CVE-2021-44228  — safe in a curie after cveid:
    if fragment:
        return f"<{CVE_RECORD_BASE}{slug}#{fragment}>"
    return f"cveid:{slug}"


def _slug(cve_id: str) -> str:
    """Compact token safe for use in fragment identifiers."""
    return cve_id.replace("-", "_").lower()


# ---------------------------------------------------------------------------
# Sub-object serialisers — each returns a list of (subject, pred, obj) tuples
# ---------------------------------------------------------------------------

Triple = tuple[str, str, str]


def _triples_localized(
    subject: str, lt: LocalizedText
) -> list[Triple]:
    return [
        (subject, "a", "cve:LocalizedText"),
        (subject, "cve:lang",  _lit(lt.lang)),
        (subject, "cve:value", _lit(lt.value, lang=lt.lang if len(lt.lang) <= 3 else None)),
    ]


def _triples_version_range(subject: str, vr: VersionRange) -> list[Triple]:
    triples: list[Triple] = [(subject, "a", "cve:VersionRange")]
    triples.append((subject, "cve:status", _lit(vr.status)))
    if vr.version:
        triples.append((subject, "cve:version", _lit(vr.version)))
    if vr.version_type:
        triples.append((subject, "cve:versionType", _lit(vr.version_type)))
    if vr.less_than:
        triples.append((subject, "cve:lessThan", _lit(vr.less_than)))
    if vr.less_equal:
        triples.append((subject, "cve:lessEqual", _lit(vr.less_equal)))
    if vr.greater_equal:
        triples.append((subject, "cve:greaterEqual", _lit(vr.greater_equal)))
    if vr.greater_than:
        triples.append((subject, "cve:greaterThan", _lit(vr.greater_than)))
    return triples


def _triples_problem_type(subject: str, pt: ProblemType) -> list[Triple]:
    triples: list[Triple] = [(subject, "a", "cve:ProblemType")]
    if pt.cwe_id:
        triples.append((subject, "cve:cweId", _lit(pt.cwe_id)))
    if pt.owasp_id:
        triples.append((subject, "cve:owaspId", _lit(pt.owasp_id)))
    if pt.type:
        triples.append((subject, "cve:type", _lit(pt.type)))
    return triples


def _triples_affected(subject: str, p: AffectedProduct) -> list[Triple]:
    triples: list[Triple] = [(subject, "a", "cve:AffectedProduct")]
    if p.vendor:
        triples.append((subject, "cve:vendor", _lit(p.vendor)))
    if p.product:
        triples.append((subject, "cve:product", _lit(p.product)))
    if p.cpe:
        triples.append((subject, "cve:cpe", _lit(p.cpe)))
    if p.purl:
        triples.append((subject, "cve:purl", _lit(p.purl)))
    if p.swid:
        triples.append((subject, "cve:swid", _lit(p.swid)))
    if p.product_url:
        triples.append((subject, "cve:productUrl", _lit(p.product_url)))
    if p.collection_url:
        triples.append((subject, "cve:collectionUrl", _lit(p.collection_url)))
    if p.package_name:
        triples.append((subject, "cve:packageName", _lit(p.package_name)))
    if p.default_status:
        triples.append((subject, "cve:defaultStatus", _lit(p.default_status)))
    return triples


def _triples_reference(subject: str, r: Reference) -> list[Triple]:
    triples: list[Triple] = [(subject, "a", "cve:Reference")]
    triples.append((subject, "cve:url", _lit(r.url, datatype="xsd:anyURI")))
    if r.name:
        triples.append((subject, "cve:name", _lit(r.name)))
    if r.ref_type:
        triples.append((subject, "cve:refType", _lit(r.ref_type)))
    for tag in r.tags:
        triples.append((subject, "cve:tags", _lit(tag)))
    return triples


def _triples_metric(subject: str, m: CvssMetric) -> list[Triple]:
    ver_iri = f"cve:{m.version.value.replace('.', '_')}"
    triples: list[Triple] = [
        (subject, "a",           "cve:CvssMetric"),
        (subject, "cve:version", ver_iri),
    ]
    if m.vector_string:
        triples.append((subject, "cve:vectorString", _lit(m.vector_string)))
    if m.base_score is not None:
        triples.append((subject, "cve:baseScore", _lit(m.base_score, datatype="xsd:decimal")))
    if m.base_severity:
        triples.append((subject, "cve:baseSeverity", _lit(m.base_severity)))
    if m.temporal_score is not None:
        triples.append((subject, "cve:temporalScore", _lit(m.temporal_score, datatype="xsd:decimal")))
    if m.environmental_score is not None:
        triples.append((subject, "cve:environmentalScore", _lit(m.environmental_score, datatype="xsd:decimal")))
    return triples


def _triples_credit(subject: str, c: Credit) -> list[Triple]:
    triples: list[Triple] = [(subject, "a", "cve:Credit")]
    if c.name:
        triples.append((subject, "cve:name", _lit(c.name)))
    if c.lang:
        triples.append((subject, "cve:lang", _lit(c.lang)))
    for role in c.roles:
        triples.append((subject, "cve:roles", _lit(role)))
    if c.identifiers:
        triples.append((subject, "cve:identifiers",
                         _lit(json.dumps(c.identifiers, ensure_ascii=False))))
    return triples


def _triples_timeline(subject: str, t: TimelineEntry) -> list[Triple]:
    triples: list[Triple] = [(subject, "a", "cve:TimelineEntry")]
    if t.timestamp:
        triples.append((subject, "cve:timestamp", _lit(str(t.timestamp))))
    if t.lang:
        triples.append((subject, "cve:lang", _lit(t.lang)))
    if t.value:
        triples.append((subject, "cve:value", _lit(t.value)))
    return triples


# ---------------------------------------------------------------------------
# Turtle block formatter
# ---------------------------------------------------------------------------

def _emit_subject(subject: str, triples: list[Triple]) -> str:
    """Format a list of triples sharing the same subject as a Turtle block."""
    if not triples:
        return ""
    lines = [f"{subject}"]
    for i, (_, pred, obj) in enumerate(triples):
        sep = " ;" if i < len(triples) - 1 else " ."
        lines.append(f"    {pred} {obj}{sep}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Top-level serialiser
# ---------------------------------------------------------------------------

def to_turtle(record: CveRecord, path: str | Path | None = None) -> str:
    """
    Serialize a :class:`CveRecord` to an OWL-compliant Turtle document.

    The document imports the CVE ontology TBox and represents the record as
    a single named individual plus linked sub-object individuals.

    Parameters
    ----------
    record:
        The unified record to serialise (from :func:`~framework_cve.ingest.ingest`
        or :func:`~framework_cve.ingest.merge.merge`).
    path:
        Optional file path to write the Turtle to.

    Returns
    -------
    str
        The complete Turtle document.
    """
    cid   = record.cve_id
    slug  = _slug(cid)
    rec   = _iri(cid)          # e.g. cveid:CVE-2021-44228
    parts: list[str] = []

    # -----------------------------------------------------------------------
    # Prefixes + ontology import
    # -----------------------------------------------------------------------
    parts.append(PREFIXES)
    parts.append(
        f"# Ontology import — brings the TBox into scope\n"
        f"{rec} owl:imports <{ONTOLOGY_IRI}> .\n"
    )

    # -----------------------------------------------------------------------
    # Provenance — only for merged records
    # -----------------------------------------------------------------------
    if record.source_schema == "v2+v5":
        src_v2 = f"<{CVE_RECORD_BASE}{cid}#source_v2>"
        src_v5 = f"<{CVE_RECORD_BASE}{cid}#source_v5>"
        parts.append(
            f"# --- Provenance ---------------------------------------------------\n"
            f"\n"
            f"{rec}\n"
            f"    prov:wasDerivedFrom {src_v2}, {src_v5} .\n"
            f"\n"
            f"{src_v2}\n"
            f"    a prov:Entity ;\n"
            f'    rdfs:label "{cid} (CVE JSON 2.x source)"@en .\n'
            f"\n"
            f"{src_v5}\n"
            f"    a prov:Entity ;\n"
            f'    rdfs:label "{cid} (CVE JSON 5.x source)"@en .\n'
        )

    # -----------------------------------------------------------------------
    # Main CveRecord individual — scalar properties
    # -----------------------------------------------------------------------
    rec_triples: list[Triple] = [(rec, "a", "cve:CveRecord")]
    rec_triples.append((rec, "cve:cveId",       _lit(cid)))
    rec_triples.append((rec, "cve:state",        f"cve:{record.state.value}"))
    rec_triples.append((rec, "cve:sourceSchema", _lit(record.source_schema)))

    if record.title:
        rec_triples.append((rec, "cve:title", _lit(record.title)))
    if record.assigner:
        rec_triples.append((rec, "cve:assigner", _lit(record.assigner)))
    if record.requester:
        rec_triples.append((rec, "cve:requester", _lit(record.requester)))
    if record.date_public:
        rec_triples.append((rec, "cve:datePublic", _lit(str(record.date_public))))
    if record.date_assigned:
        rec_triples.append((rec, "cve:dateAssigned", _lit(str(record.date_assigned))))
    if record.date_requested:
        rec_triples.append((rec, "cve:dateRequested", _lit(str(record.date_requested))))
    if record.date_updated:
        rec_triples.append((rec, "cve:dateUpdated", _lit(str(record.date_updated))))
    for cve_id_ref in record.replaced_by:
        rec_triples.append((rec, "cve:replacedBy", _lit(cve_id_ref)))

    # Object-property links to sub-object IRIs
    def _link(fragment: str) -> str:
        return f"<{CVE_RECORD_BASE}{cid}#{fragment}>"

    for i, _ in enumerate(record.descriptions):
        rec_triples.append((rec, "cve:descriptions", _link(f"desc_{i}")))
    for i, _ in enumerate(record.problem_types):
        rec_triples.append((rec, "cve:problemTypes", _link(f"pt_{i}")))
    for i, _ in enumerate(record.affected):
        rec_triples.append((rec, "cve:affected", _link(f"affected_{i}")))
    for i, _ in enumerate(record.references):
        rec_triples.append((rec, "cve:references", _link(f"ref_{i}")))
    for i, _ in enumerate(record.metrics):
        rec_triples.append((rec, "cve:metrics", _link(f"metric_{i}")))
    for i, _ in enumerate(record.credits):
        rec_triples.append((rec, "cve:credits", _link(f"credit_{i}")))
    for i, _ in enumerate(record.timeline):
        rec_triples.append((rec, "cve:timeline", _link(f"timeline_{i}")))
    for i, _ in enumerate(record.workarounds):
        rec_triples.append((rec, "cve:workarounds", _link(f"workaround_{i}")))
    for i, _ in enumerate(record.exploits):
        rec_triples.append((rec, "cve:exploits", _link(f"exploit_{i}")))
    for i, _ in enumerate(record.solutions):
        rec_triples.append((rec, "cve:solutions", _link(f"solution_{i}")))
    for i, _ in enumerate(record.impact):
        rec_triples.append((rec, "cve:impact", _link(f"impact_{i}")))
    for i, _ in enumerate(record.notes):
        rec_triples.append((rec, "cve:notes", _link(f"note_{i}")))

    parts.append(
        f"# --- CVE Record ---------------------------------------------------\n\n"
        + _emit_subject(rec, rec_triples)
    )

    # -----------------------------------------------------------------------
    # Sub-object individuals
    # -----------------------------------------------------------------------
    def _section(label: str) -> str:
        return f"\n# --- {label} {'-' * max(0, 51 - len(label))}\n\n"

    if record.descriptions:
        parts.append(_section("Descriptions"))
        for i, lt in enumerate(record.descriptions):
            subj = _link(f"desc_{i}")
            parts.append(_emit_subject(subj, _triples_localized(subj, lt)))

    if record.problem_types:
        parts.append(_section("Problem types"))
        for i, pt in enumerate(record.problem_types):
            subj = _link(f"pt_{i}")
            sub_triples = _triples_problem_type(subj, pt)
            # inline description sub-objects
            for j, lt in enumerate(pt.description):
                desc_subj = _link(f"pt_{i}_desc_{j}")
                sub_triples.append((subj, "cve:description", desc_subj))
                parts.append(_emit_subject(desc_subj, _triples_localized(desc_subj, lt)))
            parts.append(_emit_subject(subj, sub_triples))

    if record.affected:
        parts.append(_section("Affected products"))
        for i, ap in enumerate(record.affected):
            subj = _link(f"affected_{i}")
            sub_triples = _triples_affected(subj, ap)
            for j, vr in enumerate(ap.versions):
                vr_subj = _link(f"affected_{i}_ver_{j}")
                sub_triples.append((subj, "cve:versions", vr_subj))
                parts.append(_emit_subject(vr_subj, _triples_version_range(vr_subj, vr)))
            parts.append(_emit_subject(subj, sub_triples))

    if record.references:
        parts.append(_section("References"))
        for i, ref in enumerate(record.references):
            subj = _link(f"ref_{i}")
            sub_triples = _triples_reference(subj, ref)
            for j, lt in enumerate(ref.description):
                desc_subj = _link(f"ref_{i}_desc_{j}")
                sub_triples.append((subj, "cve:description", desc_subj))
                parts.append(_emit_subject(desc_subj, _triples_localized(desc_subj, lt)))
            parts.append(_emit_subject(subj, sub_triples))

    if record.metrics:
        parts.append(_section("CVSS metrics"))
        for i, m in enumerate(record.metrics):
            subj = _link(f"metric_{i}")
            parts.append(_emit_subject(subj, _triples_metric(subj, m)))

    if record.credits:
        parts.append(_section("Credits"))
        for i, c in enumerate(record.credits):
            subj = _link(f"credit_{i}")
            parts.append(_emit_subject(subj, _triples_credit(subj, c)))

    if record.timeline:
        parts.append(_section("Timeline"))
        for i, t in enumerate(record.timeline):
            subj = _link(f"timeline_{i}")
            parts.append(_emit_subject(subj, _triples_timeline(subj, t)))

    for group_name, items in [
        ("Workarounds", record.workarounds),
        ("Exploits",    record.exploits),
        ("Solutions",   record.solutions),
        ("Impact",      record.impact),
        ("Notes",       record.notes),
    ]:
        if items:
            fragment_prefix = group_name.lower().rstrip("s")  # "workaround", "exploit", ...
            parts.append(_section(group_name))
            for i, lt in enumerate(items):
                subj = _link(f"{fragment_prefix}_{i}")
                parts.append(_emit_subject(subj, _triples_localized(subj, lt)))

    turtle = "\n".join(parts)

    if path is not None:
        Path(path).write_text(turtle, encoding="utf-8")

    return turtle
