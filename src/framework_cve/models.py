"""
Unified CVE ontology — source-schema-agnostic representation of a CVE record.

Concepts are drawn from both CVE JSON 2.x (DWF/legacy) and CVE JSON 5.x
(current CNA format).  Every field is mapped from one or both schemas;
see the ingest sub-package for the per-schema transformers.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class CveState(str, Enum):
    PUBLISHED = "PUBLISHED"   # v5 "PUBLISHED"  /  v2 "PUBLIC"
    REJECTED  = "REJECTED"    # v5 "REJECTED"   /  v2 "REJECT"
    RESERVED  = "RESERVED"    # v5 "RESERVED"   /  v2 "RESERVED"
    UNKNOWN   = "UNKNOWN"     # catch-all for unrecognised values


class CvssVersion(str, Enum):
    V2   = "2.0"
    V3_0 = "3.0"
    V3_1 = "3.1"
    V4_0 = "4.0"


class CreditRole(str, Enum):
    FINDER       = "finder"
    REPORTER     = "reporter"
    COORDINATOR  = "coordinator"
    REMEDIATION  = "remediation"
    TOOL         = "tool"
    SPONSOR      = "sponsor"
    OTHER        = "other"
    # v2 legacy roles preserved as-is when no mapping exists
    DISCOVERER   = "discoverer"
    RESEARCHER   = "researcher"
    PATCHER      = "patcher"
    TESTER       = "tester"
    REPRODUCER   = "reproducer"
    RELEASER     = "releaser"
    DOCUMENTATION = "documentation"


# ---------------------------------------------------------------------------
# Primitive / shared building blocks
# ---------------------------------------------------------------------------


class LocalizedText(BaseModel):
    """A text value paired with a BCP-47 / ISO-639-2 language tag."""
    lang:  str = Field(description="ISO-639-2 or BCP-47 language code, e.g. 'en', 'eng'")
    value: str = Field(description="The text content in that language")


class ProblemType(BaseModel):
    """
    Weakness classification for the vulnerability.

    v2  → DWF.PROBLEM_TYPE  (CWE string, OWASP string, free-text DESCRIPTION)
    v5  → cnaContainer.problemTypes[].descriptions[]
    """
    cwe_id:      str | None = Field(None, description="CWE identifier, e.g. 'CWE-79'")
    owasp_id:    str | None = Field(None, description="OWASP identifier, e.g. 'A3'")
    description: list[LocalizedText] = Field(
        default_factory=list,
        description="Free-text description when CWE/OWASP is absent or supplementary",
    )
    type:        str | None = Field(None, description="v5 'type' field (e.g. 'CWE')")


class VersionRange(BaseModel):
    """
    A version or version range specifying affected/fixed software.

    v2  → DWF.AFFECTS[].AFFECTED / FIXEDIN  (plain version strings with optional
          leading >, <, >=, <= operators)
    v5  → affected[].versions[]  (structured {version, status, lessThan, …})
    """
    version:     str | None = Field(None, description="Exact version string")
    version_type: str | None = Field(None, description="Versioning scheme, e.g. 'semver', 'git'")
    less_than:   str | None = Field(None, description="Exclusive upper bound")
    less_equal:  str | None = Field(None, description="Inclusive upper bound")
    greater_equal: str | None = Field(None, description="Inclusive lower bound")
    greater_than:  str | None = Field(None, description="Exclusive lower bound")
    status:      Literal["affected", "unaffected", "unknown"] = "affected"


class AffectedProduct(BaseModel):
    """
    A product/component affected by (or fixed for) the vulnerability.

    v2  → DWF.AFFECTS[]
    v5  → cnaContainer.affected[]
    """
    vendor:         str | None = None
    product:        str | None = None
    collection_url: str | None = Field(None, description="v5 collectionURL (package repo)")
    package_name:   str | None = Field(None, description="v5 packageName")
    purl:           str | None = Field(None, description="Package URL (purl) — v5 5.2+")
    cpe:            str | None = Field(None, description="CPE 2.2 or 2.3 string")
    swid:           str | None = Field(None, description="SWID tag — v2 only")
    product_url:    str | None = Field(None, description="v2 URL for this product")
    versions:       list[VersionRange] = Field(default_factory=list)
    default_status: Literal["affected", "unaffected", "unknown"] | None = None


class Reference(BaseModel):
    """
    An external reference for the CVE.

    v2  → DWF.REFERENCES[].FILES[].URL  (plus optional NAME, TYPE, DESCRIPTION)
    v5  → cnaContainer.references[]     (url, name, tags)
    """
    url:         str
    name:        str | None = None
    tags:        list[str] = Field(default_factory=list, description="v5 reference tags")
    description: list[LocalizedText] = Field(default_factory=list, description="v2 reference description")
    ref_type:    str | None = Field(None, description="v2 TYPE: WWW, FILE, EMAIL")


class CvssMetric(BaseModel):
    """
    A CVSS score in any supported version.

    v2  → DWF.CVSSv2 / DWF.CVSSv3  (split into BM/TM/EM sub-objects)
    v5  → cnaContainer.metrics[].cvssV2_0 / cvssV3_0 / cvssV3_1 / cvssV4_0
    """
    version:       CvssVersion
    vector_string: str | None = Field(None, description="Full CVSS vector string")
    base_score:    float | None = None
    base_severity: str | None = None
    # Temporal / environmental sub-scores (present in v2, sometimes v5)
    temporal_score:      float | None = None
    environmental_score: float | None = None
    # Raw metric components preserved for round-trip fidelity
    raw: dict[str, Any] = Field(default_factory=dict, description="Original metric object")


class Credit(BaseModel):
    """
    A party credited in relation to this CVE.

    v2  → DWF.CREDITS[].ID / ROLE
    v5  → cnaContainer.credits[]  (lang, value, type)
    """
    name:  str | None = None
    lang:  str | None = None
    roles: list[str] = Field(default_factory=list)
    # v2 identity bag: {"github-user": "joesmith", …}
    identifiers: dict[str, str] = Field(default_factory=dict)


class TimelineEntry(BaseModel):
    """
    A single event on the CVE disclosure timeline.

    v2  → DWF.TIMELINE[]
    v5  → cnaContainer.timeline[]
    """
    timestamp: datetime | str | None = None
    lang:      str | None = None
    value:     str | None = None


# ---------------------------------------------------------------------------
# Top-level unified record
# ---------------------------------------------------------------------------


class CveRecord(BaseModel):
    """
    Unified, source-agnostic CVE record.

    After ingestion from either v2.x or v5.x JSON, all consumers work
    against this single model regardless of origin schema.
    """

    # --- Identity & lifecycle -----------------------------------------------
    cve_id:        str = Field(description="CVE identifier, e.g. 'CVE-2021-44228'")
    state:         CveState = CveState.UNKNOWN
    title:         str | None = None
    replaced_by:   list[str] = Field(default_factory=list, description="CVE IDs that supersede this one")

    # --- Dates ---------------------------------------------------------------
    date_public:   datetime | str | None = Field(None, description="Date vulnerability was disclosed publicly")
    date_assigned: datetime | str | None = Field(None, description="Date CVE ID was assigned")
    date_requested: datetime | str | None = Field(None, description="Date CVE was requested — v2 only")
    date_updated:  datetime | str | None = Field(None, description="Date record was last updated")

    # --- Attribution ---------------------------------------------------------
    assigner:  str | None = Field(None, description="Org name, UUID, or email of the assigner")
    requester: str | None = Field(None, description="Requestor ID — v2 only")

    # --- Core vulnerability data --------------------------------------------
    descriptions:  list[LocalizedText] = Field(default_factory=list)
    problem_types: list[ProblemType]   = Field(default_factory=list)
    affected:      list[AffectedProduct] = Field(default_factory=list)
    references:    list[Reference]     = Field(default_factory=list)
    metrics:       list[CvssMetric]    = Field(default_factory=list)

    # --- Supplementary -------------------------------------------------------
    credits:       list[Credit]        = Field(default_factory=list)
    timeline:      list[TimelineEntry] = Field(default_factory=list)
    workarounds:   list[LocalizedText] = Field(default_factory=list)
    exploits:      list[LocalizedText] = Field(default_factory=list, description="Exploitation information — v2 EXPLOITATION / v5 exploits")
    solutions:     list[LocalizedText] = Field(default_factory=list, description="v5 solutions")
    impact:        list[LocalizedText] = Field(default_factory=list, description="v2 DWF.IMPACT / v5 impacts")
    notes:         list[LocalizedText] = Field(default_factory=list)

    # --- Provenance ----------------------------------------------------------
    source_schema: Literal["v2", "v5", "v2+v5"] = Field(description="Which schema family the record was ingested from")
    raw:           dict[str, Any]      = Field(default_factory=dict, description="Original raw record for round-trip fidelity")
