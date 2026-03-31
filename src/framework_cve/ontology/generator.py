"""
OWL/Turtle generator — derives an OWL ontology from the Pydantic unified model.

Mapping rules
-------------
Pydantic BaseModel subclass     → owl:Class
Pydantic Enum subclass          → owl:Class  +  owl:NamedIndividual per member
Field typed as BaseModel        → owl:ObjectProperty  (functional if not a list)
Field typed as list[BaseModel]  → owl:ObjectProperty  (non-functional)
Field typed as Enum             → owl:ObjectProperty  pointing at the enum class
Field typed as primitive        → owl:DatatypeProperty  with xsd: range
Field(description=…)            → rdfs:comment
Optional[T]                     → minCardinality 0
list[T]                         → minCardinality 0  (no upper bound)
non-Optional scalar             → minCardinality 1  (if not defaulted)

Usage
-----
    from framework_cve.ontology.generator import generate
    print(generate())                   # returns Turtle string
    generate(path="cve_ontology.ttl")   # writes to file
"""

from __future__ import annotations

import inspect
import textwrap
import types
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, get_args, get_origin, get_type_hints

from pydantic import BaseModel
from pydantic.fields import FieldInfo

from ..models import (
    AffectedProduct,
    Credit,
    CreditRole,
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
# Namespace
# ---------------------------------------------------------------------------

BASE_IRI = "https://ontology.cve.org/2025/cve#"
ONTOLOGY_IRI = "https://ontology.cve.org/2025/cve"

# All model classes in dependency order (leaves first)
MODEL_CLASSES: list[type[BaseModel]] = [
    LocalizedText,
    VersionRange,
    ProblemType,
    AffectedProduct,
    Reference,
    CvssMetric,
    Credit,
    TimelineEntry,
    CveRecord,
]

ENUM_CLASSES: list[type[Enum]] = [
    CveState,
    CvssVersion,
    CreditRole,
]

# Manual descriptions for enum classes (their str-mixin docstring is useless)
ENUM_DOCS: dict[type[Enum], str] = {
    CveState:   "Lifecycle state of a CVE record.",
    CvssVersion: "Supported CVSS scoring version identifiers.",
    CreditRole: "Role played by a credited party in relation to a CVE.",
}

# Primitive Python types → XSD datatype IRIs
_XSD_MAP: dict[Any, str] = {
    str:      "xsd:string",
    int:      "xsd:integer",
    float:    "xsd:decimal",
    bool:     "xsd:boolean",
    datetime: "xsd:dateTime",
}

# ---------------------------------------------------------------------------
# Type introspection helpers
# ---------------------------------------------------------------------------

def _unwrap(tp: Any) -> tuple[Any, bool, bool]:
    """
    Return (inner_type, is_optional, is_list).

    Handles Optional[T], list[T], Optional[list[T]], Union[T, None], etc.
    """
    origin = get_origin(tp)
    args   = get_args(tp)

    # Union / Optional
    if origin is types.UnionType or str(origin) in ("<class 'typing.Union'>", "typing.Union"):
        non_none = [a for a in args if a is not type(None)]
        if len(non_none) == 1:
            inner, _, is_list = _unwrap(non_none[0])
            return inner, True, is_list
        return tp, True, False

    # typing.Union
    try:
        import typing
        if origin is typing.Union:
            non_none = [a for a in args if a is not type(None)]
            if len(non_none) == 1:
                inner, _, is_list = _unwrap(non_none[0])
                return inner, True, is_list
            return tp, True, False
    except Exception:
        pass

    # list[T]
    if origin is list:
        inner = args[0] if args else Any
        return inner, True, True   # lists are always optional (min 0)

    return tp, False, False


def _is_model(tp: Any) -> bool:
    try:
        return isinstance(tp, type) and issubclass(tp, BaseModel)
    except TypeError:
        return False


def _is_enum(tp: Any) -> bool:
    try:
        return isinstance(tp, type) and issubclass(tp, Enum)
    except TypeError:
        return False


def _xsd(tp: Any) -> str | None:
    return _XSD_MAP.get(tp)


# ---------------------------------------------------------------------------
# IRI helpers
# ---------------------------------------------------------------------------

def _cls_iri(cls: type) -> str:
    return f"cve:{cls.__name__}"


def _prop_iri(field_name: str) -> str:
    # Convert snake_case → camelCase for idiomatic OWL property names
    parts = field_name.split("_")
    camel = parts[0] + "".join(p.capitalize() for p in parts[1:])
    return f"cve:{camel}"


def _individual_iri(enum_cls: type[Enum], member: Enum) -> str:
    return f"cve:{member.value.replace('.', '_').replace('-', '_')}"


def _escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


# ---------------------------------------------------------------------------
# Section generators
# ---------------------------------------------------------------------------

def _gen_prefixes() -> str:
    return textwrap.dedent("""\
        @prefix owl:  <http://www.w3.org/2002/07/owl#> .
        @prefix rdf:  <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
        @prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
        @prefix xsd:  <http://www.w3.org/2001/XMLSchema#> .
        @prefix cve:  <https://ontology.cve.org/2025/cve#> .
    """)


def _gen_ontology_header() -> str:
    return textwrap.dedent(f"""\
        <{ONTOLOGY_IRI}>
            a owl:Ontology ;
            rdfs:label "CVE Unified Ontology"@en ;
            rdfs:comment "Unified OWL ontology for CVE records. Derived from the \
cve-stones Pydantic model, supporting both CVE JSON 2.x and CVE JSON 5.x source schemas."@en .
    """)


def _gen_enum_class(cls: type[Enum]) -> str:
    lines: list[str] = []
    iri = _cls_iri(cls)
    doc = ENUM_DOCS.get(cls) or cls.__name__
    individual_iris = [_individual_iri(cls, m) for m in cls]

    # Class declaration
    lines.append(f"{iri}")
    lines.append(f"    a owl:Class ;")
    lines.append(f'    rdfs:label "{cls.__name__}"@en ;')
    lines.append(f'    rdfs:comment "{_escape(doc)}"@en ;')
    # Closed enumeration: exactly these individuals
    ind_list = " ".join(individual_iris)
    lines.append(f"    owl:equivalentClass [ a owl:Class ; owl:oneOf ( {ind_list} ) ] .")
    lines.append("")

    # Named individuals
    for member in cls:
        ind = _individual_iri(cls, member)
        lines.append(f"{ind}")
        lines.append(f"    a owl:NamedIndividual, {iri} ;")
        lines.append(f'    rdfs:label "{member.value}"@en .')
        lines.append("")

    return "\n".join(lines)


def _gen_model_class(cls: type[BaseModel]) -> str:
    lines: list[str] = []
    iri = _cls_iri(cls)
    doc = inspect.getdoc(cls) or cls.__name__

    lines.append(f"{iri}")
    lines.append(f"    a owl:Class ;")
    lines.append(f'    rdfs:label "{cls.__name__}"@en ;')
    lines.append(f'    rdfs:comment "{_escape(doc)}"@en .')
    lines.append("")
    return "\n".join(lines)


def _collect_all_properties(
    model_classes: list[type[BaseModel]],
) -> dict[str, dict]:
    """
    Walk every model class and collect property metadata keyed by property IRI.

    When two classes share a field name (e.g. ``lang`` on both LocalizedText
    and Credit) the domains are merged.  At emit time a single property
    declaration is produced with an ``owl:unionOf`` domain when there are
    multiple contributing classes.
    """
    props: dict[str, dict] = {}

    for cls in model_classes:
        hints = get_type_hints(cls, include_extras=True)
        for field_name, field_info in cls.model_fields.items():
            raw_type = hints.get(field_name, field_info.annotation)
            inner, is_optional, is_list = _unwrap(raw_type)

            prop_iri = _prop_iri(field_name)

            if prop_iri not in props:
                props[prop_iri] = {
                    "field_name": field_name,
                    "is_list": is_list,
                    "inner": inner,
                    "comment": field_info.description or "",
                    "domains": [],
                }

            props[prop_iri]["domains"].append(_cls_iri(cls))
            # A property is functional only if it is scalar in *every* class
            if is_list:
                props[prop_iri]["is_list"] = True

    return props


def _gen_all_properties(model_classes: list[type[BaseModel]]) -> str:
    """Emit one declaration per unique property IRI across all model classes."""
    lines: list[str] = []
    props = _collect_all_properties(model_classes)

    for prop_iri, meta in props.items():
        inner     = meta["inner"]
        is_list   = meta["is_list"]
        comment   = meta["comment"]
        domains   = meta["domains"]
        field_name = meta["field_name"]

        # Build domain expression
        if len(domains) == 1:
            domain_expr = domains[0]
        else:
            domain_expr = "[ owl:unionOf ( " + " ".join(domains) + " ) ]"

        lines.append(prop_iri)

        if _is_model(inner):
            range_iri = _cls_iri(inner)
            lines.append(f"    a owl:ObjectProperty ;")
            if not is_list:
                lines.append(f"    a owl:FunctionalProperty ;")
        elif _is_enum(inner):
            range_iri = _cls_iri(inner)
            lines.append(f"    a owl:ObjectProperty, owl:FunctionalProperty ;")
        else:
            range_iri = _xsd(inner) or "xsd:string"
            lines.append(f"    a owl:DatatypeProperty ;")
            if not is_list:
                lines.append(f"    a owl:FunctionalProperty ;")

        lines.append(f'    rdfs:label "{field_name}"@en ;')
        if comment:
            lines.append(f'    rdfs:comment "{_escape(comment)}"@en ;')
        lines.append(f"    rdfs:domain {domain_expr} ;")
        lines.append(f"    rdfs:range {range_iri} .")
        lines.append("")

    return "\n".join(lines)


def _gen_restrictions(cls: type[BaseModel]) -> str:
    """
    Emit owl:Restriction cardinality axioms on the class as rdfs:subClassOf.
    Required (non-optional, non-defaulted) scalar fields get minCardinality 1.
    """
    lines: list[str] = []
    hints = get_type_hints(cls, include_extras=True)
    fields: dict[str, FieldInfo] = cls.model_fields

    restrictions: list[str] = []
    for field_name, field_info in fields.items():
        raw_type = hints.get(field_name, field_info.annotation)
        _, is_optional, is_list = _unwrap(raw_type)

        prop_iri = _prop_iri(field_name)
        has_default = field_info.default is not None or field_info.default_factory is not None  # type: ignore[misc]

        if is_list:
            # Lists: 0 or more — no restriction needed (open world)
            pass
        elif not is_optional and not has_default:
            # Required scalar field
            restrictions.append(
                f"[ a owl:Restriction ; owl:onProperty {prop_iri} ; owl:minCardinality 1 ]"
            )
        else:
            # Optional scalar: 0..1
            restrictions.append(
                f"[ a owl:Restriction ; owl:onProperty {prop_iri} ; owl:maxCardinality 1 ]"
            )

    if restrictions:
        cls_iri = _cls_iri(cls)
        for r in restrictions:
            lines.append(f"{cls_iri} rdfs:subClassOf {r} .")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def generate(path: str | Path | None = None) -> str:
    """
    Generate a Turtle-serialised OWL ontology from the Pydantic unified model.

    Parameters
    ----------
    path:
        If given, write the Turtle to this file path in addition to returning it.

    Returns
    -------
    str
        The full Turtle document.
    """
    sections: list[str] = [
        "# ============================================================",
        "# CVE Unified Ontology",
        "# Auto-generated from framework_cve.models (Pydantic → OWL)",
        "# ============================================================",
        "",
        _gen_prefixes(),
        "# --- Ontology declaration -------------------------------------------",
        "",
        _gen_ontology_header(),
        "# --- Enumeration classes -------------------------------------------",
        "",
    ]

    for cls in ENUM_CLASSES:
        sections.append(f"# {cls.__name__}")
        sections.append(_gen_enum_class(cls))

    sections.append("# --- Domain classes -----------------------------------------------")
    sections.append("")
    for cls in MODEL_CLASSES:
        sections.append(f"# {cls.__name__}")
        sections.append(_gen_model_class(cls))

    sections.append("# --- Properties ---------------------------------------------------")
    sections.append("")
    sections.append(_gen_all_properties(MODEL_CLASSES))

    sections.append("# --- Cardinality restrictions -------------------------------------")
    sections.append("")
    for cls in MODEL_CLASSES:
        r = _gen_restrictions(cls)
        if r.strip():
            sections.append(f"# Restrictions on {cls.__name__}")
            sections.append(r)

    turtle = "\n".join(sections)

    if path is not None:
        Path(path).write_text(turtle, encoding="utf-8")

    return turtle


if __name__ == "__main__":
    import sys
    out_path = sys.argv[1] if len(sys.argv) > 1 else "cve_ontology.ttl"
    generate(path=out_path)
    print(f"Written: {out_path}")
