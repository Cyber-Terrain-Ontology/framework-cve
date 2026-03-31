# framework-cve

A unified CVE ontology and ingestion library that supports both the legacy
**CVE JSON 2.x** (DWF) format and the current **CVE JSON 5.x** (CNA) format.

Records from either schema are normalised into a single Pydantic model, and an
OWL ontology in Turtle format is generated directly from that model so the two
representations stay in sync automatically.

---

## Contents

```
framework-cve/
├── schema/
│   ├── CVE_JSON_2.0_spec.md              # CVE JSON 2.x specification (archived)
│   ├── CVE_JSON_5.0_schema.json          # CVE JSON 5.0 JSON Schema (draft-07)
│   ├── CVE_Record_Format_5.x_current.json  # CVE JSON 5.2 JSON Schema (current)
│   └── cve_ontology.ttl                  # Generated OWL ontology (Turtle)
│
├── src/cve_stones/
│   ├── models.py                         # Unified Pydantic model (the ontology source)
│   ├── ingest/
│   │   ├── __init__.py                   # Auto-detect schema version and dispatch
│   │   ├── v2.py                         # CVE JSON 2.x → CveRecord mapper
│   │   └── v5.py                         # CVE JSON 5.x → CveRecord mapper
│   └── ontology/
│       └── generator.py                  # Derives OWL/Turtle from the Pydantic model
│
├── tests/
│   └── test_ingest.py                    # 39 tests covering v2 and v5 ingestion
└── pyproject.toml
```

---

## Background: two schemas

| | CVE JSON 2.x | CVE JSON 5.x |
|---|---|---|
| Also known as | DWF / legacy format | CNA format |
| Field style | `ALL_CAPS` keys | `camelCase` keys |
| Multilingual text | `{"eng": "...", "ger": "..."}` dicts | `[{"lang": "en", "value": "..."}]` arrays |
| Schema artefact | Markdown specification | JSON Schema draft-07 |
| Current version | 2.4 (frozen) | 5.2 (active) |
| Status | Still in wide use; community did not fully migrate | Preferred for new records |

The 2.x format predates formal JSON Schema tooling and is documented only as a
Markdown specification (`schema/CVE_JSON_2.0_spec.md`).  The 5.x format is a
machine-readable JSON Schema.  This library ingests both.

---

## Installation

Requires Python 3.11+.

```bash
pip install -e .              # library only
pip install -e ".[dev]"       # library + pytest
```

---

## Quick start

```python
import json
from cve_stones import ingest

# Works with either schema — version is detected automatically
with open("CVE-2021-44228.json") as f:
    record = ingest(json.load(f))

print(record.cve_id)          # "CVE-2021-44228"
print(record.state)           # CveState.PUBLISHED
print(record.source_schema)   # "v5"

for desc in record.descriptions:
    print(f"[{desc.lang}] {desc.value}")

for product in record.affected:
    print(product.vendor, product.product)
    for vr in product.versions:
        print(" ", vr.status, vr.version or f"< {vr.less_than}")
```

---

## Unified model

`src/cve_stones/models.py` is the single source of truth.  All consumers work
against `CveRecord` regardless of which schema the record originated from.

### Key classes

| Class | Description |
|---|---|
| `CveRecord` | Top-level record (identity, dates, lifecycle, all sub-objects) |
| `LocalizedText` | `lang` + `value` — used for descriptions, notes, workarounds, etc. |
| `AffectedProduct` | Vendor, product, CPE/purl/SWID, version ranges |
| `VersionRange` | A single version or bounded range (`lessThan`, `greaterEqual`, …) |
| `ProblemType` | CWE / OWASP classification plus free-text description |
| `Reference` | URL, name, tags, type |
| `CvssMetric` | CVSS score for any version (v2, v3.0, v3.1, v4.0) |
| `Credit` | Credited party with roles and identity handles |
| `TimelineEntry` | Timestamped disclosure event |

### Schema field mapping

| Concept | v2 source field | v5 source field | Unified field |
|---|---|---|---|
| Identifier | `CVE_ID` | `cveMetadata.cveId` | `cve_id` |
| State | `STATE: "PUBLIC"` | `state: "PUBLISHED"` | `CveState` enum |
| Title | `TITLE` | `cnaContainer.title` | `title` |
| Descriptions | `DWF.DESCRIPTION` (dict) | `cnaContainer.descriptions[]` | `list[LocalizedText]` |
| Affected | `DWF.AFFECTS[]` | `cnaContainer.affected[]` | `list[AffectedProduct]` |
| Version ranges | `">=2.0"` string prefix | `{lessThan, status, …}` object | `VersionRange` |
| CVSS | `DWF.CVSSv2/v3` BM/TM/EM | `metrics[].cvssV3_1` object | `list[CvssMetric]` |
| Credits | `CREDITS[].ID + ROLE` | `credits[].type + value` | `list[Credit]` |
| Public date | `DATE_PUBLIC` | `cveMetadata.datePublished` | `date_public` |
| Assigner | `ASSIGNER` (email) | `assignerShortName` / UUID | `assigner` |

The `raw` field on every `CveRecord` preserves the original decoded JSON for
round-trip fidelity and access to schema-specific fields that have no unified
equivalent.

---

## OWL ontology

### What is generated

`schema/cve_ontology.ttl` is an OWL 2 ontology in Turtle format, derived
automatically from the Pydantic model in `models.py`.  It uses the namespace:

```
https://ontology.cve.org/2025/cve#   (prefix: cve:)
```

The mapping from Pydantic to OWL follows these rules:

| Pydantic construct | OWL construct |
|---|---|
| `class Foo(BaseModel)` | `cve:Foo a owl:Class` |
| `class Bar(str, Enum)` | `cve:Bar a owl:Class` + `owl:oneOf(…)` closed enumeration + `owl:NamedIndividual` per member |
| Field typed as `BaseModel` subclass | `owl:ObjectProperty` with `rdfs:range cve:ThatClass` |
| Field typed as `Enum` subclass | `owl:ObjectProperty` pointing at the enum class (value is a named individual) |
| Field typed as `str / int / float / bool / datetime` | `owl:DatatypeProperty` with corresponding `xsd:` range |
| Scalar (non-list) field | `owl:FunctionalProperty` (at most one value) |
| `list[T]` field | non-functional property (unbounded) |
| `Optional[T]` field | `owl:maxCardinality 1` restriction |
| `Field(description=…)` | `rdfs:comment` |

Properties shared across multiple classes (e.g. `cve:lang` appears on
`LocalizedText`, `Credit`, and `TimelineEntry`) are declared **once** with an
`owl:unionOf` domain rather than multiple `rdfs:domain` triples.  Multiple
`rdfs:domain` triples would be interpreted by OWL reasoners as an intersection,
wrongly inferring that any individual with that property must belong to all
contributing classes simultaneously.

### Regenerating the ontology

After any change to `src/cve_stones/models.py`, regenerate the Turtle file:

```bash
python -m cve_stones.ontology.generator schema/cve_ontology.ttl
```

Or from Python:

```python
from cve_stones.ontology.generator import generate
generate(path="schema/cve_ontology.ttl")
```

`generate()` also returns the Turtle as a string if you want to inspect or
post-process it without writing to disk:

```python
turtle = generate()
print(turtle)
```

### Extending the model

1. Edit `src/cve_stones/models.py` — add fields, classes, or enum members.
2. Update the relevant ingest mapper in `src/cve_stones/ingest/v2.py` or `v5.py`
   to populate the new fields from source records.
3. Add test coverage in `tests/test_ingest.py`.
4. Regenerate the ontology:
   ```bash
   python -m cve_stones.ontology.generator schema/cve_ontology.ttl
   ```

The ontology is always a downstream artefact of the model — edit the model,
never the `.ttl` file directly.

---

## Running the tests

```bash
pytest
pytest -v          # verbose, shows each test name
pytest --cov=cve_stones --cov-report=term-missing
```

The test suite covers:

- Schema version auto-detection (v2 and v5 heuristics)
- Full v2 ingestion: identity, state mapping, multilingual descriptions,
  affected products with version-range operators, CVSS v2/v3 score and
  vector reconstruction, credits, timeline, workarounds, exploits, impact
- Full v5 ingestion: identity, state mapping, title, CWE problemTypes,
  structured version ranges, CVSS v3.1 with severity, credits, timeline,
  workarounds, ADP fallback
- Raw record preservation (round-trip check)

---

## Source schema references

| Schema | Location |
|---|---|
| CVE JSON 2.x specification | `schema/CVE_JSON_2.0_spec.md` |
| CVE JSON 5.0 JSON Schema | `schema/CVE_JSON_5.0_schema.json` |
| CVE JSON 5.2 JSON Schema (current) | `schema/CVE_Record_Format_5.x_current.json` |
| Upstream schema repository | https://github.com/CVEProject/cve-schema |
