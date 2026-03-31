"""
Tests for merge() and to_turtle() covering:
- Merge strategy (v5 primary, v2 secondary, deduplication, gap-filling)
- Turtle instance serialization (structure, provenance, sub-objects)

The fixture CVE uses Log4Shell (CVE-2021-44228) as the CVE ID.
The v2 record adds fields absent from v5: OWASP ID, exploitation text,
v2 CVSS scores, requester, and a v2-only timeline entry.
The v5 record is authoritative for title, v3.1 CVSS, purl, and descriptions.
"""

import pytest

from framework_cve import ingest, merge, to_turtle
from framework_cve.models import CveState, CvssVersion

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

CVE_ID = "CVE-2021-44228"

V2_RAW = {
    "DATA_VERSION": "2.4",
    "CVE_ID": CVE_ID,
    "STATE": "PUBLIC",
    "TITLE": "Log4j JNDI injection",          # less specific — v5 should win
    "DATE_PUBLIC": "2021-12-10",
    "DATE_REQUESTED": "2021-11-26",
    "REQUESTER": "researcher@example.com",
    "ASSIGNER": "cve@mitre.org",
    "DWF": {
        "PROBLEM_TYPE": {
            "CWE": "CWE-917",
            "OWASP": "A1",                     # v2-only OWASP — should survive merge
            "DESCRIPTION": {"eng": "Improper Neutralization of Special Elements"},
        },
        "IMPACT": {"eng": "Remote code execution via JNDI lookup"},
        "AFFECTS": [
            {
                "VENDOR": "Apache",
                "PRODUCT": "Log4j2",
                "CPE": "cpe:/a:apache:log4j:2.0",   # v2-only CPE
                "AFFECTED": [">=2.0", "<2.15.0"],
                "FIXEDIN": ["2.15.0"],
            }
        ],
        "DESCRIPTION": {
            "eng": "Apache Log4j2 allows RCE via crafted JNDI lookup.",
            "ger": "Apache Log4j2 erlaubt RCE über JNDI.",    # v2-only language
        },
        "REFERENCES": [
            {
                "NAME": "Apache Advisory",
                "TYPE": "WWW",
                "FILES": [{"URL": "https://logging.apache.org/log4j/2.x/security.html"}],
            },
            {
                "NAME": "NVD Entry",
                "TYPE": "WWW",
                "FILES": [{"URL": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"}],  # v2-only ref
            },
        ],
        "CVSSv2": {
            "BM": {"AV": "N", "AC": "L", "AU": "N", "C": "C", "I": "C", "A": "C", "SCORE": "10.0"},
        },
        "CVSSv3": {
            "BM": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C",
                   "C": "H", "I": "H", "A": "H", "SCORE": "10.0"},
        },
        "CREDITS": [
            {"ID": {"github-user": "chenzhaojun"}, "ROLE": ["discoverer"]}
        ],
        "TIMELINE": [
            {"TIMESTAMP": "2021-11-24", "TEXT": {"eng": "Reported to Apache privately"}},
        ],
        "EXPLOITATION": {"eng": "Actively exploited in the wild within days of disclosure."},
        "WORKAROUND": {"eng": "Set log4j2.formatMsgNoLookups=true"},
    },
}

V5_RAW = {
    "dataType": "CVE_RECORD",
    "dataVersion": "5.0",
    "cveMetadata": {
        "cveId": CVE_ID,
        "assignerOrgId": "8254265b-2729-46b6-b9e3-3dfca2d5bfca",
        "assignerShortName": "apache",           # more specific assigner — v5 wins
        "state": "PUBLISHED",
        "datePublished": "2021-12-10T10:00:00Z",
        "dateReserved": "2021-11-26T00:00:00Z",
        "dateUpdated": "2021-12-14T00:00:00Z",
    },
    "containers": {
        "cna": {
            "title": "Log4Shell — Remote code execution in Log4j2 via JNDI",  # wins
            "descriptions": [
                {"lang": "en",
                 "value": "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features "
                          "do not protect against attacker-controlled LDAP and other "
                          "JNDI related endpoints."},
            ],
            "affected": [
                {
                    "vendor": "Apache",
                    "product": "Log4j2",
                    "packageURL": "pkg:maven/org.apache.logging.log4j/log4j-core",  # v5-only purl
                    "versions": [
                        {"version": "2.0-beta9", "status": "affected",
                         "lessThan": "2.15.0", "versionType": "maven"},
                        {"version": "2.15.0", "status": "unaffected"},
                    ],
                    "defaultStatus": "unaffected",
                }
            ],
            "problemTypes": [
                {
                    "descriptions": [
                        {"lang": "en", "cweId": "CWE-917",
                         "description": "Improper Neutralization of Special Elements",
                         "type": "CWE"},
                    ]
                }
            ],
            "references": [
                {"url": "https://logging.apache.org/log4j/2.x/security.html",
                 "name": "Apache Log4j Security Page",
                 "tags": ["vendor-advisory"]},   # same URL as v2 — should merge tags
            ],
            "metrics": [
                {
                    "cvssV3_1": {
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                        "baseScore": 10.0,
                        "baseSeverity": "CRITICAL",
                    }
                }
            ],
            "credits": [
                {"lang": "en",
                 "value": "Chen Zhaojun of Alibaba Cloud Security Team",
                 "type": "finder"},
            ],
            "timeline": [
                {"time": "2021-12-09T00:00:00Z", "lang": "en",
                 "value": "Vulnerability disclosed publicly"},
            ],
            "workarounds": [
                {"lang": "en", "value": "Set log4j2.formatMsgNoLookups=true"}
            ],
        }
    },
}


@pytest.fixture(scope="module")
def r_v2():
    return ingest(V2_RAW)


@pytest.fixture(scope="module")
def r_v5():
    return ingest(V5_RAW)


@pytest.fixture(scope="module")
def merged(r_v2, r_v5):
    return merge(r_v2, r_v5)


@pytest.fixture(scope="module")
def turtle(merged):
    return to_turtle(merged)


# ---------------------------------------------------------------------------
# Merge tests
# ---------------------------------------------------------------------------

class TestMerge:
    def test_source_schema_is_combined(self, merged):
        assert merged.source_schema == "v2+v5"

    def test_cve_id_preserved(self, merged):
        assert merged.cve_id == CVE_ID

    def test_state_is_published(self, merged):
        assert merged.state == CveState.PUBLISHED

    def test_v5_title_wins(self, merged):
        assert "Log4Shell" in merged.title

    def test_v5_assigner_wins(self, merged):
        # v5 assignerShortName "apache" beats v2 "cve@mitre.org"
        assert merged.assigner == "apache"

    def test_v2_requester_backfilled(self, merged):
        assert merged.requester == "researcher@example.com"

    def test_descriptions_union_by_lang(self, merged):
        langs = {d.lang for d in merged.descriptions}
        # v5 contributes "en", v2 contributes "ger"
        assert "en" in langs
        assert "ger" in langs

    def test_v5_description_wins_for_en(self, merged):
        en = next(d for d in merged.descriptions if d.lang == "en")
        assert "JNDI features" in en.value   # v5's more detailed text

    def test_problem_type_owasp_backfilled_from_v2(self, merged):
        # v5 has no OWASP field; v2 does — should survive in merged record
        pt = next(p for p in merged.problem_types if p.cwe_id == "CWE-917")
        assert pt.owasp_id == "A1"

    def test_affected_product_merged(self, merged):
        assert len(merged.affected) == 1
        ap = merged.affected[0]
        assert ap.vendor == "Apache"
        assert ap.product == "Log4j2"

    def test_purl_backfilled_from_v5(self, merged):
        ap = merged.affected[0]
        assert ap.purl is not None
        assert "log4j" in ap.purl

    def test_cpe_backfilled_from_v2(self, merged):
        ap = merged.affected[0]
        assert ap.cpe is not None
        assert "apache" in ap.cpe

    def test_version_ranges_unioned(self, merged):
        ap = merged.affected[0]
        # v2: >=2.0, <2.15.0, unaffected 2.15.0
        # v5: affected 2.0-beta9/<2.15.0, unaffected 2.15.0
        assert len(ap.versions) >= 2
        statuses = {vr.status for vr in ap.versions}
        assert "affected" in statuses
        assert "unaffected" in statuses

    def test_reference_url_deduplicated(self, merged):
        urls = [r.url for r in merged.references]
        # Apache advisory appears in both — should be one entry
        apache_refs = [u for u in urls if "logging.apache.org" in u]
        assert len(apache_refs) == 1

    def test_v5_reference_tag_preserved(self, merged):
        ref = next(r for r in merged.references if "logging.apache.org" in r.url)
        assert "vendor-advisory" in ref.tags

    def test_nvd_reference_from_v2_preserved(self, merged):
        urls = [r.url for r in merged.references]
        assert any("nvd.nist.gov" in u for u in urls)

    def test_cvss_v2_from_v2_source(self, merged):
        versions = {m.version for m in merged.metrics}
        assert CvssVersion.V2 in versions

    def test_cvss_v3_1_from_v5_source(self, merged):
        m = next(x for x in merged.metrics if x.version == CvssVersion.V3_1)
        assert m.base_score == pytest.approx(10.0)
        assert m.base_severity == "CRITICAL"

    def test_exploits_from_v2(self, merged):
        assert any("wild" in e.value for e in merged.exploits)

    def test_workaround_deduped_by_lang(self, merged):
        # Both v2 and v5 have the same English workaround
        en_wk = [w for w in merged.workarounds if w.lang in ("en", "eng")]
        assert len(en_wk) == 1

    def test_timeline_includes_both_sources(self, merged):
        texts = [t.value for t in merged.timeline if t.value]
        assert any("privately" in t for t in texts)   # v2
        assert any("publicly" in t for t in texts)    # v5

    def test_raw_has_both_schemas(self, merged):
        assert "v2" in merged.raw
        assert "v5" in merged.raw

    def test_merge_wrong_cve_raises(self, r_v2):
        from framework_cve.models import CveRecord, CveState
        other = r_v2.model_copy(update={"cve_id": "CVE-1999-0001"})
        with pytest.raises(ValueError, match="Cannot merge"):
            merge(r_v2, other)


# ---------------------------------------------------------------------------
# Serializer tests
# ---------------------------------------------------------------------------

class TestToTurtle:
    def test_returns_string(self, turtle):
        assert isinstance(turtle, str)
        assert len(turtle) > 100

    def test_prefixes_present(self, turtle):
        assert "@prefix cve:" in turtle
        assert "@prefix cveid:" in turtle
        assert "@prefix prov:" in turtle
        assert "@prefix xsd:" in turtle

    def test_record_individual(self, turtle):
        assert f"cveid:{CVE_ID}" in turtle
        assert "a cve:CveRecord" in turtle

    def test_state_individual(self, turtle):
        assert "cve:PUBLISHED" in turtle

    def test_source_schema_literal(self, turtle):
        assert '"v2+v5"' in turtle

    def test_provenance_triples(self, turtle):
        assert "prov:wasDerivedFrom" in turtle
        assert "source_v2" in turtle
        assert "source_v5" in turtle
        assert "prov:Entity" in turtle

    def test_ontology_import(self, turtle):
        assert "owl:imports" in turtle
        assert "cyberterrain.org/ns/frameworks/cve" in turtle

    def test_descriptions_section(self, turtle):
        assert "cve:LocalizedText" in turtle
        assert "cve:descriptions" in turtle
        # German description from v2 should be present
        assert "ger" in turtle or "de" in turtle

    def test_problem_type_individual(self, turtle):
        assert "cve:ProblemType" in turtle
        assert "CWE-917" in turtle
        assert "A1" in turtle   # OWASP from v2

    def test_affected_product_individual(self, turtle):
        assert "cve:AffectedProduct" in turtle
        assert '"Apache"' in turtle
        assert '"Log4j2"' in turtle

    def test_purl_in_affected(self, turtle):
        assert "log4j" in turtle
        assert "cve:purl" in turtle

    def test_cpe_in_affected(self, turtle):
        assert "cve:cpe" in turtle
        assert "apache" in turtle.lower()

    def test_version_range_individuals(self, turtle):
        assert "cve:VersionRange" in turtle
        assert "cve:lessThan" in turtle

    def test_reference_individuals(self, turtle):
        assert "cve:Reference" in turtle
        assert "logging.apache.org" in turtle
        assert "nvd.nist.gov" in turtle   # v2-only ref preserved
        assert "vendor-advisory" in turtle

    def test_cvss_metrics(self, turtle):
        assert "cve:CvssMetric" in turtle
        # v3.1 from v5
        assert "CVSS:3.1" in turtle
        assert '"10.0"' in turtle
        assert "CRITICAL" in turtle
        # v2 from v2-source
        assert "cve:2_0" in turtle or '"2.0"' in turtle

    def test_credits_section(self, turtle):
        assert "cve:Credit" in turtle
        # v5 credit (named)
        assert "Alibaba" in turtle
        # v2 credit (identifiers)
        assert "chenzhaojun" in turtle

    def test_timeline_both_entries(self, turtle):
        assert "cve:TimelineEntry" in turtle
        assert "privately" in turtle
        assert "publicly" in turtle

    def test_exploits_section(self, turtle):
        assert "cve:exploits" in turtle
        assert "wild" in turtle

    def test_workaround_section(self, turtle):
        assert "cve:workarounds" in turtle
        assert "formatMsgNoLookups" in turtle

    def test_write_to_file(self, merged, tmp_path):
        out = tmp_path / "test.ttl"
        result = to_turtle(merged, path=out)
        assert out.exists()
        assert out.read_text(encoding="utf-8") == result
