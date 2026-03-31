"""
Tests for the unified CVE ingest pipeline.

Each test constructs a minimal representative record in one schema format,
ingests it, and asserts that the unified CveRecord fields are correct.
"""

import pytest

from framework_cve import ingest
from framework_cve.models import CveRecord, CveState, CvssVersion


# ---------------------------------------------------------------------------
# Fixtures — representative raw records
# ---------------------------------------------------------------------------

V2_MINIMAL = {
    "DATA_VERSION": "2.4",
    "CVE_ID": "CVE-2019-0001",
    "STATE": "PUBLIC",
    "TITLE": "Widget overflow",
    "DATE_PUBLIC": "2019-01-15",
    "DATE_ASSIGNED": "2019-01-10",
    "REQUESTER": "researcher@example.com",
    "ASSIGNER": "cve@mitre.org",
    "DWF": {
        "PROBLEM_TYPE": {
            "CWE": "CWE-79",
            "DESCRIPTION": {"eng": "Cross-site scripting"},
        },
        "IMPACT": {"eng": "Remote code execution possible"},
        "AFFECTS": [
            {
                "VENDOR": "Acme",
                "PRODUCT": "WidgetLib",
                "AFFECTED": ["1.0", ">=2.0", "<3.0"],
                "FIXEDIN": ["3.1"],
            }
        ],
        "DESCRIPTION": {
            "eng": "Acme WidgetLib before 3.1 allows XSS via crafted input.",
            "ger": "Acme WidgetLib vor 3.1 erlaubt XSS.",
        },
        "REFERENCES": [
            {
                "NAME": "Advisory",
                "TYPE": "WWW",
                "FILES": [{"URL": "https://example.com/advisory/2019-0001"}],
            }
        ],
        "CVSSv2": {
            "BM": {"AV": "N", "AC": "M", "AU": "N", "C": "P", "I": "P", "A": "N", "SCORE": "5.8"},
            "TM": {"SCORE": "4.5"},
        },
        "CVSSv3": {
            "BM": {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C", "C": "L", "I": "L", "A": "N", "SCORE": "6.1"},
        },
        "CREDITS": [
            {"ID": {"github-user": "jdoe"}, "ROLE": ["discoverer", "reporter"]}
        ],
        "TIMELINE": [
            {"TIMESTAMP": "2019-01-01", "TEXT": {"eng": "Discovered by jdoe"}},
        ],
        "WORKAROUND": {"eng": "Disable widget rendering"},
        "EXPLOITATION": {"eng": "Public PoC available"},
    },
}

V5_MINIMAL = {
    "dataType": "CVE_RECORD",
    "dataVersion": "5.0",
    "cveMetadata": {
        "cveId": "CVE-2021-44228",
        "assignerOrgId": "8254265b-2729-46b6-b9e3-3dfca2d5bfca",
        "assignerShortName": "mitre",
        "state": "PUBLISHED",
        "datePublished": "2021-12-10T00:00:00Z",
        "dateReserved": "2021-11-26T00:00:00Z",
        "dateUpdated": "2021-12-14T00:00:00Z",
    },
    "containers": {
        "cna": {
            "title": "Log4Shell — JNDI injection in Log4j2",
            "descriptions": [
                {"lang": "en", "value": "Apache Log4j2 2.0-beta9 through 2.15.0 allows remote code execution."},
            ],
            "affected": [
                {
                    "vendor": "Apache",
                    "product": "Log4j2",
                    "versions": [
                        {"version": "2.0-beta9", "status": "affected", "lessThan": "2.15.0", "versionType": "semver"},
                        {"version": "2.15.0", "status": "unaffected"},
                    ],
                    "defaultStatus": "unaffected",
                }
            ],
            "problemTypes": [
                {
                    "descriptions": [
                        {"lang": "en", "cweId": "CWE-917", "description": "Improper Neutralization", "type": "CWE"},
                    ]
                }
            ],
            "references": [
                {"url": "https://logging.apache.org/log4j/2.x/security.html", "name": "Log4j Security Page"},
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
                {"lang": "en", "value": "Chen Zhaojun of Alibaba Cloud Security Team", "type": "finder"}
            ],
            "timeline": [
                {"time": "2021-12-09T00:00:00Z", "lang": "en", "value": "Vulnerability disclosed publicly"},
            ],
            "workarounds": [
                {"lang": "en", "value": "Set log4j2.formatMsgNoLookups=true"}
            ],
        }
    },
}


# ---------------------------------------------------------------------------
# Version detection
# ---------------------------------------------------------------------------

class TestDetectVersion:
    def test_detects_v2_by_data_version(self):
        from framework_cve.ingest import detect_version
        assert detect_version({"DATA_VERSION": "2.4", "CVE_ID": "CVE-2000-0001"}) == "v2"

    def test_detects_v2_by_keys(self):
        from framework_cve.ingest import detect_version
        assert detect_version({"DWF": {}, "CVE_ID": "CVE-2000-0001"}) == "v2"

    def test_detects_v5_by_data_type(self):
        from framework_cve.ingest import detect_version
        assert detect_version({"dataType": "CVE_RECORD", "dataVersion": "5.0"}) == "v5"

    def test_detects_v5_by_metadata_key(self):
        from framework_cve.ingest import detect_version
        assert detect_version({"cveMetadata": {}, "containers": {}}) == "v5"


# ---------------------------------------------------------------------------
# V2 ingestion
# ---------------------------------------------------------------------------

class TestIngestV2:
    @pytest.fixture(scope="class")
    def record(self) -> CveRecord:
        return ingest(V2_MINIMAL)

    def test_source_schema(self, record):
        assert record.source_schema == "v2"

    def test_cve_id(self, record):
        assert record.cve_id == "CVE-2019-0001"

    def test_state_mapping(self, record):
        assert record.state == CveState.PUBLISHED

    def test_title(self, record):
        assert record.title == "Widget overflow"

    def test_assigner(self, record):
        assert record.assigner == "cve@mitre.org"

    def test_requester(self, record):
        assert record.requester == "researcher@example.com"

    def test_descriptions(self, record):
        langs = {d.lang for d in record.descriptions}
        assert "eng" in langs
        assert "ger" in langs
        en = next(d for d in record.descriptions if d.lang == "eng")
        assert "XSS" in en.value

    def test_problem_types(self, record):
        assert len(record.problem_types) == 1
        assert record.problem_types[0].cwe_id == "CWE-79"

    def test_affected_product(self, record):
        assert len(record.affected) == 1
        prod = record.affected[0]
        assert prod.vendor == "Acme"
        assert prod.product == "WidgetLib"
        # 3 affected + 1 fixed
        assert len(prod.versions) == 4
        statuses = {v.status for v in prod.versions}
        assert "affected" in statuses
        assert "unaffected" in statuses

    def test_version_range_operator(self, record):
        vrs = {(v.greater_equal, v.less_than, v.status) for v in record.affected[0].versions}
        assert ("2.0", None, "affected") in vrs
        assert (None, "3.0", "affected") in vrs

    def test_references(self, record):
        assert len(record.references) == 1
        assert "advisory" in record.references[0].url.lower()
        assert record.references[0].ref_type == "WWW"

    def test_cvss_metrics(self, record):
        versions = {m.version for m in record.metrics}
        assert CvssVersion.V2 in versions
        assert CvssVersion.V3_1 in versions

    def test_cvss2_score(self, record):
        v2m = next(m for m in record.metrics if m.version == CvssVersion.V2)
        assert v2m.base_score == pytest.approx(5.8)
        assert v2m.temporal_score == pytest.approx(4.5)

    def test_cvss2_vector_reconstructed(self, record):
        v2m = next(m for m in record.metrics if m.version == CvssVersion.V2)
        assert v2m.vector_string is not None
        assert "AV:N" in v2m.vector_string

    def test_credits(self, record):
        assert len(record.credits) == 1
        c = record.credits[0]
        assert c.identifiers.get("github-user") == "jdoe"
        assert "discoverer" in c.roles

    def test_timeline(self, record):
        assert len(record.timeline) == 1
        assert "jdoe" in record.timeline[0].value

    def test_workarounds(self, record):
        assert any("widget" in w.value.lower() for w in record.workarounds)

    def test_exploits(self, record):
        assert any("PoC" in e.value for e in record.exploits)

    def test_impact(self, record):
        assert any("execution" in i.value.lower() for i in record.impact)

    def test_raw_preserved(self, record):
        assert record.raw["CVE_ID"] == "CVE-2019-0001"


# ---------------------------------------------------------------------------
# V5 ingestion
# ---------------------------------------------------------------------------

class TestIngestV5:
    @pytest.fixture(scope="class")
    def record(self) -> CveRecord:
        return ingest(V5_MINIMAL)

    def test_source_schema(self, record):
        assert record.source_schema == "v5"

    def test_cve_id(self, record):
        assert record.cve_id == "CVE-2021-44228"

    def test_state_mapping(self, record):
        assert record.state == CveState.PUBLISHED

    def test_title(self, record):
        assert "Log4Shell" in record.title

    def test_assigner(self, record):
        assert record.assigner == "mitre"

    def test_descriptions(self, record):
        assert len(record.descriptions) == 1
        assert "Log4j2" in record.descriptions[0].value

    def test_problem_types(self, record):
        assert len(record.problem_types) == 1
        assert record.problem_types[0].cwe_id == "CWE-917"
        assert record.problem_types[0].type == "CWE"

    def test_affected_product(self, record):
        assert len(record.affected) == 1
        prod = record.affected[0]
        assert prod.vendor == "Apache"
        assert prod.product == "Log4j2"
        assert prod.default_status == "unaffected"
        assert len(prod.versions) == 2

    def test_affected_version_range(self, record):
        vrs = record.affected[0].versions
        affected = next(v for v in vrs if v.status == "affected")
        assert affected.less_than == "2.15.0"
        assert affected.version_type == "semver"

    def test_references(self, record):
        assert len(record.references) == 1
        assert "apache.org" in record.references[0].url

    def test_cvss_metrics(self, record):
        assert len(record.metrics) == 1
        m = record.metrics[0]
        assert m.version == CvssVersion.V3_1
        assert m.base_score == pytest.approx(10.0)
        assert m.base_severity == "CRITICAL"
        assert "CVSS:3.1" in m.vector_string

    def test_credits(self, record):
        assert len(record.credits) == 1
        c = record.credits[0]
        assert "Alibaba" in c.name
        assert "finder" in c.roles

    def test_timeline(self, record):
        assert len(record.timeline) == 1
        assert "disclosed" in record.timeline[0].value.lower()

    def test_workarounds(self, record):
        assert any("formatMsgNoLookups" in w.value for w in record.workarounds)

    def test_raw_preserved(self, record):
        assert record.raw["cveMetadata"]["cveId"] == "CVE-2021-44228"
