"""Tests for nvd_importer.transformer."""

from nvd_importer.transformer import (
    build_ingest_payload,
    transform_batch,
    transform_cve,
)
from tests.conftest import (
    SAMPLE_NVD_CVE_FULL,
    SAMPLE_NVD_CVE_MINIMAL,
    SAMPLE_NVD_CVE_V2_ONLY,
    SAMPLE_NVD_CVE_V30,
)


class TestTransformCve:
    def test_full_cve(self):
        result = transform_cve(SAMPLE_NVD_CVE_FULL)
        assert result["id"] == "CVE-2024-1001"
        assert "BPF subsystem" in result["description"]
        assert result["published_at"] == "2024-01-15T10:30:00Z"
        assert result["cvss_score"] == 7.8
        assert result["cvss_severity"] == "HIGH"
        assert result["cvss_vector"] == "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
        assert result["cwe_id"] == "CWE-416"
        assert result["introduced_in"] is None
        assert result["fixed_in"] == []

    def test_cvss_v30_fallback(self):
        result = transform_cve(SAMPLE_NVD_CVE_V30)
        assert result["cvss_score"] == 5.5
        assert result["cvss_severity"] == "MEDIUM"
        assert result["cvss_vector"].startswith("CVSS:3.0/")

    def test_cvss_v2_fallback(self):
        result = transform_cve(SAMPLE_NVD_CVE_V2_ONLY)
        assert result["cvss_score"] == 7.2
        assert result["cvss_severity"] == "HIGH"
        assert result["cvss_vector"] == "AV:L/AC:L/Au:N/C:C/I:C/A:C"

    def test_placeholder_cwe_skipped(self):
        """NVD-CWE-noinfo and NVD-CWE-Other should be treated as no CWE."""
        result = transform_cve(SAMPLE_NVD_CVE_V2_ONLY)
        assert result["cwe_id"] is None

    def test_minimal_cve(self):
        result = transform_cve(SAMPLE_NVD_CVE_MINIMAL)
        assert result["id"] == "CVE-2024-9999"
        assert result["description"] is None
        assert result["published_at"] is None
        assert result["cvss_score"] is None
        assert result["cvss_severity"] is None
        assert result["cvss_vector"] is None
        assert result["cwe_id"] is None

    def test_date_with_timezone_preserved(self):
        cve = {**SAMPLE_NVD_CVE_MINIMAL, "published": "2024-01-01T00:00:00+05:00"}
        result = transform_cve(cve)
        assert result["published_at"] == "2024-01-01T00:00:00+05:00"

    def test_date_already_has_z(self):
        cve = {**SAMPLE_NVD_CVE_MINIMAL, "published": "2024-01-01T00:00:00Z"}
        result = transform_cve(cve)
        assert result["published_at"] == "2024-01-01T00:00:00Z"

    def test_non_english_fallback(self):
        cve = {
            **SAMPLE_NVD_CVE_MINIMAL,
            "descriptions": [{"lang": "es", "value": "Vulnerabilidad en el kernel."}],
        }
        result = transform_cve(cve)
        assert result["description"] == "Vulnerabilidad en el kernel."

    def test_multiple_weaknesses_picks_first_valid(self):
        cve = {
            **SAMPLE_NVD_CVE_MINIMAL,
            "weaknesses": [
                {"description": [{"lang": "en", "value": "NVD-CWE-Other"}]},
                {"description": [{"lang": "en", "value": "CWE-787"}]},
            ],
        }
        result = transform_cve(cve)
        assert result["cwe_id"] == "CWE-787"


class TestTransformBatch:
    def test_batch(self):
        results = transform_batch([SAMPLE_NVD_CVE_FULL, SAMPLE_NVD_CVE_V30])
        assert len(results) == 2
        assert results[0]["id"] == "CVE-2024-1001"
        assert results[1]["id"] == "CVE-2023-5000"

    def test_empty_batch(self):
        assert transform_batch([]) == []


class TestBuildIngestPayload:
    def test_wraps_cves(self):
        cves = [{"id": "CVE-1"}]
        payload = build_ingest_payload(cves)
        assert payload["source"] == "nvd"
        assert payload["cves"] == cves

    def test_custom_source(self):
        payload = build_ingest_payload([], source="manual")
        assert payload["source"] == "manual"
