"""Transform NVD API v2.0 response dicts into KernelScan ingest format."""

from __future__ import annotations

NVD_CWE_PLACEHOLDERS = {"NVD-CWE-Other", "NVD-CWE-noinfo"}


def transform_cve(nvd_cve: dict) -> dict:
    """Convert a single NVD CVE dict to the POST /api/cves ingest format.

    Accepts the inner ``cve`` object from the NVD API response
    (i.e. ``item["cve"]`` inside the ``vulnerabilities`` list).
    """
    description = _extract_english_description(nvd_cve)
    cvss = _extract_cvss(nvd_cve)
    cwe_id = _extract_cwe(nvd_cve)
    published_at = _normalize_date(nvd_cve.get("published"))

    return {
        "id": nvd_cve["id"],
        "description": description,
        "published_at": published_at,
        "cvss_score": cvss.get("score"),
        "cvss_severity": cvss.get("severity"),
        "cvss_vector": cvss.get("vector"),
        "cwe_id": cwe_id,
        "introduced_in": None,
        "fixed_in": [],
    }


def transform_batch(nvd_cves: list[dict]) -> list[dict]:
    """Transform a list of NVD CVE dicts."""
    return [transform_cve(c) for c in nvd_cves]


def build_ingest_payload(cves: list[dict], source: str = "nvd") -> dict:
    """Wrap transformed CVEs in the payload expected by POST /api/cves."""
    return {"source": source, "cves": cves}


# ── Field extractors ──────────────────────────────────────────────────────


def _extract_english_description(nvd_cve: dict) -> str | None:
    descriptions = nvd_cve.get("descriptions", [])
    for d in descriptions:
        if d.get("lang") == "en":
            return d.get("value")
    # Fallback: return first description if no English one found
    if descriptions:
        return descriptions[0].get("value")
    return None


def _extract_cvss(nvd_cve: dict) -> dict:
    """Extract best available CVSS data (prefer V31 > V30 > V2)."""
    metrics = nvd_cve.get("metrics", {})

    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            data = entries[0].get("cvssData", {})
            return {
                "score": data.get("baseScore"),
                "severity": data.get("baseSeverity"),
                "vector": data.get("vectorString"),
            }

    # CVSS v2 fallback — different structure
    v2_entries = metrics.get("cvssMetricV2", [])
    if v2_entries:
        data = v2_entries[0].get("cvssData", {})
        return {
            "score": data.get("baseScore"),
            "severity": v2_entries[0].get("baseSeverity"),  # severity is on parent, not cvssData
            "vector": data.get("vectorString"),
        }

    return {}


def _extract_cwe(nvd_cve: dict) -> str | None:
    """Extract the first meaningful CWE ID from weaknesses."""
    for weakness in nvd_cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            value = desc.get("value", "")
            if value and value not in NVD_CWE_PLACEHOLDERS:
                return value
    return None


def _normalize_date(date_str: str | None) -> str | None:
    """Normalize NVD date format to ISO 8601 with Z suffix.

    NVD returns dates like ``"2024-01-15T00:00:00.000"`` (no timezone).
    The backend expects ISO 8601 (``"2024-01-15T00:00:00Z"``).
    """
    if not date_str:
        return None
    # Strip fractional seconds and trailing whitespace
    cleaned = date_str.strip()
    if "." in cleaned:
        cleaned = cleaned.split(".")[0]
    # Ensure Z suffix
    if not cleaned.endswith("Z") and "+" not in cleaned:
        cleaned += "Z"
    return cleaned
