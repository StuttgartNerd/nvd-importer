"""HTTP POST to the KernelScan backend CVE ingestion API."""

from __future__ import annotations

import httpx

from nvd_importer.transformer import build_ingest_payload


def post_cves(
    base_url: str,
    cves: list[dict],
    batch_size: int = 500,
    source: str = "nvd",
    api_key: str | None = None,
) -> dict:
    """POST transformed CVEs to the backend in batches.

    Returns aggregated counts: ``{"ingested": N, "created": N, "updated": N}``.
    """
    url = f"{base_url.rstrip('/')}/api/cves"
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    totals = {"ingested": 0, "created": 0, "updated": 0}

    for i in range(0, len(cves), batch_size):
        batch = cves[i : i + batch_size]
        payload = build_ingest_payload(batch, source=source)
        response = httpx.post(url, json=payload, headers=headers, timeout=120.0)
        response.raise_for_status()
        result = response.json()
        totals["ingested"] += result.get("ingested", 0)
        totals["created"] += result.get("created", 0)
        totals["updated"] += result.get("updated", 0)

    return totals
