"""Async client for the NIST NVD CVE API v2.0."""

from __future__ import annotations

import asyncio
import logging
import sys
from typing import Callable

import httpx

logger = logging.getLogger(__name__)

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000
# Without an API key NVD allows 5 requests per 30 s.
# With a key it's 50 per 30 s.
DELAY_NO_KEY = 6.5  # seconds between requests (safe margin)
DELAY_WITH_KEY = 0.7


async def fetch_all_cves(
    keyword: str = "linux kernel",
    api_key: str | None = None,
    on_progress: Callable[[int, int], None] | None = None,
) -> list[dict]:
    """Fetch all NVD CVEs matching *keyword*.

    Returns the inner ``cve`` dicts (unwrapped from the ``vulnerabilities`` list).

    *on_progress* is called with ``(fetched_so_far, total_results)`` after each page.
    """
    headers: dict[str, str] = {}
    if api_key:
        headers["apiKey"] = api_key
    delay = DELAY_WITH_KEY if api_key else DELAY_NO_KEY

    params: dict[str, str | int] = {
        "keywordSearch": keyword,
        "resultsPerPage": PAGE_SIZE,
        "startIndex": 0,
    }

    all_cves: list[dict] = []

    async with httpx.AsyncClient(timeout=30.0) as client:
        while True:
            logger.info("NVD request startIndex=%s", params["startIndex"])
            resp = await client.get(NVD_BASE, params=params, headers=headers)
            resp.raise_for_status()
            data = resp.json()

            vulnerabilities = data.get("vulnerabilities", [])
            for item in vulnerabilities:
                cve = item.get("cve")
                if cve:
                    all_cves.append(cve)

            total_results = data.get("totalResults", 0)
            fetched = int(params["startIndex"]) + len(vulnerabilities)
            logger.info("NVD fetched %d / %d", fetched, total_results)

            if on_progress:
                on_progress(fetched, total_results)

            if fetched >= total_results:
                break

            params["startIndex"] = fetched
            await asyncio.sleep(delay)

    return all_cves


def fetch_all_cves_sync(
    keyword: str = "linux kernel",
    api_key: str | None = None,
    on_progress: Callable[[int, int], None] | None = None,
) -> list[dict]:
    """Synchronous wrapper around :func:`fetch_all_cves`."""
    return asyncio.run(fetch_all_cves(keyword, api_key, on_progress))
