"""Async client for the NIST NVD CVE API v2.0 with local caching."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from typing import Callable

import httpx

logger = logging.getLogger(__name__)

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000
# Without an API key NVD allows 5 requests per 30 s.
# With a key it's 50 per 30 s.
DELAY_NO_KEY = 6.5  # seconds between requests (safe margin)
DELAY_WITH_KEY = 0.7

DEFAULT_CACHE_DIR = "/tmp/nvd-cache"


def _cache_path(cache_dir: str, keyword: str) -> Path:
    """Return the cache file path for a given keyword search."""
    safe_name = keyword.replace(" ", "_").replace("/", "_")
    return Path(cache_dir) / f"{safe_name}.json"


def load_cache(cache_dir: str, keyword: str) -> list[dict] | None:
    """Load cached NVD CVEs from disk. Returns None if no cache exists."""
    path = _cache_path(cache_dir, keyword)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        if isinstance(data, list):
            return data
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Cache read failed (%s), will re-fetch", e)
    return None


def save_cache(cache_dir: str, keyword: str, cves: list[dict]) -> None:
    """Save raw NVD CVEs to disk cache."""
    path = _cache_path(cache_dir, keyword)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cves))
    logger.info("Cached %d CVEs to %s", len(cves), path)


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
    cache_dir: str | None = DEFAULT_CACHE_DIR,
) -> list[dict]:
    """Synchronous wrapper around :func:`fetch_all_cves` with optional caching.

    If *cache_dir* is set, checks for a cached response before hitting the API.
    After a successful fetch, saves the raw response to cache.
    """
    if cache_dir:
        cached = load_cache(cache_dir, keyword)
        if cached is not None:
            if on_progress:
                on_progress(len(cached), len(cached))
            return cached

    cves = asyncio.run(fetch_all_cves(keyword, api_key, on_progress))

    if cache_dir:
        save_cache(cache_dir, keyword, cves)

    return cves
