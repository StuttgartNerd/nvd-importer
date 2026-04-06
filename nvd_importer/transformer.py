"""Transform NVD API v2.0 response dicts into KernelScan ingest format."""

from __future__ import annotations

import re
from urllib.parse import unquote

NVD_CWE_PLACEHOLDERS = {"NVD-CWE-Other", "NVD-CWE-noinfo"}

# Reject CVEs whose description matches these patterns — they mention "kernel"
# but are clearly not Linux kernel vulnerabilities.
# Strategy: NVD keyword "linux kernel" already filters to relevant results.
# We only reject things we're *sure* are not the Linux kernel itself.
# Only reject things that are obviously not the Linux kernel.
# Better to have a few false positives than lose a real kernel CVE.
_REJECT_PATTERNS = [
    re.compile(r"^NVIDIA GPU", re.IGNORECASE),
    re.compile(r"NVIDIA GPU Display Driver", re.IGNORECASE),
    re.compile(r"^Windows Subsystem for Linux", re.IGNORECASE),
]

# Patterns to extract git commit hashes from NVD reference URLs.
# Each tuple: (compiled regex capturing the hash, source type for priority).
# URLs are unquoted before matching (handles %3B-encoded old-style URLs).
_KERNEL_COMMIT_PATTERNS = [
    # github.com/torvalds/linux/commit/{hash} — mainline
    (re.compile(r"https?://github\.com/torvalds/linux/commit/([0-9a-f]{7,40})\b"), "mainline"),
    # git.kernel.org torvalds tree (pub/scm path) — mainline
    (re.compile(r"https?://git\.kernel\.org/pub/scm/linux/kernel/git/torvalds/[^\s]*commit/?\?id=([0-9a-f]{7,40})\b"), "mainline"),
    # git.kernel.org torvalds tree (cgit path) — mainline
    (re.compile(r"https?://git\.kernel\.org/cgit/linux/kernel/git/torvalds/[^\s]*commit/?\?id=([0-9a-f]{7,40})\b"), "mainline"),
    # git.kernel.org ANY kernel subtree (pub/scm) — subsystem maintainer trees (davem/net, netdev, bpf, etc.)
    (re.compile(r"https?://git\.kernel\.org/pub/scm/linux/kernel/git/[^/]+/[^\s]*commit/?\?id=([0-9a-f]{7,40})\b"), "subsystem"),
    # git.kernel.org ANY kernel subtree (cgit path)
    (re.compile(r"https?://git\.kernel\.org/cgit/linux/kernel/git/[^/]+/[^\s]*commit/?\?id=([0-9a-f]{7,40})\b"), "subsystem"),
    # git.kernel.org/stable/c/{hash} — stable
    (re.compile(r"https?://git\.kernel\.org/stable/c/([0-9a-f]{7,40})\b"), "stable"),
    # git.kernel.org stable tree (pub/scm path) — stable
    (re.compile(r"https?://git\.kernel\.org/pub/scm/linux/kernel/git/stable/[^\s]*commit/?\?id=([0-9a-f]{7,40})\b"), "stable"),
    # Old-style git.kernel.org with ;h=HASH (after URL-decoding %3B → ;)
    (re.compile(r"https?://git\.kernel\.org/[^\s]*[;?]h=([0-9a-f]{7,40})\b"), "unknown"),
]

_SOURCE_PRIORITY = {"mainline": 0, "subsystem": 1, "stable": 2, "unknown": 3}


def transform_cve(nvd_cve: dict) -> dict:
    """Convert a single NVD CVE dict to the POST /api/cves ingest format.

    Accepts the inner ``cve`` object from the NVD API response
    (i.e. ``item["cve"]`` inside the ``vulnerabilities`` list).
    """
    description = _extract_english_description(nvd_cve)
    cvss = _extract_cvss(nvd_cve)
    cwe_id = _extract_cwe(nvd_cve)
    published_at = _normalize_date(nvd_cve.get("published"))
    references = _extract_references(nvd_cve)

    result = {
        "id": nvd_cve["id"],
        "description": description,
        "published_at": published_at,
        "cvss_score": cvss.get("score"),
        "cvss_severity": cvss.get("severity"),
        "cvss_vector": cvss.get("vector"),
        "cwe_id": cwe_id,
        "references": references,
        "nvd_status": nvd_cve.get("vulnStatus"),
        "nvd_last_modified": _normalize_date(nvd_cve.get("lastModified")),
        "cisa_exploit_add": nvd_cve.get("cisaExploitAdd"),
        "cisa_action_due": nvd_cve.get("cisaActionDue"),
        "cisa_required_action": nvd_cve.get("cisaRequiredAction"),
        "introduced_in": None,
        "fixed_in": [],
    }

    fix_commit = _extract_fix_commit(references)
    if fix_commit:
        result["fix_commit"] = fix_commit

    return result


def is_linux_kernel_cve(nvd_cve: dict) -> bool:
    """Return True if the CVE is about the Linux kernel.

    Uses CPE data when available (authoritative). Falls back to
    description heuristics for older CVEs without CPE assignments.
    """
    # If CPE configurations exist, use them as the authoritative source.
    # Only include CVEs where linux:linux_kernel appears in the CPE match.
    configs = nvd_cve.get("configurations", [])
    if configs:
        for cfg in configs:
            for node in cfg.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if "linux:linux_kernel" in match.get("criteria", ""):
                        return True
        return False

    # No CPE data — fall back to description-based rejection heuristics.
    # NVD keyword search already scopes to "linux kernel", so we only
    # reject CVEs that obviously aren't the Linux kernel itself.
    desc = _extract_english_description(nvd_cve) or ""
    for pattern in _REJECT_PATTERNS:
        if pattern.search(desc):
            return False
    return True


def transform_batch(nvd_cves: list[dict], filter_linux: bool = True) -> list[dict]:
    """Transform a list of NVD CVE dicts, optionally filtering to Linux kernel only."""
    if filter_linux:
        nvd_cves = [c for c in nvd_cves if is_linux_kernel_cve(c)]
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


def _extract_references(nvd_cve: dict) -> list[dict]:
    """Extract references as [{url, tags}], stripping the source field."""
    refs = nvd_cve.get("references", [])
    result = []
    for ref in refs:
        url = ref.get("url")
        if not url:
            continue
        result.append({
            "url": url,
            "tags": ref.get("tags", []),
        })
    return result


def _extract_fix_commit(references: list[dict]) -> str | None:
    """Extract the best kernel fix commit hash from reference URLs.

    Prefers patch-tagged mainline commits. Prefers full 40-char hashes
    but accepts shorter hashes (>= 12 chars) as fallback.
    URL-decodes references to handle old-style %3B-encoded git.kernel.org URLs.
    """
    # Collect candidates: (hash, source_type, is_patch_tagged)
    candidates: list[tuple[str, str, bool]] = []
    seen_hashes: set[str] = set()

    for ref in references:
        url = unquote(ref.get("url", ""))
        tags = ref.get("tags", [])
        is_patch = "Patch" in tags

        for pattern, source_type in _KERNEL_COMMIT_PATTERNS:
            m = pattern.search(url)
            if m:
                commit_hash = m.group(1)
                if len(commit_hash) >= 12 and commit_hash not in seen_hashes:
                    seen_hashes.add(commit_hash)
                    candidates.append((commit_hash, source_type, is_patch))
                break  # One match per URL is enough

    if not candidates:
        return None

    # Sort: prefer full hashes, then patch-tagged, then mainline before stable
    candidates.sort(key=lambda c: (
        len(c[0]) != 40,  # full hashes first
        not c[2],          # patch-tagged first
        _SOURCE_PRIORITY.get(c[1], 99),
    ))
    return candidates[0][0]


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
