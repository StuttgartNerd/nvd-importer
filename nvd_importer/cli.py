"""CLI entry point for nvd-importer."""

from __future__ import annotations

import argparse
import json
import os
import sys

from nvd_importer import __version__
from nvd_importer.transformer import build_ingest_payload, transform_batch


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="nvd-importer",
        description="Fetch Linux kernel CVEs from NVD and import into KernelScan",
    )
    parser.add_argument("--api-key", metavar="KEY",
                        default=os.getenv("NVD_API_KEY"),
                        help="NVD API key (or set NVD_API_KEY env var)")
    parser.add_argument("--keyword", default="linux kernel",
                        help='NVD keyword search (default: "linux kernel")')
    parser.add_argument("--input", "-i", metavar="FILE", dest="input_file",
                        help="Read NVD JSON from file instead of fetching from API")
    parser.add_argument("--output", "-o", metavar="FILE",
                        help="Write ingest JSON to file (default: stdout)")
    parser.add_argument("--post", metavar="URL",
                        help="POST to backend (e.g. http://localhost:8000)")
    parser.add_argument("--batch-size", type=int, default=500,
                        help="CVEs per POST batch (default: 500)")
    parser.add_argument("--pretty", action="store_true",
                        help="Pretty-print JSON output")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Suppress progress messages")
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")

    args = parser.parse_args()

    # ── Load CVEs ─────────────────────────────────────────────────────────
    if args.input_file:
        cves = _load_from_file(args.input_file, quiet=args.quiet)
    else:
        cves = _fetch_from_nvd(args.keyword, args.api_key, quiet=args.quiet)

    if not args.quiet:
        print(f"Transformed {len(cves)} CVEs", file=sys.stderr)

    # ── Output ────────────────────────────────────────────────────────────
    payload = build_ingest_payload(cves)
    indent = 2 if args.pretty else None
    json_str = json.dumps(payload, indent=indent)

    if args.output:
        with open(args.output, "w") as f:
            f.write(json_str)
            f.write("\n")
        if not args.quiet:
            size_kb = len(json_str) / 1024
            print(f"Written to {args.output} ({size_kb:.1f} KB)", file=sys.stderr)
    elif not args.post:
        # Only print to stdout if not posting (avoid mixing data with progress)
        print(json_str)

    # ── POST ──────────────────────────────────────────────────────────────
    if args.post:
        from nvd_importer.poster import post_cves

        if not args.quiet:
            print(f"POSTing {len(cves)} CVEs to {args.post}/api/cves "
                  f"(batch size {args.batch_size})...", file=sys.stderr)
        try:
            result = post_cves(args.post, cves, batch_size=args.batch_size)
            if not args.quiet:
                print(f"Done: {result['created']} created, "
                      f"{result['updated']} updated, "
                      f"{result['ingested']} total ingested", file=sys.stderr)
        except Exception as e:
            print(f"POST failed: {e}", file=sys.stderr)
            sys.exit(1)


def _fetch_from_nvd(keyword: str, api_key: str | None, *, quiet: bool) -> list[dict]:
    """Fetch from NVD API and transform to ingest format."""
    from nvd_importer.fetcher import fetch_all_cves_sync

    def on_progress(fetched: int, total: int) -> None:
        if not quiet:
            print(f"Fetched {fetched}/{total} CVEs from NVD...", file=sys.stderr)

    if not quiet:
        key_status = "with API key" if api_key else "without API key (slow)"
        print(f'Fetching "{keyword}" from NVD {key_status}...', file=sys.stderr)

    nvd_cves = fetch_all_cves_sync(keyword=keyword, api_key=api_key, on_progress=on_progress)

    if not quiet:
        print(f"Fetched {len(nvd_cves)} raw CVEs from NVD", file=sys.stderr)

    return transform_batch(nvd_cves)


def _load_from_file(path: str, *, quiet: bool) -> list[dict]:
    """Load CVEs from a JSON file, auto-detecting format.

    If the file has a ``"cves"`` key, treat as pre-processed ingest format.
    If it has a ``"vulnerabilities"`` key, treat as NVD API response and transform.
    If it's a list of dicts with ``"id"`` keys, treat as raw NVD CVE objects.
    """
    if not quiet:
        print(f"Loading from {path}...", file=sys.stderr)

    with open(path) as f:
        data = json.load(f)

    # Pre-processed ingest format
    if isinstance(data, dict) and "cves" in data:
        if not quiet:
            print(f"Detected ingest format ({len(data['cves'])} CVEs)", file=sys.stderr)
        return data["cves"]

    # NVD API response wrapper
    if isinstance(data, dict) and "vulnerabilities" in data:
        raw = [item["cve"] for item in data["vulnerabilities"] if "cve" in item]
        if not quiet:
            print(f"Detected NVD response format ({len(raw)} CVEs), transforming...", file=sys.stderr)
        return transform_batch(raw)

    # List of raw NVD CVE objects
    if isinstance(data, list) and data and "id" in data[0]:
        if not quiet:
            print(f"Detected NVD CVE list ({len(data)} CVEs), transforming...", file=sys.stderr)
        return transform_batch(data)

    print(f"Error: unrecognized JSON format in {path}", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
