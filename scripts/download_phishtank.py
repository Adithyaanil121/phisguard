"""
Download PhishTank verified phishing URLs.

Usage:
    python scripts/download_phishtank.py [--output-dir data/raw]

Requirements:
    - PHISHTANK_API_KEY env var (register for free at phishtank.org)
    - Or run without a key to use the public endpoint (rate-limited)

Filters applied before saving:
    - verified == "yes"
    - online == "yes"

Output: data/raw/phishtank_YYYY-MM-DD.csv
Manifest: data/manifests/download_log.json (appended)
"""
import argparse
import csv
import hashlib
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

import httpx

PHISHTANK_URL = "http://data.phishtank.com/data/{key}/online-valid.csv"
PHISHTANK_PUBLIC_URL = "http://data.phishtank.com/data/online-valid.csv"
MANIFEST_FILE = "data/manifests/download_log.json"


def compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_manifest(manifest_path: Path) -> list:
    if manifest_path.exists():
        with manifest_path.open() as f:
            data = json.load(f)
            return data if isinstance(data, list) else [data]
    return []


def save_manifest(manifest_path: Path, entries: list) -> None:
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with manifest_path.open("w") as f:
        json.dump(entries, f, indent=2)


def download_phishtank(output_dir: str = "data/raw") -> None:
    today = datetime.now(UTC).strftime("%Y-%m-%d")
    output_path = Path(output_dir) / f"phishtank_{today}.csv"
    manifest_path = Path(MANIFEST_FILE)

    # Idempotent: skip if already downloaded today
    if output_path.exists():
        print(f"[phishtank] Already downloaded today: {output_path}")
        return

    output_path.parent.mkdir(parents=True, exist_ok=True)

    api_key = os.environ.get("PHISHTANK_API_KEY", "")
    url = PHISHTANK_URL.format(key=api_key) if api_key else PHISHTANK_PUBLIC_URL

    print(f"[phishtank] Downloading from {url} ...")
    try:
        with httpx.Client(timeout=60.0, follow_redirects=True) as client:
            response = client.get(url, headers={"User-Agent": "PhishGuard/1.0"})
        response.raise_for_status()
    except httpx.HTTPError as e:
        print(f"[phishtank] ERROR: Download failed: {e}", file=sys.stderr)
        sys.exit(1)

    raw_content = response.text
    reader = csv.DictReader(raw_content.splitlines())
    rows = list(reader)

    # Filter: verified + online
    filtered = [
        r for r in rows
        if r.get("verified", "").strip().lower() == "yes"
        and r.get("online", "").strip().lower() == "yes"
    ]

    with output_path.open("w", newline="", encoding="utf-8") as f:
        if filtered:
            writer = csv.DictWriter(f, fieldnames=filtered[0].keys())
            writer.writeheader()
            writer.writerows(filtered)

    sha256 = compute_sha256(output_path)
    record_count = len(filtered)
    print(f"[phishtank] Saved {record_count} verified+online entries to {output_path}")

    # Update manifest
    manifest = load_manifest(manifest_path)
    manifest.append({
        "source": "phishtank",
        "download_date": today,
        "record_count": record_count,
        "sha256": sha256,
        "license": "Free with attribution (phishtank.org terms)",
        "url": url,
        "output_file": str(output_path),
    })
    save_manifest(manifest_path, manifest)
    print(f"[phishtank] Manifest updated: {manifest_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Download PhishTank verified phishing URLs")
    parser.add_argument("--output-dir", default="data/raw", help="Output directory")
    args = parser.parse_args()
    download_phishtank(args.output_dir)


if __name__ == "__main__":
    main()
