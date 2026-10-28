"""
Download Tranco top-100K domain list (candidate benign domains).

Usage:
    python scripts/download_tranco.py [--output-dir data/raw]

Tranco is a research-grade list of popular domains from multiple
ranking providers. Domains here are CANDIDATE benign — they are
not guaranteed safe and must be excluded if they appear in any
phishing feed.

Output: data/raw/tranco_YYYY-MM-DD.csv
Manifest: data/manifests/download_log.json (appended)
"""
import argparse
import csv
import hashlib
import io
import json
import sys
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import httpx

# Tranco top 1M zip archive
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
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


def download_tranco(output_dir: str = "data/raw", top_n: int = 100_000) -> None:
    today = datetime.now(UTC).strftime("%Y-%m-%d")
    output_path = Path(output_dir) / f"tranco_{today}.csv"
    manifest_path = Path(MANIFEST_FILE)

    # Idempotent: skip if already downloaded today
    if output_path.exists():
        print(f"[tranco] Already downloaded today: {output_path}")
        return

    output_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"[tranco] Downloading top {top_n:,} from Tranco ({TRANCO_URL}) ...")
    try:
        with httpx.Client(timeout=180.0, follow_redirects=True) as client:
            response = client.get(TRANCO_URL, headers={"User-Agent": "PhishGuard/1.0"})
        response.raise_for_status()
    except httpx.HTTPError as e:
        print(f"[tranco] ERROR: Download failed: {e}", file=sys.stderr)
        sys.exit(1)

    # Unzip in-memory
    with zipfile.ZipFile(io.BytesIO(response.content)) as z:
        # Find the csv filename inside the zip
        csv_filename = [name for name in z.namelist() if name.endswith(".csv")][0]
        with z.open(csv_filename) as f:
            lines = io.TextIOWrapper(f, encoding="utf-8").readlines()

    records = []
    for line in lines[:top_n]:
        parts = line.strip().split(",", 1)
        if len(parts) == 2:
            rank, domain = parts[0].strip(), parts[1].strip()
            records.append({"rank": rank, "domain": domain})

    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["rank", "domain"])
        writer.writeheader()
        writer.writerows(records)

    sha256 = compute_sha256(output_path)
    record_count = len(records)
    print(f"[tranco] Saved {record_count:,} domains to {output_path}")

    # Update manifest
    manifest = load_manifest(manifest_path)
    manifest.append({
        "source": "tranco",
        "download_date": today,
        "record_count": record_count,
        "sha256": sha256,
        "license": "Free for research (tranco-list.eu)",
        "url": TRANCO_URL,
        "output_file": str(output_path),
        "note": (
            "Candidate benign only. Domains not guaranteed safe. "
            "Must be excluded if found in any phishing feed."
        ),
    })
    save_manifest(manifest_path, manifest)
    print(f"[tranco] Manifest updated: {manifest_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Download Tranco top-100K domain list")
    parser.add_argument("--output-dir", default="data/raw", help="Output directory")
    parser.add_argument("--top-n", type=int, default=100_000, help="Max domains to fetch")
    args = parser.parse_args()
    download_tranco(args.output_dir, args.top_n)


if __name__ == "__main__":
    main()
