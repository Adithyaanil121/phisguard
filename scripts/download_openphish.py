"""
Download OpenPhish community feed (free tier).

Usage:
    python scripts/download_openphish.py [--output-dir data/raw]

IMPORTANT — Holdout use only:
    This feed is used as a time-separated holdout set and evaluation
    evidence source. Do NOT include OpenPhish URLs in the training
    or validation sets to avoid data leakage.

Output: data/raw/openphish_YYYY-MM-DD.txt
Manifest: data/manifests/download_log.json (appended)
"""
import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import httpx

OPENPHISH_URL = "https://openphish.com/feed.txt"
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


def download_openphish(output_dir: str = "data/raw") -> None:
    today = datetime.now(UTC).strftime("%Y-%m-%d")
    output_path = Path(output_dir) / f"openphish_{today}.txt"
    manifest_path = Path(MANIFEST_FILE)

    # Idempotent: skip if already downloaded today
    if output_path.exists():
        print(f"[openphish] Already downloaded today: {output_path}")
        return

    output_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"[openphish] Downloading from {OPENPHISH_URL} ...")
    try:
        with httpx.Client(timeout=30.0, follow_redirects=True) as client:
            response = client.get(OPENPHISH_URL, headers={"User-Agent": "PhishGuard/1.0"})
        response.raise_for_status()
    except httpx.HTTPError as e:
        print(f"[openphish] ERROR: Download failed: {e}", file=sys.stderr)
        sys.exit(1)

    # One URL per line; filter empty lines and strip whitespace
    lines = [ln.strip() for ln in response.text.splitlines() if ln.strip()]
    record_count = len(lines)

    with output_path.open("w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    sha256 = compute_sha256(output_path)
    print(f"[openphish] Saved {record_count:,} URLs to {output_path}")

    # Update manifest
    manifest = load_manifest(manifest_path)
    manifest.append({
        "source": "openphish",
        "download_date": today,
        "record_count": record_count,
        "sha256": sha256,
        "license": "OpenPhish Community Feed (free, non-commercial)",
        "url": OPENPHISH_URL,
        "output_file": str(output_path),
        "usage": (
            "HOLDOUT ONLY — do not use for training or validation. "
            "Use as time-separated test evidence and to exclude Tranco domains."
        ),
    })
    save_manifest(manifest_path, manifest)
    print(f"[openphish] Manifest updated: {manifest_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Download OpenPhish community feed")
    parser.add_argument("--output-dir", default="data/raw", help="Output directory")
    args = parser.parse_args()
    download_openphish(args.output_dir)


if __name__ == "__main__":
    main()
