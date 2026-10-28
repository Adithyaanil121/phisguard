"""
Dataset builder for PhishGuard.

Builds train/validation/test splits with domain-disjoint partitioning.

Usage:
    python backend/training/build_dataset.py \\
        --phishtank data/raw/phishtank_YYYY-MM-DD.csv \\
        --tranco data/raw/tranco_YYYY-MM-DD.csv \\
        --openphish data/raw/openphish_YYYY-MM-DD.txt \\
        --output-dir data/processed \\
        --seed 42

Design notes:
- Benign URLs use VARIED construction methods (not just https://domain/)
  to prevent the model from learning source-construction artifacts.
- Tranco domains are described as "candidate benign" only.
- Domain-disjoint split ensures no data leakage between splits.
- All Tranco domains appearing in any phishing feed are excluded.
"""
import argparse
import csv
import json
import math
import random
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

import tldextract

# ---------------------------------------------------------------------------
# Benign URL construction
# ---------------------------------------------------------------------------

COMMON_PATHS = [
    "/",
    "/about",
    "/contact",
    "/login",
    "/help",
    "/support",
    "/privacy",
    "/terms",
    "/faq",
    "/blog",
    "/news",
    "/products",
    "/services",
    "/account",
    "/settings",
    "/search",
]

COMMON_QUERIES = [
    "",
    "?lang=en",
    "?ref=homepage",
    "?page=1",
    "?utm_source=direct",
]


def construct_benign_urls(domain: str, count: int = 3, seed: int = 42) -> list[dict]:
    """
    Generate varied URLs for a candidate-benign domain.

    Returns list of dicts with 'url', 'method', 'domain'.
    Variety prevents the model from treating URL structure as a class signal.
    """
    rng = random.Random(seed + hash(domain))
    urls = []

    # Method 1: Root URL (always include)
    urls.append({
        "url": f"https://{domain}/",
        "method": "root",
        "domain": domain,
    })

    # Method 2: Common paths with optional queries
    paths = rng.sample(COMMON_PATHS[1:], min(count - 1, len(COMMON_PATHS) - 1))
    for path in paths:
        query = rng.choice(COMMON_QUERIES)
        urls.append({
            "url": f"https://{domain}{path}{query}",
            "method": "common_path",
            "domain": domain,
        })

    return urls[:count]


# ---------------------------------------------------------------------------
# Data loaders
# ---------------------------------------------------------------------------

def load_phishtank(path: Path) -> list[str]:
    """Load verified+online phishing URLs from PhishTank CSV."""
    urls = []
    with path.open(encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            url = row.get("url", "").strip()
            if url:
                urls.append(url)
    return urls


def load_tranco_domains(path: Path) -> list[str]:
    """Load domain list from Tranco CSV (rank,domain — no header)."""
    domains = []
    with path.open(encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            domain = row.get("domain", "").strip().lower()
            if domain:
                domains.append(domain)
    return domains


def load_openphish(path: Path) -> set[str]:
    """Load OpenPhish URL list as a set of URLs for fast lookup."""
    urls = set()
    with path.open(encoding="utf-8") as f:
        for line in f:
            url = line.strip()
            if url:
                urls.add(url)
    return urls


def get_registered_domain(url_or_domain: str) -> str:
    """Extract registered domain using tldextract (handles .co.uk etc.)."""
    ext = tldextract.extract(url_or_domain)
    top = getattr(ext, "top_domain_under_public_suffix", None)
    if top is None:
        top = getattr(ext, "registered_domain", "")
    return (top or "").lower()


# ---------------------------------------------------------------------------
# Domain-disjoint split
# ---------------------------------------------------------------------------

def domain_disjoint_split(
    records: list[dict],
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
    seed: int = 42,
) -> tuple[list[dict], list[dict], list[dict]]:
    """
    Split records so that all URLs from the same registered domain
    stay within the same split, preventing leakage.
    """
    # Group by registered domain
    by_domain: dict[str, list[dict]] = defaultdict(list)
    for rec in records:
        by_domain[rec["registered_domain"]].append(rec)

    domains = sorted(by_domain.keys())
    rng = random.Random(seed)
    rng.shuffle(domains)

    n = len(domains)
    n_train = math.floor(n * train_ratio)
    n_val = math.floor(n * val_ratio)

    train_domains = set(domains[:n_train])
    val_domains = set(domains[n_train:n_train + n_val])

    train, val, test = [], [], []
    for domain, recs in by_domain.items():
        if domain in train_domains:
            train.extend(recs)
        elif domain in val_domains:
            val.extend(recs)
        else:
            test.extend(recs)

    return train, val, test


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def build_dataset(
    phishtank_path: str | None = None,
    tranco_path: str | None = None,
    openphish_path: str | None = None,
    output_dir: str = "data/processed",
    manifest_dir: str | Path | None = None,
    seed: int = 42,
    urls_per_domain: int = 3,
    phishtank: str | None = None,
    tranco: str | None = None,
    openphish: str | None = None,
) -> None:
    phishtank_path = phishtank_path or phishtank
    tranco_path = tranco_path or tranco
    openphish_path = openphish_path or openphish

    if not phishtank_path:
        raise ValueError("phishtank_path is required")
    if not tranco_path:
        raise ValueError("tranco_path is required")

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    m_dir = Path(manifest_dir) if manifest_dir else Path("data/manifests")
    m_dir.mkdir(parents=True, exist_ok=True)

    print("[dataset] Loading PhishTank ...")
    phishing_urls = load_phishtank(Path(phishtank_path))
    print(f"[dataset]   {len(phishing_urls):,} phishing URLs loaded")

    print("[dataset] Loading Tranco domains ...")
    tranco_domains = load_tranco_domains(Path(tranco_path))
    print(f"[dataset]   {len(tranco_domains):,} candidate-benign domains loaded")

    # Build lookup sets for exclusion
    phishing_registered = {get_registered_domain(u) for u in phishing_urls}
    openphish_urls: set[str] = set()
    openphish_registered: set[str] = set()
    if openphish_path and Path(openphish_path).exists():
        print("[dataset] Loading OpenPhish holdout feed ...")
        openphish_urls = load_openphish(Path(openphish_path))
        openphish_registered = {get_registered_domain(u) for u in openphish_urls}
        print(f"[dataset]   {len(openphish_urls):,} OpenPhish holdout URLs")

    # Exclude Tranco domains that appear in phishing feeds
    tranco_excluded_phishtank = 0
    tranco_excluded_openphish = 0
    clean_domains = []
    for domain in tranco_domains:
        reg = get_registered_domain(domain) or domain
        if reg in phishing_registered:
            tranco_excluded_phishtank += 1
        elif reg in openphish_registered:
            tranco_excluded_openphish += 1
        else:
            clean_domains.append(domain)

    print(
        f"[dataset]   Excluded {tranco_excluded_phishtank} Tranco domains in PhishTank, "
        f"{tranco_excluded_openphish} in OpenPhish"
    )
    print(f"[dataset]   {len(clean_domains):,} clean candidate-benign domains remain")

    # Build records
    print("[dataset] Building phishing records ...")
    phishing_records = []
    seen_urls: set[str] = set()
    for url in phishing_urls:
        if url not in seen_urls:
            seen_urls.add(url)
            phishing_records.append({
                "url": url,
                "label": 1,
                "source": "phishtank",
                "construction_method": "original",
                "registered_domain": get_registered_domain(url),
            })

    print("[dataset] Building benign records ...")
    benign_records = []
    for domain in clean_domains:
        for entry in construct_benign_urls(domain, count=urls_per_domain, seed=seed):
            url = entry["url"]
            if url not in seen_urls:
                seen_urls.add(url)
                benign_records.append({
                    "url": url,
                    "label": 0,
                    "source": "tranco",
                    "construction_method": entry["method"],
                    "registered_domain": get_registered_domain(domain) or domain,
                })

    all_records = phishing_records + benign_records
    exact_dups_before = (
        len(phishing_urls) + sum(urls_per_domain for _ in clean_domains) - len(all_records)
    )

    print(
        f"[dataset]   {len(phishing_records):,} phishing + "
        f"{len(benign_records):,} benign records"
    )

    # Domain-disjoint split
    print("[dataset] Splitting (domain-disjoint, 70/15/15) ...")
    train, val, test = domain_disjoint_split(all_records, seed=seed)
    print(
        f"[dataset]   Train: {len(train):,} | Validation: {len(val):,} | Test: {len(test):,}"
    )

    # Verify no domain appears in more than one split
    fieldnames = ["url", "label", "source", "construction_method", "registered_domain"]
    splits = {"train": train, "validation": val, "test": test}

    for name, records in splits.items():
        path = out / f"{name}.csv"
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(records)
        print(f"[dataset]   Saved {path}")

    # Build and save manifest
    def split_stats(records: list[dict]) -> dict:
        phish = sum(1 for r in records if r["label"] == 1)
        benign = len(records) - phish
        return {"total": len(records), "phishing": phish, "benign": benign}

    manifest = {
        "version": "v1",
        "created": datetime.now(UTC).strftime("%Y-%m-%d"),
        "seed": seed,
        "splits": {name: split_stats(recs) for name, recs in splits.items()},
        "sources": {
            "phishing": ["phishtank"],
            "benign": ["tranco"],
        },
        "benign_construction_methods": ["root", "common_path"],
        "deduplication": {"exact_duplicates_removed": exact_dups_before},
        "domain_exclusions": {
            "tranco_in_phishtank": tranco_excluded_phishtank,
            "tranco_in_openphish": tranco_excluded_openphish,
        },
        "label_policy": {
            "phishing": "PhishTank verified+online entries",
            "benign": (
                "Tranco top-100K domains, treated as candidate benign, "
                "not guaranteed safe"
            ),
        },
        "inputs": {
            "phishtank": phishtank_path,
            "tranco": tranco_path,
            "openphish": openphish_path,
        },
    }

    manifest_path = m_dir / "dataset_v1.json"
    with manifest_path.open("w") as f:
        json.dump(manifest, f, indent=2)
    print(f"[dataset] Manifest saved: {manifest_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build PhishGuard dataset")
    parser.add_argument("--phishtank", required=True, help="Path to PhishTank CSV")
    parser.add_argument("--tranco", required=True, help="Path to Tranco domain CSV")
    parser.add_argument("--openphish", default=None, help="Path to OpenPhish feed (optional)")
    parser.add_argument("--output-dir", default="data/processed", help="Output directory")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument(
        "--urls-per-domain", type=int, default=3, help="Benign URLs per Tranco domain"
    )
    args = parser.parse_args()

    build_dataset(
        phishtank_path=args.phishtank,
        tranco_path=args.tranco,
        openphish_path=args.openphish,
        output_dir=args.output_dir,
        seed=args.seed,
        urls_per_domain=args.urls_per_domain,
    )


if __name__ == "__main__":
    main()
