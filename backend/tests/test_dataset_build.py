"""
Tests for build_dataset.py — uses synthetic data only; no network calls.

Verifies:
- Domain-disjoint split: no registered domain spans multiple splits.
- No exact duplicate URLs.
- Tranco domains present in phishing feed are excluded.
- Benign records include varied construction methods (not just root).
- Manifest stats match actual split sizes.
- Script is deterministic (same seed → identical output).
"""
import csv
import json
import sys
from pathlib import Path

import pytest

# Ensure backend package is importable from tests
sys.path.insert(0, str(Path(__file__).parent.parent))

from training.build_dataset import (
    build_dataset,
    construct_benign_urls,
    domain_disjoint_split,
    get_registered_domain,
)

# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------

class TestConstructBenignUrls:
    def test_always_includes_root(self):
        results = construct_benign_urls("example.com", count=3, seed=42)
        assert any(r["method"] == "root" for r in results)

    def test_respects_count(self):
        for n in (1, 2, 3, 5):
            results = construct_benign_urls("test.com", count=n, seed=42)
            assert len(results) <= n

    def test_variety_with_count_3(self):
        results = construct_benign_urls("example.com", count=3, seed=42)
        methods = {r["method"] for r in results}
        assert len(methods) > 1, "Expected both root and common_path methods"

    def test_all_urls_valid_https(self):
        for entry in construct_benign_urls("google.com", count=3, seed=42):
            assert entry["url"].startswith("https://")

    def test_deterministic(self):
        a = construct_benign_urls("example.com", count=3, seed=42)
        b = construct_benign_urls("example.com", count=3, seed=42)
        assert a == b


class TestGetRegisteredDomain:
    def test_simple_domain(self):
        assert get_registered_domain("https://example.com/path") == "example.com"

    def test_subdomain_stripped(self):
        assert get_registered_domain("https://login.paypal.com/") == "paypal.com"

    def test_co_uk_handled(self):
        result = get_registered_domain("https://bbc.co.uk/news")
        assert result == "bbc.co.uk"

    def test_bare_domain(self):
        result = get_registered_domain("google.com")
        assert result == "google.com"


class TestDomainDisjointSplit:
    def _make_records(self, domains: list[str]) -> list[dict]:
        """Create fake records with one URL per domain."""
        return [{"url": f"https://{d}/", "registered_domain": d} for d in domains]

    def test_no_domain_in_multiple_splits(self):
        domains = [f"domain{i}.com" for i in range(100)]
        records = self._make_records(domains)
        train, val, test = domain_disjoint_split(records, seed=42)

        train_domains = {r["registered_domain"] for r in train}
        val_domains = {r["registered_domain"] for r in val}
        test_domains = {r["registered_domain"] for r in test}

        assert not (train_domains & val_domains), "Train/val domain overlap"
        assert not (train_domains & test_domains), "Train/test domain overlap"
        assert not (val_domains & test_domains), "Val/test domain overlap"

    def test_all_records_assigned(self):
        domains = [f"domain{i}.com" for i in range(60)]
        records = self._make_records(domains)
        train, val, test = domain_disjoint_split(records, seed=42)
        assert len(train) + len(val) + len(test) == len(records)

    def test_deterministic(self):
        domains = [f"domain{i}.com" for i in range(50)]
        records = self._make_records(domains)
        a_train, a_val, a_test = domain_disjoint_split(records, seed=42)
        b_train, b_val, b_test = domain_disjoint_split(records, seed=42)
        assert [r["registered_domain"] for r in a_train] == [
            r["registered_domain"] for r in b_train
        ]

    def test_approximate_ratios(self):
        domains = [f"domain{i}.com" for i in range(200)]
        records = self._make_records(domains)
        train, val, test = domain_disjoint_split(records, train_ratio=0.70, val_ratio=0.15, seed=42)
        total = len(records)
        assert 0.60 <= len(train) / total <= 0.80
        assert 0.08 <= len(val) / total <= 0.22
        assert 0.05 <= len(test) / total <= 0.25


# ---------------------------------------------------------------------------
# Integration test — full pipeline on synthetic data
# ---------------------------------------------------------------------------

def _write_phishtank_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["phish_id", "url", "phish_detail_url", "submission_time",
                  "verified", "verification_time", "online", "target"]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})


def _write_tranco_csv(path: Path, domains: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["rank", "domain"])
        writer.writeheader()
        for i, d in enumerate(domains, 1):
            writer.writerow({"rank": i, "domain": d})


def _write_openphish_txt(path: Path, urls: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        f.write("\n".join(urls) + "\n")


@pytest.fixture()
def synthetic_inputs(tmp_path):
    # 20 phishing URLs across 20 distinct domains
    phishing = [
        {"url": f"http://phish{i}.evil.com/steal?id={i}",
         "verified": "yes", "online": "yes"}
        for i in range(20)
    ]
    phishtank_path = tmp_path / "raw" / "phishtank.csv"
    _write_phishtank_csv(phishtank_path, phishing)

    # 60 Tranco domains, 2 of which overlap with phishing feed
    tranco_domains = [f"legitimate{i}.com" for i in range(58)]
    tranco_domains += ["phish0.evil.com", "phish1.evil.com"]  # should be excluded
    tranco_path = tmp_path / "raw" / "tranco.csv"
    _write_tranco_csv(tranco_path, tranco_domains)

    # OpenPhish with 5 unique phishing URLs (not in PhishTank)
    openphish_urls = [f"http://openphish{i}.bad.com/login" for i in range(5)]
    openphish_path = tmp_path / "raw" / "openphish.txt"
    _write_openphish_txt(openphish_path, openphish_urls)

    output_dir = tmp_path / "processed"
    manifest_dir = tmp_path / "manifests"
    return {
        "phishtank": str(phishtank_path),
        "tranco": str(tranco_path),
        "openphish": str(openphish_path),
        "output_dir": str(output_dir),
        "manifest_dir": str(manifest_dir),
        "tmp_path": tmp_path,
    }


def test_full_pipeline_no_domain_overlap(synthetic_inputs):
    build_dataset(**{k: v for k, v in synthetic_inputs.items() if k != "tmp_path"}, seed=42)
    out = Path(synthetic_inputs["output_dir"])

    domains_by_split = {}
    for split in ("train", "validation", "test"):
        rows = list(csv.DictReader((out / f"{split}.csv").open(encoding="utf-8")))
        domains_by_split[split] = {r["registered_domain"] for r in rows}

    assert not (domains_by_split["train"] & domains_by_split["validation"])
    assert not (domains_by_split["train"] & domains_by_split["test"])
    assert not (domains_by_split["validation"] & domains_by_split["test"])


def test_full_pipeline_no_exact_duplicate_urls(synthetic_inputs):
    build_dataset(**{k: v for k, v in synthetic_inputs.items() if k != "tmp_path"}, seed=42)
    out = Path(synthetic_inputs["output_dir"])

    all_urls = []
    for split in ("train", "validation", "test"):
        rows = list(csv.DictReader((out / f"{split}.csv").open(encoding="utf-8")))
        all_urls.extend(r["url"] for r in rows)

    assert len(all_urls) == len(set(all_urls)), "Duplicate URLs found across splits"


def test_full_pipeline_excluded_tranco_phishing_domains(synthetic_inputs):
    build_dataset(**{k: v for k, v in synthetic_inputs.items() if k != "tmp_path"}, seed=42)
    out = Path(synthetic_inputs["output_dir"])

    benign_domains = set()
    for split in ("train", "validation", "test"):
        rows = list(csv.DictReader((out / f"{split}.csv").open(encoding="utf-8")))
        for r in rows:
            if r["label"] == "0":
                benign_domains.add(r["registered_domain"])

    assert "evil.com" not in benign_domains, "Phishing domain appeared in benign records"


def test_benign_records_have_varied_construction_methods(synthetic_inputs):
    build_dataset(**{k: v for k, v in synthetic_inputs.items() if k != "tmp_path"}, seed=42)
    out = Path(synthetic_inputs["output_dir"])

    methods = set()
    for split in ("train", "validation", "test"):
        rows = list(csv.DictReader((out / f"{split}.csv").open(encoding="utf-8")))
        methods.update(r["construction_method"] for r in rows if r["label"] == "0")

    assert "root" in methods
    assert "common_path" in methods


def test_manifest_stats_match_actual_splits(synthetic_inputs):
    build_dataset(**{k: v for k, v in synthetic_inputs.items() if k != "tmp_path"}, seed=42)
    manifest_path = Path(synthetic_inputs["manifest_dir"]) / "dataset_v1.json"
    assert manifest_path.exists(), "Manifest file was not created"

    with manifest_path.open(encoding="utf-8") as f:
        manifest = json.load(f)

    assert manifest["version"] == "v1"
    assert "candidate benign" in manifest["label_policy"]["benign"].lower()

    out = Path(synthetic_inputs["output_dir"])
    for split in ("train", "validation", "test"):
        rows = list(csv.DictReader((out / f"{split}.csv").open(encoding="utf-8")))
        assert len(rows) > 0, f"Split {split} is empty"
        assert manifest["splits"][split]["total"] == len(rows)


def test_pipeline_deterministic(synthetic_inputs):
    """Running twice with same seed → identical output files."""
    kwargs = {k: v for k, v in synthetic_inputs.items() if k != "tmp_path"}
    build_dataset(**kwargs, seed=42)
    out = Path(synthetic_inputs["output_dir"])

    first_run = {}
    for split in ("train", "validation", "test"):
        first_run[split] = (out / f"{split}.csv").read_text(encoding="utf-8")

    # Overwrite with second run
    build_dataset(**kwargs, seed=42)
    for split in ("train", "validation", "test"):
        content = (out / f"{split}.csv").read_text(encoding="utf-8")
        assert content == first_run[split], f"Non-deterministic output in {split}"
