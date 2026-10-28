"""
Featurize dataset splits for model training and evaluation.

Usage:
    python scripts/featurize_dataset.py [--data-dir data/processed]

Reads:
    data/processed/train.csv
    data/processed/validation.csv
    data/processed/test.csv

Extracts lexical and structural features for every URL and saves:
    data/processed/train_features.csv
    data/processed/validation_features.csv
    data/processed/test_features.csv
    data/processed/feature_names.json
"""
import argparse
import csv
import json
import sys
from pathlib import Path

# Add backend directory to path so app.features is importable
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from app.features import extract_all_features, get_feature_names


def featurize_file(
    input_csv: Path, output_csv: Path, feature_names: list[str]
) -> int:
    """Read URLs from input_csv, extract features, and write output_csv."""
    if not input_csv.exists():
        print(f"[featurize] Skipping missing file: {input_csv}")
        return 0

    with input_csv.open(encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    meta_fields = ["url", "label", "source", "construction_method", "registered_domain"]
    fieldnames = meta_fields + feature_names

    output_rows = []
    skipped = 0
    for r in rows:
        url = r.get("url", "").strip()
        if not url:
            skipped += 1
            continue
        try:
            feats, _, _ = extract_all_features(url)
            row_dict = {k: r.get(k, "") for k in meta_fields}
            for fn in feature_names:
                val = feats.get(fn, 0)
                if val is None:
                    val = 0
                row_dict[fn] = val
            output_rows.append(row_dict)
        except Exception as e:
            # If normalization fails on bad URL, skip or log
            print(f"[featurize] Warning: failed to parse {url}: {e}", file=sys.stderr)
            skipped += 1

    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with output_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(output_rows)

    print(
        f"[featurize] Processed {len(output_rows):,} rows "
        f"({skipped} skipped) -> {output_csv}"
    )
    return len(output_rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract features from dataset splits")
    parser.add_argument("--data-dir", default="data/processed", help="Path to processed CSVs")
    args = parser.parse_args()

    data_dir = Path(args.data_dir)
    feature_names = get_feature_names()

    # Save feature names list
    names_path = data_dir / "feature_names.json"
    data_dir.mkdir(parents=True, exist_ok=True)
    with names_path.open("w", encoding="utf-8") as f:
        json.dump(feature_names, f, indent=2)
    print(f"[featurize] Saved {len(feature_names)} feature names to {names_path}")

    splits = ["train", "validation", "test"]
    for split in splits:
        in_path = data_dir / f"{split}.csv"
        out_path = data_dir / f"{split}_features.csv"
        featurize_file(in_path, out_path, feature_names)


if __name__ == "__main__":
    main()
