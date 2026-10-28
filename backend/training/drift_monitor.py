"""
Feature and Dataset Drift Monitoring Engine (Ticket 8.5).

Computes Population Stability Index (PSI) between baseline training feature
distributions and recent inference or test observations.
Alerts when features drift due to evolving attacker techniques or changing web norms.
"""
import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import pandas as pd


def calculate_psi(baseline: np.ndarray, target: np.ndarray, num_buckets: int = 10) -> float:
    """
    Compute Population Stability Index (PSI) between baseline and target distributions.
    PSI < 0.1: No significant change / stable
    0.1 <= PSI < 0.25: Moderate shift
    PSI >= 0.25: Significant drift / re-training required
    """
    if len(baseline) == 0 or len(target) == 0:
        return 0.0

    # Ensure finite numeric values
    b_clean = baseline[np.isfinite(baseline)]
    t_clean = target[np.isfinite(target)]

    if len(b_clean) == 0 or len(t_clean) == 0:
        return 0.0

    # Compute quantile bucket thresholds on baseline
    percentiles = np.linspace(0, 100, num_buckets + 1)
    try:
        bins = np.percentile(b_clean, percentiles)
    except Exception:
        return 0.0

    bins = np.unique(bins)
    if len(bins) < 2:
        # Uniform feature, compare proportions directly
        p_base = len(b_clean) / (len(b_clean) + 1e-6)
        p_targ = len(t_clean) / (len(t_clean) + 1e-6)
        return float(abs(p_base - p_targ))

    # Add small epsilon to avoid division by zero
    eps = 1e-4

    b_counts, _ = np.histogram(b_clean, bins=bins)
    t_counts, _ = np.histogram(t_clean, bins=bins)

    b_pct = (b_counts + eps) / (np.sum(b_counts) + eps * len(b_counts))
    t_pct = (t_counts + eps) / (np.sum(t_counts) + eps * len(t_counts))

    psi_val = np.sum((t_pct - b_pct) * np.log(t_pct / b_pct))
    return float(max(0.0, psi_val))


def run_drift_analysis(
    baseline_path_str: str = "data/processed/train_features.csv",
    target_path_str: str = "data/processed/test_features.csv",
    output_report_str: str = "reports/drift_report.json",
) -> dict:
    baseline_path = Path(baseline_path_str)
    target_path = Path(target_path_str)

    if not baseline_path.exists() or not target_path.exists():
        raise FileNotFoundError(
            f"Feature sets missing: baseline={baseline_path}, target={target_path}"
        )

    b_df = pd.read_csv(baseline_path)
    t_df = pd.read_csv(target_path)

    # Exclude metadata columns
    exclude = {"url", "label", "source", "construction_method", "registered_domain"}
    feature_cols = [c for c in b_df.columns if c in t_df.columns and c not in exclude]

    drift_results = {}
    significant_drift_count = 0
    moderate_drift_count = 0

    for feat in feature_cols:
        b_vals = b_df[feat].values
        t_vals = t_df[feat].values
        psi = calculate_psi(b_vals, t_vals)

        status = "stable"
        if psi >= 0.25:
            status = "significant_drift"
            significant_drift_count += 1
        elif psi >= 0.10:
            status = "moderate_shift"
            moderate_drift_count += 1

        drift_results[feat] = {
            "psi": round(psi, 4),
            "status": status,
        }

    report = {
        "timestamp": datetime.now(UTC).isoformat(),
        "baseline_dataset": str(baseline_path),
        "target_dataset": str(target_path),
        "features_evaluated": len(feature_cols),
        "stable_count": len(feature_cols) - (significant_drift_count + moderate_drift_count),
        "moderate_shift_count": moderate_drift_count,
        "significant_drift_count": significant_drift_count,
        "model_re_training_recommended": significant_drift_count > 0,
        "feature_metrics": drift_results,
    }

    out_file = Path(output_report_str)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with out_file.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"[drift-monitor] Drift analysis saved to {out_file}")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate feature and dataset drift")
    parser.add_argument("--baseline", default="data/processed/train_features.csv")
    parser.add_argument("--target", default="data/processed/test_features.csv")
    parser.add_argument("--output", default="reports/drift_report.json")
    args = parser.parse_args()

    run_drift_analysis(args.baseline, args.target, args.output)
