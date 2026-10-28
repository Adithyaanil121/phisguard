"""
Model comparison using validation-eval data only.

The test set is NEVER loaded here — model selection must not leak test information.
Produces comparison metrics and visualization plots saved to reports/.
Selects the winning model based on:
1. Phishing recall (highest priority — missing phishing is dangerous)
2. Precision (false alarms erode user trust)
3. Calibration quality (lowest Brier score)
4. Inference latency
"""
import argparse
import json
import shutil
import time
from datetime import UTC, datetime
from pathlib import Path

import joblib
import matplotlib
import numpy as np
import pandas as pd
from sklearn.calibration import calibration_curve
from sklearn.metrics import (
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import train_test_split

matplotlib.use("Agg")
import matplotlib.pyplot as plt

META_COLS = ("url", "label", "source", "construction_method", "registered_domain")


def load_val_eval_data(
    val_path: str = "data/processed/validation_features.csv",
    seed: int = 42,
) -> tuple[np.ndarray, np.ndarray, list[str], pd.DataFrame]:
    """Load validation features and return the 50% validation-eval split."""
    val_df = pd.read_csv(val_path)
    feature_cols = [c for c in val_df.columns if c not in META_COLS]

    X_full = val_df[feature_cols].values
    y_full = val_df["label"].values

    _X_cal, X_eval, _y_cal, y_eval = train_test_split(
        X_full,
        y_full,
        test_size=0.5,
        random_state=seed,
        stratify=y_full,
    )
    return X_eval, y_eval, feature_cols, val_df


def generate_exploratory_plots(
    val_df: pd.DataFrame, feature_cols: list[str], reports_dir: Path
) -> None:
    """Generate feature distributions and correlation heatmap."""
    # 1. Feature correlation heatmap
    plt.figure(figsize=(14, 12))
    corr = val_df[feature_cols].corr()
    plt.imshow(corr, cmap="coolwarm", vmin=-1, vmax=1)
    plt.colorbar()
    plt.xticks(range(len(feature_cols)), feature_cols, rotation=90, fontsize=8)
    plt.yticks(range(len(feature_cols)), feature_cols, fontsize=8)
    plt.title("Feature Correlation Heatmap", fontsize=14)
    plt.tight_layout()
    plt.savefig(reports_dir / "feature_correlation.png", dpi=150)
    plt.close()

    # 2. Feature distributions (top 10 by variance)
    top_feats = (
        val_df[feature_cols]
        .var()
        .sort_values(ascending=False)
        .head(10)
        .index.tolist()
    )
    fig, axes = plt.subplots(2, 5, figsize=(18, 7))
    axes = axes.flatten()
    for i, col in enumerate(top_feats):
        ax = axes[i]
        benign_vals = val_df[val_df["label"] == 0][col].clip(
            upper=val_df[col].quantile(0.99)
        )
        phish_vals = val_df[val_df["label"] == 1][col].clip(
            upper=val_df[col].quantile(0.99)
        )
        ax.hist(benign_vals, bins=20, alpha=0.5, label="Benign", color="blue")
        ax.hist(phish_vals, bins=20, alpha=0.5, label="Phishing", color="red")
        ax.set_title(col, fontsize=9)
        if i == 0:
            ax.legend(fontsize=8)
    plt.suptitle("Top 10 Feature Distributions by Class", fontsize=14)
    plt.tight_layout()
    plt.savefig(reports_dir / "feature_distributions.png", dpi=150)
    plt.close()


def evaluate_model_on_val_eval(
    model_bundle: dict, X_eval: np.ndarray, y_eval: np.ndarray
) -> dict:
    """Compute all evaluation metrics and inference latency on validation-eval split."""
    model = model_bundle["model"]
    scaler = model_bundle["scaler"]

    # Scale using the model's fitted scaler
    X_scaled = scaler.transform(X_eval)

    # Latency test (100 individual calls)
    sample_indices = np.random.RandomState(42).choice(
        len(X_scaled), size=min(100, len(X_scaled)), replace=False
    )
    latencies = []
    for idx in sample_indices:
        t0 = time.perf_counter()
        _ = model.predict_proba(X_scaled[idx : idx + 1])
        latencies.append((time.perf_counter() - t0) * 1000)
    avg_latency_ms = float(np.mean(latencies))

    # Full predictions
    probas = model.predict_proba(X_scaled)[:, 1]
    preds = (probas >= 0.5).astype(int)

    cm = confusion_matrix(y_eval, preds)
    tn, fp, fn, tp = cm.ravel()

    return {
        "accuracy": float(np.mean(preds == y_eval)),
        "precision_phishing": float(precision_score(y_eval, preds, pos_label=1, zero_division=0)),
        "recall_phishing": float(recall_score(y_eval, preds, pos_label=1, zero_division=0)),
        "f1_phishing": float(f1_score(y_eval, preds, pos_label=1, zero_division=0)),
        "precision_benign": float(precision_score(y_eval, preds, pos_label=0, zero_division=0)),
        "recall_benign": float(recall_score(y_eval, preds, pos_label=0, zero_division=0)),
        "f1_macro": float(f1_score(y_eval, preds, average="macro")),
        "roc_auc": float(roc_auc_score(y_eval, probas)),
        "brier_score": float(brier_score_loss(y_eval, probas)),
        "fpr": float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0,
        "inference_latency_ms": round(avg_latency_ms, 3),
        "confusion_matrix": {
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp),
        },
        "_probas": probas,
        "_preds": preds,
    }


def compare_and_select(
    models_dir: str = "models",
    val_path: str = "data/processed/validation_features.csv",
    reports_dir_str: str = "reports",
    seed: int = 42,
) -> None:
    reports_dir = Path(reports_dir_str)
    reports_dir.mkdir(parents=True, exist_ok=True)
    m_dir = Path(models_dir)

    print("[compare] Loading validation-eval split ...")
    X_eval, y_eval, feature_cols, val_df = load_val_eval_data(val_path, seed=seed)
    print(
        f"[compare]   {len(X_eval):,} validation-eval samples "
        f"({sum(y_eval == 1):,} phishing, {sum(y_eval == 0):,} benign)"
    )

    print("[compare] Generating exploratory feature plots ...")
    generate_exploratory_plots(val_df, feature_cols, reports_dir)

    # Candidate models
    candidates = ["lr_v1", "rf_v1"]
    results = {}
    model_bundles = {}

    for name in candidates:
        model_file = m_dir / f"{name}.joblib"
        if not model_file.exists():
            print(f"[compare] Warning: {model_file} not found, skipping")
            continue
        print(f"[compare] Evaluating {name} on validation-eval ...")
        bundle = joblib.load(model_file)
        model_bundles[name] = bundle
        metrics = evaluate_model_on_val_eval(bundle, X_eval, y_eval)
        results[name] = metrics

    # Plot ROC curves overlaid
    plt.figure(figsize=(8, 6))
    for name, res in results.items():
        fpr, tpr, _ = roc_curve(y_eval, res["_probas"])
        plt.plot(fpr, tpr, label=f"{name} (AUC = {res['roc_auc']:.4f})")
    plt.plot([0, 1], [0, 1], "k--", label="Chance")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate (Recall)")
    plt.title("Validation ROC Curves")
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.savefig(reports_dir / "roc_curve_validation.png", dpi=150)
    plt.close()

    # Plot Precision-Recall curves
    plt.figure(figsize=(8, 6))
    for name, res in results.items():
        prec, rec, _ = precision_recall_curve(y_eval, res["_probas"])
        plt.plot(rec, prec, label=f"{name} (F1={res['f1_phishing']:.4f})")
    plt.xlabel("Recall (Phishing)")
    plt.ylabel("Precision (Phishing)")
    plt.title("Validation Precision-Recall Curves")
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.savefig(reports_dir / "precision_recall_validation.png", dpi=150)
    plt.close()

    # Plot Confusion Matrices
    fig, axes = plt.subplots(1, len(results), figsize=(5 * len(results), 4))
    if len(results) == 1:
        axes = [axes]
    for ax, (name, res) in zip(axes, results.items(), strict=False):
        cm = np.array([
            [res["confusion_matrix"]["tn"], res["confusion_matrix"]["fp"]],
            [res["confusion_matrix"]["fn"], res["confusion_matrix"]["tp"]],
        ])
        ax.imshow(cm, cmap="Blues")
        ax.set_title(f"Confusion Matrix: {name}")
        ax.set_xticks([0, 1])
        ax.set_yticks([0, 1])
        ax.set_xticklabels(["Benign", "Phishing"])
        ax.set_yticklabels(["Benign", "Phishing"])
        for r in range(2):
            for c in range(2):
                ax.text(c, r, str(cm[r, c]), ha="center", va="center", color="gray")
    plt.tight_layout()
    plt.savefig(reports_dir / "confusion_matrix_validation.png", dpi=150)
    plt.close()

    # Plot Calibration Curves
    plt.figure(figsize=(8, 6))
    for name, res in results.items():
        prob_true, prob_pred = calibration_curve(y_eval, res["_probas"], n_bins=10)
        plt.plot(prob_pred, prob_true, marker="o", label=f"{name} (Brier={res['brier_score']:.4f})")
    plt.plot([0, 1], [0, 1], "k--", label="Perfect Calibration")
    plt.xlabel("Mean Predicted Probability")
    plt.ylabel("Fraction of Positives")
    plt.title("Validation Calibration Curves")
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.savefig(reports_dir / "calibration_curve_validation.png", dpi=150)
    plt.close()

    # Plot Feature Importance for RF (Ticket 2.3 requirement)
    if "rf_v1" in model_bundles:
        rf_model = model_bundles["rf_v1"]["model"]
        base_rf = getattr(rf_model, "estimator", rf_model)
        if hasattr(base_rf, "estimator"):  # FrozenEstimator
            base_rf = base_rf.estimator
        if hasattr(base_rf, "feature_importances_"):
            importances = base_rf.feature_importances_
            sorted_idx = np.argsort(importances)[::-1][:15]
            plt.figure(figsize=(10, 6))
            plt.barh(range(15), importances[sorted_idx][::-1], align="center", color="teal")
            plt.yticks(range(15), [feature_cols[i] for i in sorted_idx][::-1])
            plt.xlabel("Feature Importance")
            plt.title("Top 15 Feature Importances (Random Forest)")
            plt.tight_layout()
            plt.savefig(reports_dir / "feature_importance.png", dpi=150)
            plt.close()

    # Model selection:
    # 1. Recall on phishing class
    # 2. Precision on phishing class
    # 3. Calibration (Brier score)
    # 4. Latency
    best_model_name = max(
        results.keys(),
        key=lambda k: (
            results[k]["recall_phishing"],
            results[k]["precision_phishing"],
            -results[k]["brier_score"],
        ),
    )
    selection_rationale = (
        f"Selected '{best_model_name}' based on validation-eval criteria: "
        f"Phishing Recall = {results[best_model_name]['recall_phishing']:.4f}, "
        f"Precision = {results[best_model_name]['precision_phishing']:.4f}, "
        f"ROC-AUC = {results[best_model_name]['roc_auc']:.4f}, "
        f"Brier Score = {results[best_model_name]['brier_score']:.4f}, "
        f"Latency = {results[best_model_name]['inference_latency_ms']} ms/URL."
    )
    print(f"\n[compare] {selection_rationale}")

    # Build clean output for JSON (omit numpy arrays)
    clean_results = {}
    for name, m in results.items():
        clean_results[name] = {k: v for k, v in m.items() if not k.startswith("_")}

    comparison_doc = {
        "compared_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "evaluation_split": "validation_eval (50% held-out validation)",
        "models": clean_results,
        "selected_model": best_model_name,
        "selection_rationale": selection_rationale,
    }

    comp_file = reports_dir / "model_comparison_validation.json"
    with comp_file.open("w", encoding="utf-8") as f:
        json.dump(comparison_doc, f, indent=2)
    print(f"[compare] Saved comparison table: {comp_file}")

    # Ticket 2.4: Copy winning model to models/phishguard_v1.joblib and write model_metadata.json
    best_src = m_dir / f"{best_model_name}.joblib"
    best_dst = m_dir / "phishguard_v1.joblib"
    shutil.copyfile(best_src, best_dst)
    print(f"[compare] Copied {best_src} -> {best_dst}")

    best_metrics = clean_results[best_model_name]
    metadata = {
        "model_name": best_model_name,
        "version": "v1.0.0",
        "trained_on": datetime.now(UTC).strftime("%Y-%m-%d"),
        "dataset_version": "dataset_v1",
        "feature_count": len(feature_cols),
        "feature_names": feature_cols,
        "selection_criteria": selection_rationale,
        "validation_metrics": {
            "recall_phishing": best_metrics["recall_phishing"],
            "precision_phishing": best_metrics["precision_phishing"],
            "f1_macro": best_metrics["f1_macro"],
            "roc_auc": best_metrics["roc_auc"],
            "brier_score": best_metrics["brier_score"],
            "inference_latency_ms": best_metrics["inference_latency_ms"],
        },
        "note": "Metrics populated by compare_models.py. Final test metrics in evaluate.py output.",
    }
    meta_path = m_dir / "model_metadata.json"
    with meta_path.open("w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    print(f"[compare] Saved model metadata: {meta_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare models on validation data")
    parser.add_argument("--models-dir", default="models")
    parser.add_argument("--val-path", default="data/processed/validation_features.csv")
    parser.add_argument("--reports-dir", default="reports")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    compare_and_select(
        models_dir=args.models_dir,
        val_path=args.val_path,
        reports_dir_str=args.reports_dir,
        seed=args.seed,
    )


if __name__ == "__main__":
    main()
