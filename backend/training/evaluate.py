"""
Final evaluation of the SELECTED model on the held-out test set.

This script runs ONCE on the chosen model only (phishguard_v1.joblib).
Test set metrics are computed and recorded separately from validation metrics.
Never used for model comparison or hyperparameter selection.
"""
import argparse
import json
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
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)

matplotlib.use("Agg")
import matplotlib.pyplot as plt

META_COLS = ("url", "label", "source", "construction_method", "registered_domain")


def evaluate_final(
    model_path_str: str = "models/phishguard_v1.joblib",
    test_path_str: str = "data/processed/test_features.csv",
    reports_dir_str: str = "reports",
) -> dict:
    reports_dir = Path(reports_dir_str)
    reports_dir.mkdir(parents=True, exist_ok=True)

    model_path = Path(model_path_str)
    test_path = Path(test_path_str)

    print(f"[evaluate] Loading selected model: {model_path} ...")
    bundle = joblib.load(model_path)
    model = bundle["model"]
    scaler = bundle["scaler"]
    feature_names = bundle["feature_names"]

    print(f"[evaluate] Loading untouched test set: {test_path} ...")
    test_df = pd.read_csv(test_path)
    X_test = test_df[feature_names].values
    y_test = test_df["label"].values
    print(
        f"[evaluate]   {len(X_test):,} test samples "
        f"({sum(y_test == 1):,} phishing, {sum(y_test == 0):,} benign)"
    )

    X_test_scaled = scaler.transform(X_test)
    probas = model.predict_proba(X_test_scaled)[:, 1]
    preds = (probas >= 0.5).astype(int)

    cm = confusion_matrix(y_test, preds)
    tn, fp, fn, tp = cm.ravel()

    metrics = {
        "evaluated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "model_path": str(model_path),
        "model_name": bundle.get("model_name", "phishguard_v1"),
        "test_dataset": str(test_path),
        "sample_count": len(y_test),
        "phishing_count": int(sum(y_test == 1)),
        "benign_count": int(sum(y_test == 0)),
        "accuracy": float(np.mean(preds == y_test)),
        "precision_phishing": float(precision_score(y_test, preds, pos_label=1, zero_division=0)),
        "recall_phishing": float(recall_score(y_test, preds, pos_label=1, zero_division=0)),
        "f1_phishing": float(f1_score(y_test, preds, pos_label=1, zero_division=0)),
        "precision_benign": float(precision_score(y_test, preds, pos_label=0, zero_division=0)),
        "recall_benign": float(recall_score(y_test, preds, pos_label=0, zero_division=0)),
        "f1_macro": float(f1_score(y_test, preds, average="macro")),
        "roc_auc": float(roc_auc_score(y_test, probas)),
        "brier_score": float(brier_score_loss(y_test, probas)),
        "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0,
        "false_negative_rate": float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0,
        "confusion_matrix": {
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_positives": int(tp),
        },
    }

    # Save metrics JSON
    metrics_file = reports_dir / "final_test_metrics.json"
    with metrics_file.open("w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(f"[evaluate] Saved test metrics: {metrics_file}")

    # Plot 1: Test ROC Curve
    plt.figure(figsize=(7, 6))
    fpr, tpr, _ = roc_curve(y_test, probas)
    plt.plot(fpr, tpr, color="crimson", lw=2, label=f"ROC (AUC = {metrics['roc_auc']:.4f})")
    plt.plot([0, 1], [0, 1], "k--", label="Chance")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate (Recall)")
    plt.title("Final Test Set ROC Curve")
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.savefig(reports_dir / "roc_curve_test.png", dpi=150)
    plt.close()

    # Plot 2: Test Confusion Matrix
    plt.figure(figsize=(6, 5))
    cm_matrix = np.array([[tn, fp], [fn, tp]])
    plt.imshow(cm_matrix, cmap="Blues")
    plt.colorbar()
    plt.title("Final Test Set Confusion Matrix")
    plt.xticks([0, 1], ["Benign", "Phishing"])
    plt.yticks([0, 1], ["Benign", "Phishing"])
    for r in range(2):
        for c in range(2):
            plt.text(
                c, r, f"{cm_matrix[r, c]:,}", ha="center", va="center", color="gray", fontsize=12
            )
    plt.ylabel("Actual Label")
    plt.xlabel("Predicted Label")
    plt.tight_layout()
    plt.savefig(reports_dir / "confusion_matrix_test.png", dpi=150)
    plt.close()

    # Plot 3: Test Calibration Curve
    plt.figure(figsize=(7, 6))
    prob_true, prob_pred = calibration_curve(y_test, probas, n_bins=10)
    label_text = f"Calibrated (Brier={metrics['brier_score']:.4f})"
    plt.plot(prob_pred, prob_true, marker="o", color="navy", label=label_text)
    plt.plot([0, 1], [0, 1], "k--", label="Perfect Calibration")
    plt.xlabel("Mean Predicted Probability")
    plt.ylabel("Fraction of Positives")
    plt.title("Final Test Set Calibration Curve")
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.savefig(reports_dir / "calibration_curve_test.png", dpi=150)
    plt.close()

    print("\n[evaluate] Final Test Evaluation Summary:")
    print(f"  Phishing Recall:    {metrics['recall_phishing']:.4%}")
    print(f"  Phishing Precision: {metrics['precision_phishing']:.4%}")
    print(f"  ROC-AUC:            {metrics['roc_auc']:.4f}")
    print(f"  Brier Score:        {metrics['brier_score']:.4f}")
    print(f"  False Positive Rate: {metrics['false_positive_rate']:.4%}")
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate selected model on test set")
    parser.add_argument("--model-path", default="models/phishguard_v1.joblib")
    parser.add_argument("--test-path", default="data/processed/test_features.csv")
    parser.add_argument("--reports-dir", default="reports")
    args = parser.parse_args()

    evaluate_final(
        model_path_str=args.model_path,
        test_path_str=args.test_path,
        reports_dir_str=args.reports_dir,
    )


if __name__ == "__main__":
    main()
