"""
Model training pipeline for PhishGuard.

Trains and calibrates models on training features and held-out calibration data.
Test set is NEVER touched here.

Models trained:
1. Logistic Regression (lr_v1)
2. Random Forest (rf_v1)
"""
import argparse
from pathlib import Path
from typing import Any

import joblib
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

META_COLS = ("url", "label", "source", "construction_method", "registered_domain")


def train_model(
    model_class: Any,
    model_params: dict[str, Any],
    model_name: str,
    train_path: str = "data/processed/train_features.csv",
    val_path: str = "data/processed/validation_features.csv",
    output_dir: str = "models",
    seed: int = 42,
) -> tuple[Path, list[str]]:
    """
    Train, calibrate, and save a model.

    Procedure:
    1. Fit StandardScaler on X_train ONLY.
    2. Split validation into 50% calibration and 50% eval (stratified).
    3. Train base model on X_train_scaled.
    4. Calibrate probabilities using Sigmoid / Platt scaling on X_cal_scaled.
    5. Save bundle (calibrated model, scaler, feature_names) to output_dir.
    """
    print(f"\n[train] Training {model_name} ...")
    train_df = pd.read_csv(train_path)
    val_df = pd.read_csv(val_path)

    feature_cols = [c for c in train_df.columns if c not in META_COLS]
    print(f"[train]   {len(feature_cols)} features detected")

    X_train = train_df[feature_cols].values
    y_train = train_df["label"].values

    # Validation split: 50% for calibration, 50% for model comparison evaluation
    X_val_full = val_df[feature_cols].values
    y_val_full = val_df["label"].values

    X_cal, _X_eval, y_cal, _y_eval = train_test_split(
        X_val_full,
        y_val_full,
        test_size=0.5,
        random_state=seed,
        stratify=y_val_full,
    )

    # Scale features (FIT ON TRAINING SET ONLY)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_cal_scaled = scaler.transform(X_cal)

    print(f"[train]   Fitting {model_class.__name__} on {len(X_train_scaled):,} samples ...")
    base_clf = model_class(**model_params)
    base_clf.fit(X_train_scaled, y_train)

    print(f"[train]   Calibrating probabilities on {len(X_cal_scaled):,} calibration samples ...")
    try:
        from sklearn.frozen import FrozenEstimator

        calibrated = CalibratedClassifierCV(FrozenEstimator(base_clf), method="sigmoid")
    except ImportError:
        calibrated = CalibratedClassifierCV(base_clf, cv="prefit", method="sigmoid")

    calibrated.fit(X_cal_scaled, y_cal)

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    output_path = out_dir / f"{model_name}.joblib"

    joblib.dump(
        {
            "model": calibrated,
            "scaler": scaler,
            "feature_names": feature_cols,
            "model_name": model_name,
        },
        output_path,
    )
    print(f"[train]   Successfully saved: {output_path}")

    return output_path, feature_cols


def main() -> None:
    parser = argparse.ArgumentParser(description="Train PhishGuard ML models")
    parser.add_argument("--train-path", default="data/processed/train_features.csv")
    parser.add_argument("--val-path", default="data/processed/validation_features.csv")
    parser.add_argument("--output-dir", default="models")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    # Ticket 2.1: Logistic Regression
    train_model(
        model_class=LogisticRegression,
        model_params={"max_iter": 1000, "random_state": args.seed},
        model_name="lr_v1",
        train_path=args.train_path,
        val_path=args.val_path,
        output_dir=args.output_dir,
        seed=args.seed,
    )

    # Ticket 2.2: Random Forest
    train_model(
        model_class=RandomForestClassifier,
        model_params={
            "n_estimators": 100,
            "max_depth": 20,
            "random_state": args.seed,
            "n_jobs": -1,
        },
        model_name="rf_v1",
        train_path=args.train_path,
        val_path=args.val_path,
        output_dir=args.output_dir,
        seed=args.seed,
    )


if __name__ == "__main__":
    main()
