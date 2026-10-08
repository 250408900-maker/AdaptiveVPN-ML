
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import Pipeline


DATA_DIR = Path("data/processed/v3")
MODEL_DIR = Path("models")
REPORT_DIR = Path("data/processed/v3/reports")

FEATURES = [
    "tcp_connect_mean_ms",
    "tcp_connect_std_ms",
    "tcp_failure_pct",
    "icmp_nonresponse_pct",
]

CLASSES = [
    "NORMAL",
    "HIGH_LATENCY",
    "PACKET_LOSS",
]


def make_model():
    return Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("classifier", RandomForestClassifier(
            n_estimators=200,
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=42,
        )),
    ])


def main():
    frames = []

    for path in sorted(DATA_DIR.glob("*_features.csv")):
        df = pd.read_csv(path)

        if df.empty:
            continue

        df = df[df["label"].isin(CLASSES)].copy()

        if df.empty:
            continue

        df["capture_id"] = path.stem.removesuffix("_features")
        frames.append(df)

    if not frames:
        raise SystemExit("No V3 training data found.")

    data = pd.concat(frames, ignore_index=True)

    for feature in FEATURES:
        if feature not in data.columns:
            raise SystemExit(f"Missing feature: {feature}")

        data[feature] = pd.to_numeric(
            data[feature],
            errors="coerce",
        )

    X = data[FEATURES]
    y = data["label"]
    groups = data["capture_id"]

    print("\n" + "=" * 55)
    print("ADAPTIVEVPN-ML — V3 MODEL TRAINING")
    print("=" * 55)

    print(f"Windows: {len(data)}")
    print(f"Captures: {groups.nunique()}")
    print("\nCapture counts per class:")
    print(
        data.groupby("label")["capture_id"]
        .nunique()
        .to_string()
    )

    capture_counts = (
        data.groupby("label")["capture_id"].nunique()
    )

    if any(capture_counts.get(label, 0) < 3 for label in CLASSES):
        raise SystemExit(
            "Need at least 3 independent captures per class."
        )

    splitter = StratifiedGroupKFold(
        n_splits=3,
        shuffle=True,
        random_state=42,
    )

    predictions = np.empty(len(data), dtype=object)
    predictions[:] = None

    for fold, (train_idx, test_idx) in enumerate(
        splitter.split(X, y, groups),
        start=1,
    ):
        train_groups = set(groups.iloc[train_idx])
        test_groups = set(groups.iloc[test_idx])

        assert train_groups.isdisjoint(test_groups)

        model = make_model()
        model.fit(X.iloc[train_idx], y.iloc[train_idx])

        predictions[test_idx] = model.predict(
            X.iloc[test_idx]
        )

        print(
            f"\nFold {fold}: "
            f"{len(train_groups)} train captures, "
            f"{len(test_groups)} test captures"
        )

    print("\n" + "=" * 55)
    print("CAPTURE-GROUPED CROSS-VALIDATION")
    print("=" * 55)

    print(f"Accuracy: {accuracy_score(y, predictions):.4f}")
    print(
        "Balanced accuracy: "
        f"{balanced_accuracy_score(y, predictions):.4f}"
    )
    print(
        "Macro F1: "
        f"{f1_score(y, predictions, average='macro'):.4f}"
    )

    print("\nClassification report:")
    print(
        classification_report(
            y,
            predictions,
            labels=CLASSES,
            zero_division=0,
        )
    )

    print("Confusion matrix:")
    print(
        pd.DataFrame(
            confusion_matrix(
                y,
                predictions,
                labels=CLASSES,
            ),
            index=CLASSES,
            columns=CLASSES,
        ).to_string()
    )

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    evaluation = data[
        ["capture_id", "window_start_s", "label"]
    ].copy()

    evaluation["prediction"] = predictions

    evaluation.to_csv(
        REPORT_DIR / "v3_grouped_predictions.csv",
        index=False,
    )

    # Train a final model on all available data.
    # This is for later testing, not an independent
    # estimate of real-world performance.
    final_model = make_model()
    final_model.fit(X, y)

    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    joblib.dump(
        {
            "model": final_model,
            "features": FEATURES,
            "classes": CLASSES,
        },
        MODEL_DIR / "v3_random_forest.joblib",
    )

    print("\nSaved:")
    print("models/v3_random_forest.joblib")
    print("data/processed/v3/reports/v3_grouped_predictions.csv")
    print("\nV3 TRAINING COMPLETE")


if __name__ == "__main__":
    main()
