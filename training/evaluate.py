from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)


# =========================================================
# PATHS
# =========================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

MODEL_PATH = PROJECT_ROOT / "models" / "rf_v1.joblib"
TEST_PATH = PROJECT_ROOT / "data" / "processed" / "test.csv"
REPORTS_DIR = PROJECT_ROOT / "reports"

REPORTS_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


# =========================================================
# LOAD MODEL
# =========================================================

print("========================================")
print("ADAPTIVEVPN-ML MODEL EVALUATION")
print("========================================")

print(f"\nModel: {MODEL_PATH}")
print(f"Test data: {TEST_PATH}")


if not MODEL_PATH.exists():
    raise FileNotFoundError(
        f"Model not found: {MODEL_PATH}"
    )

if not TEST_PATH.exists():
    raise FileNotFoundError(
        f"Test dataset not found: {TEST_PATH}"
    )


artifact = joblib.load(MODEL_PATH)


# Support both:
# 1. saved dictionary artifact
# 2. directly saved sklearn model

if isinstance(artifact, dict):

    model = artifact["model"]

    feature_columns = artifact.get(
        "features",
        artifact.get("feature_columns"),
    )

    model_labels = artifact.get(
        "labels",
        None,
    )

else:

    model = artifact
    feature_columns = None
    model_labels = None


# =========================================================
# LOAD TEST DATA
# =========================================================

test_df = pd.read_csv(TEST_PATH)

print(
    f"\nTest windows: {len(test_df)}"
)

if "capture_id" in test_df.columns:
    print(
        f"Test captures: "
        f"{test_df['capture_id'].nunique()}"
    )


if "label" not in test_df.columns:
    raise ValueError(
        "test.csv does not contain a 'label' column."
    )


# =========================================================
# DETERMINE FEATURE COLUMNS
# =========================================================

if feature_columns is None:

    # Try sklearn's stored feature names first.

    if hasattr(model, "feature_names_in_"):

        feature_columns = list(
            model.feature_names_in_
        )

    else:

        # Fallback to our shared feature contract.

        from core.features import FEATURE_COLUMNS

        feature_columns = list(
            FEATURE_COLUMNS
        )


missing_features = [
    feature
    for feature in feature_columns
    if feature not in test_df.columns
]

if missing_features:
    raise ValueError(
        "Test dataset is missing model features: "
        f"{missing_features}"
    )


print(
    f"\nFeatures used: {len(feature_columns)}"
)

for index, feature in enumerate(
    feature_columns,
    start=1,
):
    print(
        f"{index:02d}. {feature}"
    )


# =========================================================
# PREPARE X AND y
# =========================================================

X_test = test_df[
    feature_columns
].copy()

y_test = test_df[
    "label"
].astype(str)


# Safety checks

if X_test.isnull().any().any():

    bad_columns = (
        X_test.columns[
            X_test.isnull().any()
        ]
        .tolist()
    )

    raise ValueError(
        "NaN values found in test features: "
        f"{bad_columns}"
    )


# =========================================================
# PREDICT
# =========================================================

print("\n========================================")
print("RUNNING PREDICTIONS")
print("========================================")


y_pred = model.predict(
    X_test
)


# =========================================================
# METRICS
# =========================================================

accuracy = accuracy_score(
    y_test,
    y_pred,
)

macro_f1 = f1_score(
    y_test,
    y_pred,
    average="macro",
    zero_division=0,
)

weighted_f1 = f1_score(
    y_test,
    y_pred,
    average="weighted",
    zero_division=0,
)


print("\n========================================")
print("RESULTS")
print("========================================")

print(
    f"\nAccuracy:    {accuracy:.4f} "
    f"({accuracy * 100:.2f}%)"
)

print(
    f"Macro F1:    {macro_f1:.4f}"
)

print(
    f"Weighted F1: {weighted_f1:.4f}"
)


# =========================================================
# CLASS LABELS
# =========================================================

labels = sorted(
    set(y_test)
    | set(y_pred)
)


print("\n========================================")
print("CLASSIFICATION REPORT")
print("========================================\n")

report_text = classification_report(
    y_test,
    y_pred,
    labels=labels,
    zero_division=0,
)

print(
    report_text
)


# =========================================================
# CONFUSION MATRIX
# =========================================================

cm = confusion_matrix(
    y_test,
    y_pred,
    labels=labels,
)

cm_df = pd.DataFrame(
    cm,
    index=[
        f"actual_{label}"
        for label in labels
    ],
    columns=[
        f"pred_{label}"
        for label in labels
    ],
)


print("========================================")
print("CONFUSION MATRIX")
print("========================================\n")

print(
    cm_df.to_string()
)


# =========================================================
# SAVE WINDOW PREDICTIONS
# =========================================================

predictions_df = test_df.copy()

predictions_df[
    "predicted_label"
] = y_pred

predictions_df[
    "correct"
] = (
    predictions_df["label"]
    == predictions_df["predicted_label"]
)


predictions_path = (
    REPORTS_DIR
    / "rf_v1_test_predictions.csv"
)

predictions_df.to_csv(
    predictions_path,
    index=False,
)


# =========================================================
# SAVE CLASSIFICATION REPORT
# =========================================================

report_dict = classification_report(
    y_test,
    y_pred,
    labels=labels,
    output_dict=True,
    zero_division=0,
)

report_df = (
    pd.DataFrame(report_dict)
    .transpose()
)

report_path = (
    REPORTS_DIR
    / "rf_v1_classification_report.csv"
)

report_df.to_csv(
    report_path
)


# =========================================================
# SAVE CONFUSION MATRIX
# =========================================================

cm_path = (
    REPORTS_DIR
    / "rf_v1_confusion_matrix.csv"
)

cm_df.to_csv(
    cm_path
)


# =========================================================
# CAPTURE-LEVEL SUMMARY
# =========================================================

# Windows from the same capture are related.
# So besides window-level accuracy, we also inspect
# each independent capture as a whole.

if "capture_id" in predictions_df.columns:

    capture_rows = []

    for capture_id, group in predictions_df.groupby(
        "capture_id"
    ):

        actual_label = (
            group["label"]
            .iloc[0]
        )

        predicted_label = (
            group["predicted_label"]
            .mode()
            .iloc[0]
        )

        capture_rows.append(
            {
                "capture_id": capture_id,
                "actual_label": actual_label,
                "predicted_label": predicted_label,
                "windows": len(group),
                "correct": (
                    actual_label
                    == predicted_label
                ),
            }
        )

    capture_df = pd.DataFrame(
        capture_rows
    )

    capture_accuracy = (
        capture_df["correct"]
        .mean()
    )

    print("\n========================================")
    print("CAPTURE-LEVEL RESULTS")
    print("========================================\n")

    print(
        capture_df.to_string(
            index=False
        )
    )

    print(
        f"\nCapture accuracy: "
        f"{capture_accuracy:.4f} "
        f"({capture_accuracy * 100:.2f}%)"
    )

    capture_path = (
        REPORTS_DIR
        / "rf_v1_capture_predictions.csv"
    )

    capture_df.to_csv(
        capture_path,
        index=False,
    )


# =========================================================
# DONE
# =========================================================

print("\n========================================")
print("EVALUATION COMPLETE")
print("========================================")

print(
    f"\nPredictions saved -> "
    f"{predictions_path}"
)

print(
    f"Classification report -> "
    f"{report_path}"
)

print(
    f"Confusion matrix -> "
    f"{cm_path}"
)