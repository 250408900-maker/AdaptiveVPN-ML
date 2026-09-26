import sys
from pathlib import Path

import pandas as pd


# =========================================================
# PROJECT ROOT
# =========================================================

# build_dataset.py lives here:
# AdaptiveVPN-ML/training/build_dataset.py
PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# =========================================================
# SHARED FEATURE CONTRACT
# =========================================================

from core.features import (
    FEATURE_COLUMNS,
    METADATA_COLUMNS,
    TARGET_COLUMN,
)


# =========================================================
# PATHS
# =========================================================

PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
OUTPUT_FILE = PROCESSED_DIR / "features_v2.csv"

# Known capture we don't want in the research dataset
EXCLUDED_FILES = {
    "route_failure_001_features.csv",
}


# =========================================================
# FIND FEATURE CSV FILES
# =========================================================

feature_files = sorted(
    PROCESSED_DIR.glob("*_features.csv")
)

feature_files = [
    file
    for file in feature_files
    if file.name not in EXCLUDED_FILES
]

if not feature_files:
    raise FileNotFoundError(
        "No *_features.csv files found in data/processed"
    )


print("=== ADAPTIVEVPN-ML DATASET BUILDER ===\n")

print("Feature contract:")
print(f"  ML features: {len(FEATURE_COLUMNS)}")

for feature in FEATURE_COLUMNS:
    print(f"  - {feature}")


print("\nFeature files found:")

for file in feature_files:
    print(f"  - {file.name}")


# =========================================================
# EXPECTED CAPTURE SCHEMA
# =========================================================

EXPECTED_CAPTURE_COLUMNS = (
    METADATA_COLUMNS
    + FEATURE_COLUMNS
    + [TARGET_COLUMN]
)


# =========================================================
# LOAD AND VALIDATE EACH CAPTURE
# =========================================================

frames = []

for file in feature_files:

    print(f"\nChecking: {file.name}")

    df = pd.read_csv(file)

    # -----------------------------------------------------
    # Check required columns
    # -----------------------------------------------------

    missing = [
        column
        for column in EXPECTED_CAPTURE_COLUMNS
        if column not in df.columns
    ]

    if missing:
        raise ValueError(
            f"{file.name} is missing columns: {missing}"
        )

    # -----------------------------------------------------
    # Verify ML feature order
    # -----------------------------------------------------

    actual_feature_order = [
        column
        for column in df.columns
        if column in FEATURE_COLUMNS
    ]

    if actual_feature_order != FEATURE_COLUMNS:
        raise ValueError(
            f"{file.name} has incorrect feature order.\n"
            f"Expected: {FEATURE_COLUMNS}\n"
            f"Actual:   {actual_feature_order}"
        )

    # -----------------------------------------------------
    # Check labels
    # -----------------------------------------------------

    if df[TARGET_COLUMN].isna().any():
        raise ValueError(
            f"{file.name} contains missing labels."
        )

    labels = df[TARGET_COLUMN].unique()

    if len(labels) != 1:
        raise ValueError(
            f"{file.name} contains multiple labels: "
            f"{labels.tolist()}"
        )

    # -----------------------------------------------------
    # Force canonical column order
    # -----------------------------------------------------

    df = df[EXPECTED_CAPTURE_COLUMNS].copy()

    # Example:
    # high_latency_005_features.csv
    #
    # becomes capture_id:
    # high_latency_005

    capture_id = file.name.replace(
        "_features.csv",
        "",
    )

    df.insert(
        0,
        "capture_id",
        capture_id,
    )

    frames.append(df)

    print(
        f"  OK - {len(df)} windows - "
        f"{labels[0]}"
    )


# =========================================================
# COMBINE DATASET
# =========================================================

dataset = pd.concat(
    frames,
    ignore_index=True,
)


# =========================================================
# FINAL DATASET VALIDATION
# =========================================================

required_columns = (
    ["capture_id"]
    + METADATA_COLUMNS
    + FEATURE_COLUMNS
    + [TARGET_COLUMN]
)

missing = [
    column
    for column in required_columns
    if column not in dataset.columns
]

if missing:
    raise ValueError(
        f"Dataset missing required columns: {missing}"
    )


# ---------------------------------------------------------
# Missing feature values
# ---------------------------------------------------------

missing_feature_values = (
    dataset[FEATURE_COLUMNS]
    .isna()
    .sum()
)

bad_missing = missing_feature_values[
    missing_feature_values > 0
]

if not bad_missing.empty:
    raise ValueError(
        "Missing ML feature values detected:\n"
        f"{bad_missing}"
    )


# ---------------------------------------------------------
# Numeric feature check
# ---------------------------------------------------------

non_numeric = [
    column
    for column in FEATURE_COLUMNS
    if not pd.api.types.is_numeric_dtype(
        dataset[column]
    )
]

if non_numeric:
    raise ValueError(
        f"Non-numeric ML features detected: {non_numeric}"
    )


# ---------------------------------------------------------
# Capture ID check
# ---------------------------------------------------------

if dataset["capture_id"].isna().any():
    raise ValueError(
        "Dataset contains missing capture IDs."
    )


# =========================================================
# SAVE
# =========================================================

dataset.to_csv(
    OUTPUT_FILE,
    index=False,
)


# =========================================================
# DATASET REPORT
# =========================================================

print("\n========================================")
print("DATASET CREATED")
print("========================================")

print(f"\nTotal windows: {len(dataset)}")

print(
    f"Independent captures: "
    f"{dataset['capture_id'].nunique()}"
)

print(
    f"ML features: "
    f"{len(FEATURE_COLUMNS)}"
)


print("\n=== WINDOWS PER CLASS ===")

print(
    dataset[TARGET_COLUMN]
    .value_counts()
    .sort_index()
)


print("\n=== CAPTURES PER CLASS ===")

capture_counts = (
    dataset[
        ["capture_id", TARGET_COLUMN]
    ]
    .drop_duplicates()
    [TARGET_COLUMN]
    .value_counts()
    .sort_index()
)

print(capture_counts)


print("\n=== CAPTURE SUMMARY ===")

summary = (
    dataset
    .groupby(
        ["capture_id", TARGET_COLUMN]
    )
    .size()
    .reset_index(
        name="windows"
    )
)

print(
    summary.to_string(
        index=False
    )
)


# =========================================================
# FINAL CONTRACT CHECK
# =========================================================

actual_features = [
    column
    for column in dataset.columns
    if column in FEATURE_COLUMNS
]

contract_match = (
    actual_features == FEATURE_COLUMNS
)

print("\n=== FEATURE CONTRACT CHECK ===")

print(
    f"Expected features: "
    f"{len(FEATURE_COLUMNS)}"
)

print(
    f"Dataset features:  "
    f"{len(actual_features)}"
)

print(
    f"Feature order match: "
    f"{contract_match}"
)

if not contract_match:
    raise RuntimeError(
        "Final dataset does not match feature contract."
    )


print(f"\nSaved -> {OUTPUT_FILE}")

print("\n========================================")
print("BUILD COMPLETE")
print("========================================")