from pathlib import Path
import pandas as pd


# =========================================================
# Paths
# =========================================================

PROCESSED_DIR = Path("data/processed")
OUTPUT_FILE = PROCESSED_DIR / "features_v2.csv"

# Known capture we don't want in the research dataset
EXCLUDED_FILES = {
    "route_failure_001_features.csv",
}


# =========================================================
# Find feature CSV files
# =========================================================

feature_files = sorted(PROCESSED_DIR.glob("*_features.csv"))

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

print("Feature files found:")

for file in feature_files:
    print(f"  - {file.name}")


# =========================================================
# Load each capture
# =========================================================

frames = []

for file in feature_files:

    df = pd.read_csv(file)

    # Example:
    # high_latency_002_features.csv
    # becomes:
    # high_latency_002
    #
    # Every window from this PCAP therefore shares
    # the same capture_id.

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


# =========================================================
# Combine dataset
# =========================================================

dataset = pd.concat(
    frames,
    ignore_index=True,
)


# =========================================================
# Validate
# =========================================================

required_columns = {
    "capture_id",
    "label",
}

missing = required_columns - set(dataset.columns)

if missing:
    raise ValueError(
        f"Dataset missing required columns: {missing}"
    )


# =========================================================
# Save
# =========================================================

dataset.to_csv(
    OUTPUT_FILE,
    index=False,
)


# =========================================================
# Dataset report
# =========================================================

print("\n========================================")
print("DATASET CREATED")
print("========================================")

print(f"\nTotal windows: {len(dataset)}")

print(
    f"Independent captures: "
    f"{dataset['capture_id'].nunique()}"
)


print("\n=== WINDOWS PER CLASS ===")

print(
    dataset["label"]
    .value_counts()
    .sort_index()
)


print("\n=== CAPTURES PER CLASS ===")

capture_counts = (
    dataset[
        ["capture_id", "label"]
    ]
    .drop_duplicates()
    ["label"]
    .value_counts()
    .sort_index()
)

print(capture_counts)


print("\n=== CAPTURE SUMMARY ===")

summary = (
    dataset
    .groupby(
        ["capture_id", "label"]
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


print(f"\nSaved -> {OUTPUT_FILE}")

print("\n========================================")
print("BUILD COMPLETE")
print("========================================")