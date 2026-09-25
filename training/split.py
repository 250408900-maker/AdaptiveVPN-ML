from pathlib import Path
import pandas as pd
import numpy as np

# ============================================================
# Paths
# ============================================================

DATASET_PATH = Path("data/processed/features_v2.csv")
TRAIN_PATH = Path("data/processed/train.csv")
TEST_PATH = Path("data/processed/test.csv")

RANDOM_SEED = 42
TEST_RATIO = 0.20


# ============================================================
# Load dataset
# ============================================================

print("=== ADAPTIVEVPN-ML GROUP SPLIT ===\n")

df = pd.read_csv(DATASET_PATH)

required_columns = {"capture_id", "label"}

missing = required_columns - set(df.columns)

if missing:
    raise ValueError(
        f"Dataset missing required columns: {missing}"
    )

print(f"Total windows: {len(df)}")
print(f"Total captures: {df['capture_id'].nunique()}")


# ============================================================
# Get capture-level table
# ============================================================

captures = (
    df[["capture_id", "label"]]
    .drop_duplicates()
    .reset_index(drop=True)
)

print("\n=== CAPTURES PER CLASS ===")
print(captures["label"].value_counts().sort_index())


# ============================================================
# Class-aware capture split
#
# IMPORTANT:
# We split CAPTURES, not windows.
# This prevents windows from the same capture appearing
# in both train and test.
# ============================================================

rng = np.random.default_rng(RANDOM_SEED)

train_capture_ids = []
test_capture_ids = []

for label, group in captures.groupby("label"):

    capture_ids = group["capture_id"].tolist()

    rng.shuffle(capture_ids)

    n_captures = len(capture_ids)

    if n_captures < 2:
        raise ValueError(
            f"Class {label} has only {n_captures} capture(s). "
            "Need at least 2 independent captures to create "
            "train/test sets safely."
        )

    # At least ONE capture from every class must be in test.
    n_test = max(
        1,
        int(round(n_captures * TEST_RATIO))
    )

    # Never put every capture into test.
    n_test = min(
        n_test,
        n_captures - 1
    )

    test_ids = capture_ids[:n_test]
    train_ids = capture_ids[n_test:]

    test_capture_ids.extend(test_ids)
    train_capture_ids.extend(train_ids)


# ============================================================
# Build train/test datasets
# ============================================================

train_df = df[
    df["capture_id"].isin(train_capture_ids)
].copy()

test_df = df[
    df["capture_id"].isin(test_capture_ids)
].copy()


# ============================================================
# Display summary
# ============================================================

def print_summary(name, dataset):

    print(f"\n=== {name} ===")

    print(f"Windows: {len(dataset)}")
    print(
        f"Captures: "
        f"{dataset['capture_id'].nunique()}"
    )

    print("\nCaptures:")

    for capture in sorted(
        dataset["capture_id"].unique()
    ):
        print(f"  {capture}")

    print("\nClass distribution:")

    print(
        dataset["label"]
        .value_counts()
        .sort_index()
    )


print_summary(
    "TRAIN",
    train_df
)

print_summary(
    "TEST",
    test_df
)


# ============================================================
# Verify every class exists in BOTH sets
# ============================================================

all_labels = set(df["label"].unique())

train_labels = set(
    train_df["label"].unique()
)

test_labels = set(
    test_df["label"].unique()
)

missing_train = (
    all_labels - train_labels
)

missing_test = (
    all_labels - test_labels
)

print("\n=== CLASS COVERAGE CHECK ===")

if missing_train:
    raise RuntimeError(
        f"Classes missing from TRAIN: "
        f"{missing_train}"
    )

if missing_test:
    raise RuntimeError(
        f"Classes missing from TEST: "
        f"{missing_test}"
    )

print(
    "PASS: every class appears "
    "in both train and test."
)


# ============================================================
# Leakage check
# ============================================================

train_captures = set(
    train_df["capture_id"].unique()
)

test_captures = set(
    test_df["capture_id"].unique()
)

overlap = (
    train_captures
    & test_captures
)

print("\n=== LEAKAGE CHECK ===")

if overlap:
    raise RuntimeError(
        f"DATA LEAKAGE DETECTED: {overlap}"
    )

print(
    "PASS: no capture appears "
    "in both train and test."
)


# ============================================================
# Save
# ============================================================

TRAIN_PATH.parent.mkdir(
    parents=True,
    exist_ok=True
)

train_df.to_csv(
    TRAIN_PATH,
    index=False
)

test_df.to_csv(
    TEST_PATH,
    index=False
)

print(
    f"\nSaved train -> {TRAIN_PATH}"
)

print(
    f"Saved test  -> {TEST_PATH}"
)

print("\n========================================")
print("GROUP SPLIT COMPLETE")
print("========================================")