
from pathlib import Path

import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)

# ==========================================
# PATHS
# ==========================================

ROOT = Path(__file__).resolve().parents[2]
DATASET = ROOT / "data" / "processed" / "dataset_v2_clean.csv"
MODEL_PATH = ROOT / "models" / "v2_random_forest.joblib"

print("\n=== ADAPTIVEVPN-ML V2 TRAINING ===")

# ==========================================
# LOAD DATASET
# ==========================================

df = pd.read_csv(DATASET)

required = {"label", "capture_file"}
if not required.issubset(df.columns):
    raise ValueError("Dataset needs label and capture_file columns")

print("\nDataset shape:", df.shape)
print("\nClass distribution:")
print(df["label"].value_counts().sort_index())

# ==========================================
# CAPTURE-AWARE TRAIN / TEST SPLIT
# ==========================================

# Reserve the last capture of every class for testing.
# All other captures are used for training.

test_captures = []

for label in sorted(df["label"].unique()):
    captures = sorted(
        df.loc[df["label"] == label, "capture_file"].unique()
    )

    if len(captures) < 2:
        raise ValueError(
            f"Need at least 2 captures for {label}"
        )

    test_captures.append(captures[-1])

test_mask = df["capture_file"].isin(test_captures)

train_df = df.loc[~test_mask].copy()
test_df = df.loc[test_mask].copy()

assert set(train_df["capture_file"]).isdisjoint(
    set(test_df["capture_file"])
)

print("\n=== CAPTURE-AWARE SPLIT ===")
print("Training captures:", train_df["capture_file"].nunique())
print("Testing captures:", test_df["capture_file"].nunique())

print("Training samples:", len(train_df))
print("Testing samples:", len(test_df))

print("\nTraining class distribution:")
print(train_df["label"].value_counts().sort_index())

print("\nTesting class distribution:")
print(test_df["label"].value_counts().sort_index())

print("\nHeld-out test captures:")
for capture in test_captures:
    print(" -", capture)

# ==========================================
# PREPARE FEATURES
# ==========================================

# Never use labels, capture identifiers, or
# window positions as predictive features.

excluded = [
    "label",
    "capture_file",
    "window_start_s",
    "window_end_s",
]

features = [
    column for column in df.columns
    if column not in excluded
]

X_train = train_df[features].apply(
    pd.to_numeric, errors="raise"
)

X_test = test_df[features].apply(
    pd.to_numeric, errors="raise"
)

if X_train.isna().any().any() or X_test.isna().any().any():
    raise ValueError("Missing feature values detected")

y_train = train_df["label"]
y_test = test_df["label"]

print("\n=== FEATURES ===")
for feature in features:
    print(" -", feature)

# ==========================================
# TRAIN RANDOM FOREST
# ==========================================

print("\n=== TRAINING ===")

model = RandomForestClassifier(
    n_estimators=300,
    random_state=42,
    class_weight="balanced",
    n_jobs=-1,
)

model.fit(X_train, y_train)

print("Training complete!")

# ==========================================
# EVALUATE MODEL
# ==========================================

predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)
balanced_accuracy = balanced_accuracy_score(
    y_test, predictions
)
macro_f1 = f1_score(
    y_test, predictions, average="macro"
)

print("\n=== RESULTS ===")
print(f"Accuracy: {accuracy * 100:.2f}%")
print(f"Balanced accuracy: {balanced_accuracy * 100:.2f}%")
print(f"Macro F1: {macro_f1:.4f}")

print("\n=== CLASSIFICATION REPORT ===")
print(
    classification_report(
        y_test,
        predictions,
        zero_division=0,
    )
)

# ==========================================
# CONFUSION MATRIX
# ==========================================

labels = sorted(df["label"].unique())

matrix = confusion_matrix(
    y_test,
    predictions,
    labels=labels,
)

matrix_df = pd.DataFrame(
    matrix,
    index=[f"actual_{x}" for x in labels],
    columns=[f"pred_{x}" for x in labels],
)

print("\n=== CONFUSION MATRIX ===")
print(matrix_df.to_string())

# ==========================================
# FEATURE IMPORTANCE
# ==========================================

importance = pd.DataFrame({
    "feature": features,
    "importance": model.feature_importances_,
})

importance = importance.sort_values(
    "importance", ascending=False
)

print("\n=== FEATURE IMPORTANCE ===")
print(importance.to_string(index=False))

# ==========================================
# SAVE MODEL
# ==========================================

MODEL_PATH.parent.mkdir(
    parents=True,
    exist_ok=True,
)

joblib.dump(
    {
        "model": model,
        "features": features,
        "labels": labels,
        "test_captures": test_captures,
    },
    MODEL_PATH,
)

print("\nModel saved:", MODEL_PATH)
print("\n=== V2 TRAINING COMPLETE ===")
