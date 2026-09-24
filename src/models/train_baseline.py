from pathlib import Path

import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split


# =========================================================
# Paths
# =========================================================

DATASET = Path("data/processed/dataset.csv")
MODEL_DIR = Path("models")
MODEL_PATH = MODEL_DIR / "baseline_random_forest.joblib"


# =========================================================
# Load dataset
# =========================================================

print("=== ADAPTIVE VPN ML - BASELINE TRAINING ===\n")

if not DATASET.exists():
    raise FileNotFoundError(
        f"Dataset not found: {DATASET}"
    )

df = pd.read_csv(DATASET)

print(f"Dataset rows: {len(df)}")
print(f"Dataset columns: {len(df.columns)}")

print("\nClass distribution:")
print(df["label"].value_counts().sort_index())


# =========================================================
# Prepare features
# =========================================================

# Window positions tell us where a sample occurred in a
# capture, not the network condition itself.
drop_columns = [
    "label",
    "window_start_s",
    "window_end_s",
]

X = df.drop(columns=drop_columns)
y = df["label"]

# Force feature columns to numeric values.
X = X.apply(pd.to_numeric, errors="coerce")

# Replace any missing values with zero.
X = X.fillna(0)

print("\nFeatures used:")

for feature in X.columns:
    print(f"  - {feature}")


# =========================================================
# Train/test split
# =========================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.25,
    random_state=42,
    stratify=y,
)

print("\n=== SPLIT ===")
print(f"Training samples: {len(X_train)}")
print(f"Testing samples:  {len(X_test)}")

print("\nTraining distribution:")
print(y_train.value_counts().sort_index())

print("\nTesting distribution:")
print(y_test.value_counts().sort_index())


# =========================================================
# Random Forest baseline
# =========================================================

print("\n=== TRAINING RANDOM FOREST ===")

model = RandomForestClassifier(
    n_estimators=300,
    random_state=42,
    class_weight="balanced",
    n_jobs=-1,
)

model.fit(X_train, y_train)

print("Training complete.")


# =========================================================
# Predictions
# =========================================================

predictions = model.predict(X_test)


# =========================================================
# Accuracy
# =========================================================

accuracy = accuracy_score(
    y_test,
    predictions,
)

print("\n=== RESULTS ===")

print(
    f"Accuracy: {accuracy:.4f}"
)

print(
    f"Accuracy: {accuracy * 100:.2f}%"
)


# =========================================================
# Classification report
# =========================================================

print("\n=== CLASSIFICATION REPORT ===")

print(
    classification_report(
        y_test,
        predictions,
        zero_division=0,
    )
)


# =========================================================
# Confusion matrix
# =========================================================

labels = sorted(
    y.unique()
)

cm = confusion_matrix(
    y_test,
    predictions,
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

print("\n=== CONFUSION MATRIX ===")

print(cm_df)


# =========================================================
# Feature importance
# =========================================================

importance = pd.DataFrame(
    {
        "feature": X.columns,
        "importance": model.feature_importances_,
    }
)

importance = importance.sort_values(
    "importance",
    ascending=False,
)

print("\n=== FEATURE IMPORTANCE ===")

print(
    importance.to_string(
        index=False
    )
)


# =========================================================
# Save model
# =========================================================

MODEL_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

artifact = {
    "model": model,
    "features": list(X.columns),
    "labels": labels,
}

joblib.dump(
    artifact,
    MODEL_PATH,
)

print(
    f"\nModel saved -> {MODEL_PATH}"
)


# =========================================================
# Finished
# =========================================================

print("\n========================================")
print("BASELINE TRAINING COMPLETE")
print("========================================")