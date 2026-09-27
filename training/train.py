import sys
from pathlib import Path

import joblib
import pandas as pd
import sklearn

from sklearn.ensemble import RandomForestClassifier


# =========================================================
# PROJECT ROOT
# =========================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# =========================================================
# SHARED FEATURE CONTRACT
# =========================================================

from core.features import (
    FEATURE_COLUMNS,
    TARGET_COLUMN,
)


# =========================================================
# PATHS
# =========================================================

TRAIN_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "train.csv"
)

MODEL_DIR = PROJECT_ROOT / "models"

MODEL_FILE = MODEL_DIR / "rf_v1.joblib"


# =========================================================
# LOAD TRAINING DATA
# =========================================================

print("========================================")
print("ADAPTIVEVPN-ML MODEL TRAINING")
print("========================================")

print(f"\nLoading -> {TRAIN_FILE}")

train = pd.read_csv(TRAIN_FILE)

print(f"Training windows: {len(train)}")

print(
    f"Independent captures: "
    f"{train['capture_id'].nunique()}"
)


# =========================================================
# VALIDATE FEATURE CONTRACT
# =========================================================

missing_features = [
    feature
    for feature in FEATURE_COLUMNS
    if feature not in train.columns
]

if missing_features:
    raise ValueError(
        f"Training dataset missing features: "
        f"{missing_features}"
    )

if TARGET_COLUMN not in train.columns:
    raise ValueError(
        f"Training dataset missing target: "
        f"{TARGET_COLUMN}"
    )


# =========================================================
# CREATE X AND y
# =========================================================

# ONLY the official 12 ML features go into the model.
#
# capture_id is NOT a feature.
# window_start_s/window_end_s are NOT features.
# label is the prediction target.

X_train = train[FEATURE_COLUMNS].copy()

y_train = train[TARGET_COLUMN].copy()


print("\n=== FEATURE CONTRACT ===")

print(f"Features: {len(FEATURE_COLUMNS)}")

for index, feature in enumerate(
    FEATURE_COLUMNS,
    start=1,
):
    print(f"{index:02d}. {feature}")


print("\n=== TRAINING CLASS DISTRIBUTION ===")

print(
    y_train
    .value_counts()
    .sort_index()
)


# =========================================================
# SAFETY CHECKS
# =========================================================

if X_train.isna().any().any():
    raise ValueError(
        "Training features contain missing values."
    )


non_numeric = [
    column
    for column in FEATURE_COLUMNS
    if not pd.api.types.is_numeric_dtype(
        X_train[column]
    )
]

if non_numeric:
    raise ValueError(
        f"Non-numeric features detected: "
        f"{non_numeric}"
    )


# =========================================================
# RANDOM FOREST V1
# =========================================================

print("\n========================================")
print("TRAINING RANDOM FOREST V1")
print("========================================")

model = RandomForestClassifier(
    n_estimators=300,
    random_state=42,
    class_weight="balanced",
    n_jobs=-1,
)

model.fit(
    X_train,
    y_train,
)


print("\nTraining complete.")


# =========================================================
# FEATURE IMPORTANCE
# =========================================================

importance = pd.Series(
    model.feature_importances_,
    index=FEATURE_COLUMNS,
).sort_values(
    ascending=False
)


print("\n=== FEATURE IMPORTANCE ===")

for feature, score in importance.items():
    print(
        f"{feature:<28} "
        f"{score:.4f}"
    )


# =========================================================
# SAVE MODEL ARTIFACT
# =========================================================

MODEL_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


artifact = {
    "model": model,

    # Critical:
    # inference must use these exact columns
    # in this exact order.
    "features": list(FEATURE_COLUMNS),

    "labels": list(model.classes_),

    "model_name": "RandomForestClassifier",

    "model_version": "rf_v1",

    "sklearn_version": sklearn.__version__,

    "training_windows": len(train),

    "training_captures": (
        train["capture_id"].nunique()
    ),
}


joblib.dump(
    artifact,
    MODEL_FILE,
)


# =========================================================
# VERIFY SAVED MODEL
# =========================================================

if not MODEL_FILE.exists():
    raise RuntimeError(
        "Model file was not created."
    )

loaded = joblib.load(MODEL_FILE)

if loaded["features"] != list(FEATURE_COLUMNS):
    raise RuntimeError(
        "Saved model feature contract mismatch."
    )


# =========================================================
# FINISHED
# =========================================================

print("\n========================================")
print("MODEL SAVED")
print("========================================")

print(f"\nPath: {MODEL_FILE}")

print(
    f"Model: "
    f"{artifact['model_name']}"
)

print(
    f"Version: "
    f"{artifact['model_version']}"
)

print(
    f"Training windows: "
    f"{artifact['training_windows']}"
)

print(
    f"Training captures: "
    f"{artifact['training_captures']}"
)

print(
    f"Classes: "
    f"{artifact['labels']}"
)

print(
    f"scikit-learn: "
    f"{artifact['sklearn_version']}"
)

print("\nMODEL TRAINING COMPLETE")