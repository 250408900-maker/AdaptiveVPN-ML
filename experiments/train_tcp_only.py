from pathlib import Path
import joblib
import numpy as np
import pandas as pd

from sklearn.model_selection import StratifiedGroupKFold
from sklearn.metrics import (
    accuracy_score, balanced_accuracy_score, f1_score,
    classification_report, confusion_matrix
)
from src.models.train_v3 import make_model

FEATURES = [
    "tcp_connect_mean_ms",
    "tcp_connect_std_ms",
    "tcp_failure_pct",
]
CLASSES = ["NORMAL", "HIGH_LATENCY", "PACKET_LOSS"]

paths = sorted(Path("data/processed/v3").glob("*_features.csv"))
frames = []

for path in paths:
    df = pd.read_csv(path)
    if df.empty:
        continue
    df["capture_id"] = path.stem.replace("_features", "")
    frames.append(df)

data = pd.concat(frames, ignore_index=True)
data = data[data["label"].isin(CLASSES)].copy()

X = data[FEATURES].apply(pd.to_numeric, errors="coerce")
y = data["label"]
groups = data["capture_id"]

print("V3 windows:", len(data))
print("Independent captures:", groups.nunique())
print("Captures by class:")
print(data.groupby("label")["capture_id"].nunique())

splitter = StratifiedGroupKFold(
    n_splits=3, shuffle=True, random_state=42
)

predictions = np.empty(len(data), dtype=object)

for fold, (train_idx, test_idx) in enumerate(
    splitter.split(X, y, groups), start=1
):
    assert set(groups.iloc[train_idx]).isdisjoint(
        set(groups.iloc[test_idx])
    )
    model = make_model()
    model.fit(X.iloc[train_idx], y.iloc[train_idx])
    predictions[test_idx] = model.predict(X.iloc[test_idx])
    print(f"Fold {fold}: {len(test_idx)} held-out windows")

print()
print("Accuracy:", round(accuracy_score(y, predictions), 4))
print("Balanced accuracy:", round(balanced_accuracy_score(y, predictions), 4))
print("Macro F1:", round(f1_score(y, predictions, average="macro"), 4))
print()
print(classification_report(y, predictions, labels=CLASSES))
print("Confusion matrix:")
print(confusion_matrix(y, predictions, labels=CLASSES))

final_model = make_model()
final_model.fit(X, y)

Path("models").mkdir(exist_ok=True)
joblib.dump(
    {"model": final_model, "features": FEATURES, "classes": CLASSES},
    "models/v3_tcp_only.joblib"
)
print("Saved: models/v3_tcp_only.joblib")

v4_path = Path("data/processed/v4/normal_v4_002_features.csv")
v4 = pd.read_csv(v4_path)
v4_X = v4[FEATURES].apply(pd.to_numeric, errors="coerce")
valid = v4_X.notna().all(axis=1)

print()
print("V4 windows:", len(v4))
print("V4 evaluable:", int(valid.sum()))

if valid.any():
    predicted = final_model.predict(v4_X.loc[valid])
    print("V4 predictions:", list(predicted))
    print("V4 NORMAL predictions:", int(sum(predicted == "NORMAL")))
