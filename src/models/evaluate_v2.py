
from pathlib import Path

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import LeaveOneGroupOut
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    f1_score,
    classification_report,
    confusion_matrix,
)

ROOT = Path(__file__).resolve().parents[2]
DATASET = ROOT / "data/processed/dataset_v2_clean.csv"

df = pd.read_csv(DATASET)

excluded = [
    "label",
    "capture_file",
    "window_start_s",
    "window_end_s",
]

features = [
    col for col in df.columns
    if col not in excluded
]

X = df[features].apply(pd.to_numeric, errors="raise")
y = df["label"]
groups = df["capture_file"]

if X.isna().any().any():
    raise ValueError("Missing feature values")

logo = LeaveOneGroupOut()

predictions = pd.Series(index=df.index, dtype="str")
results = []

print("=== LEAVE-ONE-CAPTURE-OUT EVALUATION ===")

for fold, (train_idx, test_idx) in enumerate(
    logo.split(X, y, groups), start=1
):
    model = RandomForestClassifier(
        n_estimators=300,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1,
    )

    model.fit(X.iloc[train_idx], y.iloc[train_idx])

    predicted = model.predict(X.iloc[test_idx])
    predictions.iloc[test_idx] = predicted

    actual = y.iloc[test_idx]
    capture = Path(groups.iloc[test_idx[0]]).name

    score = accuracy_score(actual, predicted)

    results.append({
        "capture": capture,
        "actual_label": actual.iloc[0],
        "accuracy": round(score * 100, 2),
        "correct": int((actual.to_numpy() == predicted).sum()),
        "total": len(test_idx),
    })

print("\n=== RESULTS BY CAPTURE ===")
print(pd.DataFrame(results).to_string(index=False))

print("\n=== OVERALL RESULTS ===")
print(
    f"Accuracy: {accuracy_score(y, predictions) * 100:.2f}%"
)
print(
    f"Balanced accuracy: "
    f"{balanced_accuracy_score(y, predictions) * 100:.2f}%"
)
print(
    f"Macro F1: {f1_score(y, predictions, average='macro'):.4f}"
)

print("\n=== CLASSIFICATION REPORT ===")
print(
    classification_report(
        y, predictions, zero_division=0
    )
)

labels = sorted(y.unique())

matrix = confusion_matrix(
    y, predictions, labels=labels
)

print("\n=== CONFUSION MATRIX ===")
print(
    pd.DataFrame(
        matrix,
        index=[f"actual_{x}" for x in labels],
        columns=[f"pred_{x}" for x in labels],
    ).to_string()
)

print("\n=== EVALUATION COMPLETE ===")
