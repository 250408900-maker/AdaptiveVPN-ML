import csv
from pathlib import Path

import joblib
import pandas as pd

MODEL = Path("models/v3_random_forest.joblib")
DATA = Path("data/processed/v4/normal_v4_002_features.csv")

bundle = joblib.load(MODEL)
model = bundle["model"]
features = bundle["features"]

with DATA.open(newline="", encoding="utf-8-sig") as f:
    rows = list(csv.DictReader(f))

print("V3 MODEL FEATURES:", features)
print("V4 WINDOWS:", len(rows))
print()

frame = pd.DataFrame(rows)

for feature in features:
    if feature not in frame.columns:
        frame[feature] = float("nan")
    frame[feature] = pd.to_numeric(frame[feature], errors="coerce")

print("MISSING VALUES PER FEATURE:")
print(frame[features].isna().sum().to_string())
print()

complete = frame[features].dropna()
print("EVALUABLE WINDOWS:", len(complete))
print("EXCLUDED WINDOWS:", len(frame) - len(complete))

if complete.empty:
    print()
    print("EVALUATION BLOCKED: No complete feature rows.")
    print("No values were invented or imputed.")
else:
    predictions = model.predict(complete)
    print()
    print("PREDICTIONS:")
    for index, prediction in zip(complete.index, predictions):
        print(f"Window {index}: {prediction}")
