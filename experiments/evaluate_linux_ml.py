import joblib
import pandas as pd

bundle = joblib.load("models/v3_random_forest.joblib")
df = pd.read_csv("data/processed/linux_ml_features.csv")

features = bundle["features"]
model = bundle["model"]

print("Expected features:", features)
print("Available columns:", df.columns.tolist())

missing = [f for f in features if f not in df.columns]
if missing:
    raise SystemExit(f"Missing features: {missing}")

X = df[features]
predictions = model.predict(X)

print("\n=== CONTROLLED LINUX ML EVALUATION ===")

for expected, predicted in zip(df["scenario"], predictions):
    result = "MATCH" if expected == predicted else "MISMATCH"
    print(f"{expected:15} -> {predicted:15} [{result}]")

print(f"\nMatches: {sum(df['scenario'] == predictions)}/{len(df)}")
