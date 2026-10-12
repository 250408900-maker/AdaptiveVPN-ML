import glob
import joblib
import pandas as pd

bundle = joblib.load("models/v3_random_forest.joblib")
files = sorted(glob.glob("data/processed/linux_repeats/run_*.csv"))

if len(files) != 5:
    raise SystemExit(f"Expected 5 completed runs, found {len(files)}")

df = pd.concat(
    [pd.read_csv(f).assign(run=i + 1) for i, f in enumerate(files)],
    ignore_index=True
)

model = bundle["model"]
df["prediction"] = model.predict(df[bundle["features"]])
df["match"] = df["scenario"] == df["prediction"]

print("\n=== REPEATED CONTROLLED EVALUATION ===")
print(df[["run", "scenario", "prediction", "match"]].to_string(index=False))

print("\n=== RESULTS BY SCENARIO ===")
print(df.groupby("scenario")["match"].agg(["sum", "count", "mean"]))

df.to_csv("data/processed/linux_repeated_evaluation.csv", index=False)
print("\nSaved repeated evaluation.")
