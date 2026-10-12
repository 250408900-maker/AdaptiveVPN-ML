import joblib
import pandas as pd

data = pd.read_csv(
    "data/processed/v4/normal_v4_003_features.csv"
)

print("Hotspot windows:", len(data))
print("ICMP status:")
print(data["icmp_status"].value_counts(dropna=False))
print()

for filename in [
    "models/v3_random_forest.joblib",
    "models/v3_tcp_only.joblib",
]:
    bundle = joblib.load(filename)
    features = bundle["features"]
    X = data[features].apply(
        pd.to_numeric, errors="coerce"
    )

    valid = X.notna().all(axis=1)
    print("MODEL:", filename)
    print("Complete feature rows:", int(valid.sum()))

    if not valid.any():
        print("No complete rows; prediction skipped.")
    else:
        predictions = bundle["model"].predict(X.loc[valid])
        print("Predictions:", list(predictions))
        print("NORMAL:", sum(predictions == "NORMAL"))

    print()
